import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { createRemoteServer } from '../src/server.js'
import { Store } from '../src/store.js'
import { parseIamConfig } from '../src/iam.js'

/**
 * A stand-in IAM deployment that mirrors the shapes observed on the live server:
 *   POST /api/v1/auth/login      { email, password } -> { code, message, data: { access_token, expires_in, user } }
 *   GET  /api/v1/user/profile    Authorization: Bearer -> { code, message, data: user }
 * It is deliberately strict so a wrong header or body fails loudly.
 */
class FakeIam {
  readonly users = [
    { id: 9, email: 'alice@example.test', username: '爱丽丝', password: '{{SECRET_yjulhtzo}}' },
    { id: 12, email: 'bob@example.test', username: '鲍勃', password: '{{SECRET_hf2x4b7t}}' },
  ]
  readonly tokens = new Map<string, number>()
  mode: 'ok' | 'boom' | 'not-found' = 'ok'
  loginCalls = 0
  profileCalls = 0
  private server?: Server
  base = ''

  async start(): Promise<void> {
    this.server = createServer((req, res) => { void this.handle(req, res) })
    this.server.listen(0, '127.0.0.1')
    await once(this.server, 'listening')
    this.base = `http://127.0.0.1:${(this.server.address() as { port: number }).port}`
  }
  async stop(): Promise<void> {
    this.server?.closeAllConnections()
    if (this.server) await new Promise<void>(resolve => this.server!.close(() => resolve()))
    this.server = undefined
  }
  issue(userId: number): string {
    const token = `iam-token-${randomUUID()}`
    this.tokens.set(token, userId)
    return token
  }
  private send(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  private async handle(req: IncomingMessage, res: ServerResponse) {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname
    if (this.mode === 'boom') return this.send(res, 500, { code: 500, message: 'boom' })
    if (this.mode === 'not-found') return this.send(res, 404, { code: 404, message: 'not found' })
    if (req.method === 'POST' && path === '/api/v1/auth/login') {
      this.loginCalls++
      const raw = await new Promise<string>(resolve => {
        let text = ''
        req.on('data', chunk => { text += chunk })
        req.on('end', () => resolve(text))
      })
      const body = JSON.parse(raw) as { email?: string; password?: string }
      const user = this.users.find(candidate => candidate.email === body.email && candidate.password === body.password)
      if (!user) return this.send(res, 401, { code: 401, message: 'invalid email or password', reason: 'INVALID_CREDENTIALS' })
      const { password: _password, ...rest } = user
      return this.send(res, 200, { code: 0, message: 'ok', data: { access_token: this.issue(user.id), token_type: 'Bearer', expires_in: 86_400, user: rest } })
    }
    if (req.method === 'GET' && path === '/api/v1/user/profile') {
      this.profileCalls++
      const token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : ''
      const userId = this.tokens.get(token)
      const user = this.users.find(candidate => candidate.id === userId)
      if (!user) return this.send(res, 401, { code: 401, message: 'Invalid token', reason: 'INVALID_TOKEN' })
      const { password: _password, ...rest } = user
      return this.send(res, 200, { code: 0, message: 'ok', data: rest })
    }
    this.send(res, 404, { code: 404, message: 'not found' })
  }
}

let dir: string, base: string, iam: FakeIam, app: ReturnType<typeof createRemoteServer> | undefined

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-iam-'))
  iam = new FakeIam()
  await iam.start()
})
afterEach(async () => {
  await app?.close().catch(() => undefined)
  app = undefined
  await iam.stop()
  rmSync(dir, { recursive: true, force: true })
})

async function start(extra: { accounts?: { account: string; password: string }[]; iamBase?: string; allowDeviceRebind?: boolean } = {}) {
  const baseUrl = extra.iamBase ?? iam.base
  app = createRemoteServer({
    ...(extra.accounts === undefined ? {} : { accounts: extra.accounts }),
    ...(extra.allowDeviceRebind === undefined ? {} : { allowDeviceRebind: extra.allowDeviceRebind }),
    iam: parseIamConfig(baseUrl, '5000'),
    dataFile: join(dir, 'state.json'),
    publicUrl: 'http://localhost:8080',
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
  return app
}

async function call(path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  })
  return { status: response.status, data: await response.json() as any }
}

async function signIn(account: { email: string; password: string }) {
  const result = await call('/auth/login', 'POST', { email: account.email, password: account.password })
  expect(result.status, JSON.stringify(result.data)).toBe(200)
  return result
}

async function register(session: string, role: 'host' | 'client', name: string) {
  const descriptor = { deviceId: randomUUID(), identityKey: 'A'.repeat(43), name, role, platform: 'linux', clientVersion: '0.6.3' }
  const result = await call('/devices/register', 'POST', { v: 1, device: descriptor }, session)
  expect(result.status).toBe(200)
  return { descriptor, accessToken: result.data.accessToken as string }
}

describe('IAM 身份适配', () => {
  it('用 IAM 邮箱口令登录后，设备归属于 IAM 用户而不是邮箱字符串', async () => {
    await start()
    const alice = iam.users[0]!
    const signed = await signIn(alice)
    expect(signed.data.account).toBe('爱丽丝')
    expect(signed.data.profile.displayName).toBe('爱丽丝')

    const host = await register(signed.data.token, 'host', 'alice-host')
    const state = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'))
    const device = state.devices[host.descriptor.deviceId]
    expect(device.accountId).toHaveLength(64)
    // owner 只由 IAM user id 决定，与邮箱大小写或显示名无关
    expect(state.accounts[device.accountId].account).toBe(`iam:${alice.id}`)
    expect(state.accounts[device.accountId].kind).toBe('iam')

    const client = await register(signed.data.token, 'client', 'alice-phone')
    const list = await call('/devices', 'GET', undefined, client.accessToken)
    expect(list.status).toBe(200)
    expect(list.data.items.map((item: any) => item.deviceId)).toEqual([host.descriptor.deviceId])
  })

  it('两个 IAM 用户互相看不到、也连不到对方的设备', async () => {
    await start()
    const [alice, bob] = [iam.users[0]!, iam.users[1]!]
    const aliceSession = (await signIn(alice)).data.token as string
    const host = await register(aliceSession, 'host', 'alice-host')
    const bobClient = await register((await signIn(bob)).data.token as string, 'client', 'bob-phone')

    const list = await call('/devices', 'GET', undefined, bobClient.accessToken)
    expect(list.data.items).toEqual([])
    const presence = await call(`/devices/${host.descriptor.deviceId}/presence`, 'GET', undefined, bobClient.accessToken)
    expect(presence.status).toBe(404)
    const detail = await call(`/devices/${host.descriptor.deviceId}`, 'GET', undefined, bobClient.accessToken)
    expect(detail.status).toBe(404)
  })

  it('口令错误与账号不存在都返回 401，且不回显 IAM 的错误体', async () => {
    await start()
    const alice = iam.users[0]!
    const wrong = await call('/auth/login', 'POST', { email: alice.email, password: '{{SECRET_wrongpwd1}}' })
    expect(wrong.status).toBe(401)
    expect(wrong.data.error.code).toBe('AUTH_INVALID')
    const unknown = await call('/auth/login', 'POST', { email: 'nobody@example.test', password: '{{SECRET_wrongpwd1}}' })
    expect(unknown.status).toBe(401)
    expect(JSON.stringify(unknown.data)).not.toContain('INVALID_CREDENTIALS')
  })

  it('IAM 不可用时返回 503，而不是把故障当成口令错误', async () => {
    await start()
    iam.mode = 'boom'
    const alice = iam.users[0]!
    const result = await call('/auth/login', 'POST', { email: alice.email, password: alice.password })
    expect(result.status).toBe(503)
    expect(result.data.error.code).toBe('IAM_UNAVAILABLE')
    expect(result.data.error.retryable).toBe(true)

    iam.mode = 'not-found'
    const missing = await call('/auth/login', 'POST', { email: alice.email, password: alice.password })
    expect(missing.status).toBe(503)
  })

  it('桌面端可以直接用已有 IAM token 换中继会话，且与口令登录是同一个 owner', async () => {
    await start()
    const alice = iam.users[0]!
    const host = await register((await signIn(alice)).data.token as string, 'host', 'desktop')

    const exchanged = await call('/auth/iam', 'POST', { token: iam.issue(alice.id) })
    expect(exchanged.status).toBe(200)
    expect(exchanged.data.profile.displayName).toBe('爱丽丝')

    const client = await register(exchanged.data.token, 'client', 'phone')
    const list = await call('/devices', 'GET', undefined, client.accessToken)
    expect(list.data.items.map((item: any) => item.deviceId)).toEqual([host.descriptor.deviceId])
  })

  it('伪造或过期的 IAM token 换不出会话', async () => {
    await start()
    const forged = await call('/auth/iam', 'POST', { token: 'iam-token-forged-value-1234567890' })
    expect(forged.status).toBe(401)
    expect(forged.data.error.code).toBe('AUTH_INVALID')
  })

  it('未配置 IAM 时该端点不存在，本地账号也不受影响', async () => {
    app = createRemoteServer({
      accounts: [{ account: 'local@example.test', password: '{{SECRET_localpwd1}}' }],
      dataFile: join(dir, 'local.json'),
      publicUrl: 'http://localhost:8080',
    })
    app.server.listen(0, '127.0.0.1')
    await once(app.server, 'listening')
    base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`

    const exchanged = await call('/auth/iam', 'POST', { token: iam.issue(9) })
    expect(exchanged.status).toBe(404)
    const local = await signIn({ email: 'local@example.test', password: '{{SECRET_localpwd1}}' })
    expect(local.data.account).toBe('local@example.test')
  })

  it('重启后 IAM 账号仍然有效，本地账号与 IAM 账号互不可见', async () => {
    await start({ accounts: [{ account: 'local@example.test', password: '{{SECRET_localpwd1}}' }] })
    const alice = iam.users[0]!
    const host = await register((await signIn(alice)).data.token as string, 'host', 'alice-host')
    const local = await signIn({ email: 'local@example.test', password: '{{SECRET_localpwd1}}' })
    const localClient = await register(local.data.token, 'client', 'local-phone')
    expect((await call('/devices', 'GET', undefined, localClient.accessToken)).data.items).toEqual([])

    await app!.close()
    await start({ accounts: [{ account: 'local@example.test', password: '{{SECRET_localpwd1}}' }] })
    const again = await signIn(alice)
    const client = await register(again.data.token, 'client', 'alice-phone-2')
    const list = await call('/devices', 'GET', undefined, client.accessToken)
    expect(list.data.items.map((item: any) => item.deviceId)).toEqual([host.descriptor.deviceId])
  })

  it('关闭 IAM 后，已存在的 IAM 账号与其设备不可再用', async () => {
    await start()
    const alice = iam.users[0]!
    const client = await register((await signIn(alice)).data.token as string, 'client', 'phone')

    // 同一份 state.json 以「无 IAM」配置重新打开：IAM 账号应被停用。
    const store = new Store(join(dir, 'state.json'), [{ account: 'local@example.test', password: '{{SECRET_localpwd1}}' }], {})
    expect(() => store.getAccount(`iam:${alice.id}`)).toThrow()
    expect(() => store.authenticate(client.accessToken)).toThrow()
  })
})

describe('设备换账号（DSH_ALLOW_DEVICE_REBIND）', () => {
  // 末位必须是合法的 base64url 32 字节尾字符，否则会被协议 schema 拒绝。
  const identityKey = `${'B'.repeat(42)}A`
  async function registerSame(session: string, deviceId: string, key = identityKey) {
    return call('/devices/register', 'POST', {
      v: 1,
      device: { deviceId, identityKey: key, name: 'same-device', role: 'host', platform: 'darwin', clientVersion: '0.6.3' },
    }, session)
  }

  it('默认关闭：换账号一律拒绝，且不暴露归属差异', async () => {
    await start()
    const [alice, bob] = [iam.users[0]!, iam.users[1]!]
    const deviceId = randomUUID()
    const aliceSession = (await signIn(alice)).data.token as string
    expect((await registerSame(aliceSession, deviceId)).status).toBe(200)
    const bobSession = (await signIn(bob)).data.token as string
    const taken = await registerSame(bobSession, deviceId)
    expect(taken.status).toBe(404)
    expect(taken.data.error.code).toBe('DEVICE_NOT_FOUND')
  })

  it('开启后：同一设备公钥可以换账号，旧账号随即看不到它', async () => {
    await start({ allowDeviceRebind: true })
    const [alice, bob] = [iam.users[0]!, iam.users[1]!]
    const deviceId = randomUUID()
    expect((await registerSame((await signIn(alice)).data.token as string, deviceId)).status).toBe(200)

    const bobSession = (await signIn(bob)).data.token as string
    expect((await registerSame(bobSession, deviceId)).status).toBe(200)
    const bobClient = await register(bobSession, 'client', 'bob-phone')
    expect((await call('/devices', 'GET', undefined, bobClient.accessToken)).data.items.map((item: any) => item.deviceId)).toEqual([deviceId])

    const aliceClient = await register((await signIn(alice)).data.token as string, 'client', 'alice-phone')
    expect((await call('/devices', 'GET', undefined, aliceClient.accessToken)).data.items).toEqual([])
  })

  it('开启后：公钥不同的同名 deviceId 仍被拒绝（不能夺取他人设备）', async () => {
    await start({ allowDeviceRebind: true })
    const [alice, bob] = [iam.users[0]!, iam.users[1]!]
    const deviceId = randomUUID()
    expect((await registerSame((await signIn(alice)).data.token as string, deviceId)).status).toBe(200)
    const stolen = await registerSame((await signIn(bob)).data.token as string, deviceId, `${'C'.repeat(42)}A`)
    expect(stolen.status).toBe(404)
  })
})

describe('IAM 配置解析', () => {
  it('接受带反向代理前缀的 HTTPS 地址，去掉尾斜杠', () => {
    expect(parseIamConfig('https://ai.example.test/aiserver/')).toEqual({ baseUrl: 'https://ai.example.test/aiserver', timeoutMs: 10_000 })
  })
  it('拒绝凭据、查询串、片段与非法协议', () => {
    for (const value of ['ftp://ai.example.test', 'https://user:pass@ai.example.test', 'https://ai.example.test/?x=1', 'https://ai.example.test/#x', 'not-a-url']) {
      expect(() => parseIamConfig(value)).toThrow()
    }
  })
  it('超时值必须在 1s 到 30s 之间', () => {
    expect(() => parseIamConfig('https://ai.example.test', '500')).toThrow()
    expect(() => parseIamConfig('https://ai.example.test', '60000')).toThrow()
    expect(parseIamConfig('https://ai.example.test', '3000')?.timeoutMs).toBe(3000)
  })
  it('未设置时返回 undefined，保持原有单机行为', () => {
    expect(parseIamConfig(undefined)).toBeUndefined()
    expect(parseIamConfig('  ')).toBeUndefined()
  })
})

describe('store 的 IAM 账号约束', () => {
  it('未开启 IAM 时不能凭空创建外部账号', () => {
    const store = new Store(join(dir, 'plain.json'), [{ account: 'a@example.test', password: '{{SECRET_apwd1234}}' }])
    expect(() => store.ensureIamAccount('iam:1')).toThrow()
  })
  it('只接受 iam:<数字> 形式的账号标识', () => {
    const store = new Store(join(dir, 'iam.json'), [], { iam: true })
    for (const bad of ['iam:', 'iam:abc', 'alice', 'iam:0', 'iam:-1']) expect(() => store.ensureIamAccount(bad)).toThrow()
    expect(store.ensureIamAccount('iam:7')).toHaveLength(64)
  })
  it('IAM 账号不能用口令登录', () => {
    const store = new Store(join(dir, 'iam2.json'), [], { iam: true })
    store.ensureIamAccount('iam:7')
    expect(() => store.verifyLogin('iam:7', 'anything')).toThrow()
  })
  it('重复登录只更新展示名，不重建账号（分页游标密钥保持稳定）', () => {
    const file = join(dir, 'iam3.json')
    const store = new Store(file, [], { iam: true })
    const id = store.ensureIamAccount('iam:7', '旧名')
    const before = JSON.parse(readFileSync(file, 'utf8')).accounts[id]
    store.ensureIamAccount('iam:7', '新名')
    const after = JSON.parse(readFileSync(file, 'utf8')).accounts[id]
    expect(after.displayName).toBe('新名')
    expect(after.salt).toBe(before.salt)
    expect(after.verifier).toBe(before.verifier)
  })
  it('可以完全不开本地账号，只靠 IAM', () => {
    const file = join(dir, 'iam4.json')
    const store = new Store(file, [], { iam: true })
    expect(store.account).toBe('')
    store.ensureIamAccount('iam:7', '仅 IAM')
    const reopened = new Store(file, [], { iam: true })
    expect(reopened.getAccount('iam:7')).toHaveLength(64)
    expect(reopened.displayNameOf(reopened.getAccount('iam:7'))).toBe('仅 IAM')
  })
})
