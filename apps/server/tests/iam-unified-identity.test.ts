import { createHash, generateKeyPairSync, randomUUID, sign as signData } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createRemoteServer } from '../src/server.js'
import { parseIamConfig, type IamConfig } from '../src/iam.js'
import type { OidcConfig } from '../src/iam-oidc.js'

/**
 * 真实 HTTP 集成测试：假 AI-Server、真 RS256 假 IdP、真中继进程内服务。
 * 结论不靠 mock：三条登录入口都必须落到同一个 (issuer, subject) 账号。
 */

const b64url = (value: Buffer | string): string =>
  Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }) as Record<string, unknown>, kid: 'unified-kid', use: 'sig', alg: 'RS256' }
const verifier = 'a'.repeat(43)
const challenge = b64url(createHash('sha256').update(verifier).digest())

class FakeIdp {
  private server?: Server
  base = ''
  subject = 'usr_test_0001'
  issuerOverride?: string
  tamper = false

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
  private send(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  private mint(): string {
    const now = Math.floor(Date.now() / 1000)
    const header = b64url(JSON.stringify({ alg: 'RS256', kid: 'unified-kid', typ: 'JWT' }))
    const payload = b64url(JSON.stringify({
      iss: this.issuerOverride ?? this.base,
      aud: 'client-1',
      sub: this.subject,
      exp: now + 300,
      iat: now,
      preferred_username: 'zhangsan',
      email: 'zhangsan@example.com',
    }))
    const signature = signData('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey)
    // 篡改 payload、保留旧签名：必须被验签拦下。
    const tail = this.tamper ? b64url(JSON.stringify({ iss: this.base, aud: 'client-1', sub: 'usr_attacker', exp: now + 300 })) : payload
    return `${header}.${tail}.${b64url(signature)}`
  }
  private async handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/.well-known/openid-configuration') {
      return this.send(res, 200, {
        issuer: this.base,
        token_endpoint: `${this.base}/api/oidc/token`,
        jwks_uri: `${this.base}/api/oauth/jwks`,
        code_challenge_methods_supported: ['S256'],
      })
    }
    if (url.pathname === '/api/oauth/jwks') return this.send(res, 200, { keys: [jwk] })
    if (url.pathname === '/api/oidc/token' && req.method === 'POST') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        const form = new URLSearchParams(raw)
        if (form.get('grant_type') !== 'authorization_code' || form.get('code') !== 'good-code'
          || b64url(createHash('sha256').update(form.get('code_verifier') ?? '').digest()) !== challenge) {
          return this.send(res, 400, { error: 'invalid_grant' })
        }
        this.send(res, 200, { access_token: 'at', id_token: this.mint() })
      })
      return
    }
    res.writeHead(404).end()
  }
}

interface FakeUser {
  id: number
  email: string
  username: string
  password: string
  subject: string
  issuer: string
  bound?: boolean
  provider?: string
  /** true 表示 profile 完全没有 identities 字段。 */
  omitIdentities?: boolean
}

class FakeAiServer {
  users: FakeUser[] = []
  tokens = new Map<string, FakeUser>()
  profileCalls = 0
  redirectTo?: string
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
  issue(user: FakeUser): string {
    const token = `iam-token-${randomUUID()}`
    this.tokens.set(token, user)
    return token
  }
  add(user: Partial<FakeUser> & { subject?: string; issuer: string }): FakeUser {
    const full: FakeUser = {
      id: this.users.length + 1,
      email: `user${this.users.length + 1}@example.test`,
      username: `user${this.users.length + 1}`,
      password: '{{SECRET_unified1}}',
      subject: 'usr_test_0001',
      ...user,
    }
    this.users.push(full)
    return full
  }
  private send(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  private async handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.method === 'POST' && url.pathname === '/api/v1/auth/login') {
      const raw = await new Promise<string>(resolve => {
        let text = ''
        req.on('data', chunk => { text += chunk })
        req.on('end', () => resolve(text))
      })
      const body = JSON.parse(raw) as { email?: string; password?: string }
      const user = this.users.find(candidate => candidate.email === body.email && candidate.password === body.password)
      if (!user) return this.send(res, 401, { code: 401, message: 'invalid credentials' })
      // 登录响应故意不带 identities/subject，逼中继必须再调 profile。
      return this.send(res, 200, {
        code: 0,
        message: 'ok',
        data: { access_token: this.issue(user), expires_in: 86_400, user: { id: user.id, email: user.email, username: user.username } },
      })
    }
    if (req.method === 'GET' && url.pathname === '/api/v1/user/profile') {
      this.profileCalls++
      const auth = req.headers.authorization
      const token = auth?.startsWith('Bearer ') ? auth.slice(7) : ''
      const user = this.tokens.get(token)
      if (!user) return this.send(res, 401, { code: 401, message: 'Invalid token' })
      if (this.redirectTo !== undefined) {
        res.writeHead(302, { location: this.redirectTo, 'content-type': 'text/plain' })
        return res.end('redirect')
      }
      return this.send(res, 200, {
        code: 0,
        message: 'ok',
        data: {
          id: user.id,
          email: user.email,
          username: user.username,
          ...(user.omitIdentities === true ? {} : {
            identities: {
              oidc: {
                provider: user.provider ?? 'oidc',
                bound: user.bound ?? true,
                subject: user.subject,
                issuer: user.issuer,
              },
            },
          }),
        },
      })
    }
    res.writeHead(404).end()
  }
}

let dir: string
let idp: FakeIdp
let ai: FakeAiServer
let app: ReturnType<typeof createRemoteServer> | undefined
const extras: Server[] = []

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-unified-'))
  idp = new FakeIdp()
  ai = new FakeAiServer()
  await Promise.all([idp.start(), ai.start()])
})
afterEach(async () => {
  await app?.close().catch(() => undefined)
  app = undefined
  await Promise.all(extras.splice(0).map(server => new Promise<void>(resolve => {
    server.closeAllConnections(); server.close(() => resolve())
  })))
  await Promise.all([idp.stop(), ai.stop()])
  rmSync(dir, { recursive: true, force: true })
})

function iamConfig(): IamConfig {
  const parsed = parseIamConfig(ai.base, '5000', idp.base)
  if (!parsed) throw new Error('iam config missing')
  return parsed
}
function oidcConfig(): OidcConfig {
  return { issuer: idp.base, clientId: 'client-1', clientSecret: '{{SECRET_unified2}}', timeoutMs: 5000 }
}

async function serve(options: { iam?: boolean; oidc?: boolean; accounts?: { account: string; password: string }[] } = {}) {
  app = createRemoteServer({
    accounts: options.accounts ?? [],
    dataFile: join(dir, 'state.json'),
    publicUrl: 'http://localhost:8080',
    ...(options.iam === false ? {} : { iam: iamConfig() }),
    ...(options.oidc === false ? {} : { oidc: oidcConfig() }),
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  return `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}

async function call(base: string, path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token === undefined ? {} : { Authorization: `Bearer ${token}` }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  })
  return { status: response.status, data: await response.json() as any }
}

async function register(base: string, session: string, role: 'host' | 'client', name: string) {
  const descriptor = { deviceId: randomUUID(), identityKey: 'A'.repeat(43), name, role, platform: 'linux', clientVersion: '0.6.3' }
  const result = await call(base, '/devices/register', 'POST', { v: 1, device: descriptor }, session)
  expect(result.status, JSON.stringify(result.data)).toBe(200)
  return { descriptor, accessToken: result.data.accessToken as string }
}

async function oidcLogin(base: string): Promise<string> {
  const result = await call(base, '/auth/iam/oidc', 'POST', {
    code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback',
  })
  expect(result.status, JSON.stringify(result.data)).toBe(200)
  return result.data.token as string
}

describe('统一身份：AI-Server profile 与 OIDC id_token', () => {
  it('桌面 token、口令登录、手机 OIDC 三条入口落到同一账号并可互相发现设备', async () => {
    const alice = ai.add({ email: 'alice@example.test', username: '爱丽丝', password: '{{SECRET_alice1}}', issuer: idp.base })
    const base = await serve()

    // 桌面：已有 IAM access_token 换中继会话，注册 host。
    const desktop = await call(base, '/auth/iam', 'POST', { token: ai.issue(alice) })
    expect(desktop.status, JSON.stringify(desktop.data)).toBe(200)
    expect(desktop.data.profile.displayName).toBe('爱丽丝')
    const host = await register(base, desktop.data.token, 'host', 'desktop-host')

    // 口令登录：login 只给 token，中继必须再用 profile 得到同一身份。
    const password = await call(base, '/auth/login', 'POST', { email: alice.email, password: alice.password })
    expect(password.status, JSON.stringify(password.data)).toBe(200)
    expect(password.data.profile.displayName).toBe('爱丽丝')
    const accountDevices = await call(base, '/account/devices', 'GET', undefined, password.data.token)
    expect(accountDevices.data.items.map((item: any) => item.deviceId)).toContain(host.descriptor.deviceId)

    // 手机：OIDC 验签后的 issuer + subject 必须指向同一个账号。
    const oidcToken = await oidcLogin(base)
    const client = await register(base, oidcToken, 'client', 'phone-client')
    const list = await call(base, '/devices', 'GET', undefined, client.accessToken)
    expect(list.status).toBe(200)
    expect(list.data.items.map((item: any) => item.deviceId)).toContain(host.descriptor.deviceId)
    expect(ai.profileCalls).toBeGreaterThanOrEqual(2)
  })

  it('不同 subject 互相隔离；同 subject 不同 issuer 被直接拒绝', async () => {
    const alice = ai.add({ email: 'alice@example.test', username: '爱丽丝', password: '{{SECRET_alice1}}', issuer: idp.base })
    // IdP 签发的 sub 与 Alice 的 profile subject 不同，必须落在独立账号。
    idp.subject = 'usr_oidc_other'
    const base = await serve()

    const aliceSession = await call(base, '/auth/iam', 'POST', { token: ai.issue(alice) })
    const aliceHost = await register(base, aliceSession.data.token, 'host', 'alice-host')

    const bobOidc = await oidcLogin(base)
    const bobClient = await register(base, bobOidc, 'client', 'bob-phone')
    const bobList = await call(base, '/devices', 'GET', undefined, bobClient.accessToken)
    expect(bobList.data.items).toEqual([])

    // profile 自称别的 issuer：绝不并入可信 issuer 的账号，但也不阻断登录——
    // 退回旧数字键，两者仍是两个独立 accountId，不会撞号。
    const impostor = ai.add({ subject: 'usr_test_0001', issuer: `${idp.base}/evil` })
    const impostorSession = await call(base, '/auth/iam', 'POST', { token: ai.issue(impostor) })
    expect(impostorSession.status, JSON.stringify(impostorSession.data)).toBe(200)
    const state = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'))
    const accounts = Object.values(state.accounts) as Array<{ account: string }>
    expect(accounts.map(entry => entry.account)).toContain(`iam:${impostor.id}`)
    const aliceClient = await register(base, aliceSession.data.token, 'client', 'alice-phone')
    expect((await call(base, '/devices', 'GET', undefined, aliceClient.accessToken)).data.items
      .map((item: any) => item.deviceId)).toContain(aliceHost.descriptor.deviceId)
    // impostor 没有拿到统一键，因此看不到 alice 的 host。
    const impostorClient = await register(base, impostorSession.data.token, 'client', 'impostor-phone')
    expect((await call(base, '/devices', 'GET', undefined, impostorClient.accessToken)).data.items).toEqual([])
  })

  it('issuer 仅尾斜杠不同视为同一发行方，同一 subject 仍落到同一账号', async () => {
    // AI-Server 逐字保存 IAM 下发的 issuer；OIDC 不允许尾斜杠，但历史数据可能带。
    // 归一后两者必须指向同一 (issuer, subject)，否则桌面会与手机永久分裂。
    const alice = ai.add({ email: 'alice@example.test', username: '爱丽丝', issuer: `${idp.base}/` })
    const base = await serve()

    const desktop = await call(base, '/auth/iam', 'POST', { token: ai.issue(alice) })
    expect(desktop.status, JSON.stringify(desktop.data)).toBe(200)
    const host = await register(base, desktop.data.token, 'host', 'slash-host')

    const oidcToken = await oidcLogin(base)
    const client = await register(base, oidcToken, 'client', 'slash-phone')
    const list = await call(base, '/devices', 'GET', undefined, client.accessToken)
    expect(list.data.items.map((item: any) => item.deviceId)).toContain(host.descriptor.deviceId)
  })

  it('身份形状不合格时回退旧键仍可登录；伪造 token 恒被拒绝', async () => {
    const base = await serve()
    const cases: Array<Partial<FakeUser> & { issuer: string }> = [
      { subject: '', issuer: idp.base },
      { subject: 'usr_***', issuer: idp.base },
      { subject: 'usr_test_0001', issuer: idp.base, bound: false },
      { subject: 'usr_test_0001', issuer: idp.base, provider: 'saml' },
      { subject: 'usr_test_0001', issuer: idp.base, omitIdentities: true },
      { subject: 'usr_test_0001', issuer: 'https://other-issuer.example' },
    ]
    for (const user of cases) {
      const candidate = ai.add(user)
      const result = await call(base, '/auth/iam', 'POST', { token: ai.issue(candidate) })
      // AI-Server 认可这个 token，但绑定不可信：登录保留，账号键退回数字 id。
      expect(result.status, JSON.stringify(user)).toBe(200)
    }
    const state = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'))
    const accounts = (Object.values(state.accounts) as Array<{ account: string }>).map(entry => entry.account)
    for (const user of cases) expect(accounts).toContain(`iam:${ai.users.find(item => item.subject === user.subject && item.issuer === user.issuer)?.id ?? -1}`)
    // 回退账号一律不获得统一键，因此不会与手机端合并。
    expect(accounts.filter(account => /^iam:[0-9a-f]{64}$/.test(account))).toHaveLength(0)

    // 令牌本身不被 AI-Server 认可时，必须在 HTTP 层失败，绝不降级成任何账号。
    const forged = await call(base, '/auth/iam', 'POST', { token: 'forged-but-long-enough-token' })
    expect(forged.status).toBe(401)
    expect(forged.data.error.code).toBe('AUTH_INVALID')
  })

  it('profile 返回重定向时不跟随，bearer 不会被送到别处', async () => {
    let hits = 0
    const attacker = createServer((_req, res) => { hits++; res.writeHead(200).end('{}') })
    extras.push(attacker)
    attacker.listen(0, '127.0.0.1')
    await once(attacker, 'listening')
    const target = `http://127.0.0.1:${(attacker.address() as { port: number }).port}/steal`

    const user = ai.add({ issuer: idp.base })
    ai.redirectTo = target
    const base = await serve()
    const result = await call(base, '/auth/iam', 'POST', { token: ai.issue(user) })
    expect(result.status).toBe(503)
    expect(result.data.error.code).toBe('IAM_UNAVAILABLE')
    expect(hits).toBe(0)
  })

  it('OIDC 签名被篡改时拒绝', async () => {
    idp.tamper = true
    const base = await serve()
    const result = await call(base, '/auth/iam/oidc', 'POST', {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback',
    })
    expect(result.status).toBe(401)
    expect(result.data.error.code).toBe('AUTH_INVALID')
  })

  it('OIDC-only 部署重启后账号不会被本地账号配置扫描停用', async () => {
    const first = await serve({ iam: false })
    const token = await oidcLogin(first)
    const client = await register(first, token, 'client', 'persisted-client')
    await app!.close()
    app = undefined

    // 不带 IAM、不带本地账号，仅 OIDC 重启：同一 state.json 中的账号必须仍然可用。
    const second = await serve({ iam: false })
    const again = await oidcLogin(second)
    const devices = await call(second, '/account/devices', 'GET', undefined, again)
    expect(devices.status).toBe(200)
    expect(devices.data.items.map((item: any) => item.deviceId)).toContain(client.descriptor.deviceId)
  })
})
