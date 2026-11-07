import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { WebSocket } from 'ws'
import { createControlFrame } from '@dsh-remote/protocol'
import { NoiseIkSession, createNoisePrologue, fromBase64Url, generateKeyPair, toBase64Url } from '../../../packages/crypto/src/index.js'
import { createRemoteServer } from '../src/server.js'
import { Store, hash, parseAccountsEnvironment } from '../src/store.js'

type Account = { account: string; password: string; disabled?: boolean }
const accounts: Account[] = [
  { account: 'alice@example.com', password: 'alice-password-12345' },
  { account: 'bob@example.com', password: 'bob-password-123456' },
]
const capabilities = ['transport.lan', 'transport.p2p', 'transport.relay']
type Device = Awaited<ReturnType<typeof register>>
let dir: string, base: string, app: ReturnType<typeof createRemoteServer>
let sessions: string[]
const sockets: WebSocket[] = []
const noiseSessions: NoiseIkSession[] = []

async function start(configured: Account[] = accounts) {
  app = createRemoteServer({ accounts: configured, dataFile: join(dir, 'state.json'), publicUrl: 'http://localhost:8080' })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}
async function request(path: string, method = 'GET', body?: unknown, token?: string) {
  const response = await fetch(`${base}/api/v1${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(5000),
  })
  return { status: response.status, data: await response.json() as any }
}
async function login(index: number) {
  const result = await request('/auth/login', 'POST', { email: accounts[index]!.account, password: accounts[index]!.password })
  expect(result.status).toBe(200)
  return result.data.token as string
}
async function register(index: number, role: 'host' | 'client', deviceId = randomUUID()) {
  const keys = generateKeyPair()
  const descriptor = { deviceId, identityKey: keys.publicKey, name: `${accounts[index]!.account}-${role}`, role, platform: 'linux', clientVersion: '0.6.3' }
  const response = await request('/devices/register', 'POST', { v: 1, device: descriptor }, sessions[index])
  expect(response.status).toBe(200)
  return { ...descriptor, keys, ...response.data } as typeof descriptor & { keys: typeof keys; accessToken: string; refreshToken: string; refreshTokenExpiresAt: number }
}
class Wire {
  readonly messages: any[] = []
  private readonly waiters = new Set<() => void>()
  constructor(readonly ws: WebSocket) {
    ws.on('message', raw => {
      this.messages.push(JSON.parse(raw.toString()))
      for (const waiter of [...this.waiters]) waiter()
    })
  }
  send(type: Parameters<typeof createControlFrame>[0], payload: unknown) {
    this.ws.send(JSON.stringify(createControlFrame(type, payload)))
  }
  next(type: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const take = () => {
        const index = this.messages.findIndex(message => message.type === type)
        if (index < 0) return
        cleanup()
        resolve(this.messages.splice(index, 1)[0].payload)
      }
      const timeout = setTimeout(() => { cleanup(); reject(new Error(`Timed out waiting for ${type}`)) }, 3000)
      const cleanup = () => { clearTimeout(timeout); this.waiters.delete(take) }
      this.waiters.add(take)
      take()
    })
  }
}
async function connect(device: Device) {
  const ws = new WebSocket(base.replace('http:', 'ws:') + '/ws/v1/connect')
  sockets.push(ws)
  const wire = new Wire(ws)
  await once(ws, 'open')
  wire.send('hello', { role: device.role, deviceId: device.deviceId, accessToken: device.accessToken, protocols: [1], capabilities, clientVersion: device.clientVersion })
  expect((await wire.next('hello.ack')).protocol).toBe(1)
  return wire
}
async function link(hostDevice: Device, clientDevice: Device) {
  const host = await connect(hostDevice), client = await connect(clientDevice)
  client.send('connect.request', { hostDeviceId: hostDevice.deviceId, preferredTransports: ['lan', 'p2p', 'relay'] })
  const incoming = await host.next('connect.incoming')
  host.send('connect.accepted', { connectionId: incoming.connectionId })
  expect((await client.next('connect.accepted')).connectionId).toBe(incoming.connectionId)
  return { host, client, connectionId: incoming.connectionId as string }
}
beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-multi-account-'))
  await start()
  sessions = [await login(0), await login(1)]
})
afterEach(async () => {
  for (const noise of noiseSessions.splice(0)) noise.destroy()
  for (const ws of sockets.splice(0)) ws.terminate()
  await app.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('多账号隔离', () => {
  it('JSON 环境配置验证重复账号、残缺项及旧配置冲突', () => {
    expect(parseAccountsEnvironment(JSON.stringify(accounts))).toMatchObject(accounts)
    expect(parseAccountsEnvironment(undefined, accounts[0]!.account, accounts[0]!.password)).toMatchObject([accounts[0]!])
    expect(() => parseAccountsEnvironment(JSON.stringify([accounts[0], accounts[0]]))).toThrow()
    expect(() => parseAccountsEnvironment(JSON.stringify([{ account: accounts[0]!.account }]))).toThrow()
    expect(() => parseAccountsEnvironment(JSON.stringify(accounts), accounts[0]!.account, accounts[0]!.password)).toThrow()
  })

  it('双账号只列出自己的 host，账号列表、设备详情及在线状态不可越权', async () => {
    const aliceHost = await register(0, 'host'), aliceClient = await register(0, 'client')
    const bobHost = await register(1, 'host'), bobClient = await register(1, 'client')
    const alice = await request('/account/devices', 'GET', undefined, sessions[0])
    const bob = await request('/account/devices', 'GET', undefined, sessions[1])
    expect(alice.status).toBe(200); expect(bob.status).toBe(200)
    expect(alice.data.items.map((item: any) => item.deviceId).sort()).toEqual([aliceHost.deviceId, aliceClient.deviceId].sort())
    expect(bob.data.items.map((item: any) => item.deviceId).sort()).toEqual([bobHost.deviceId, bobClient.deviceId].sort())
    const visible = await request('/devices', 'GET', undefined, aliceClient.accessToken)
    expect(visible.status).toBe(200)
    expect(visible.data.items.map((item: any) => item.deviceId)).toEqual([aliceHost.deviceId])
    expect((await request('/devices', 'GET', undefined, bobClient.accessToken)).data.items.map((item: any) => item.deviceId)).toEqual([bobHost.deviceId])
    for (const path of [`/devices/${bobHost.deviceId}`, `/devices/${bobHost.deviceId}/presence`]) {
      const result = await request(path, 'GET', undefined, aliceClient.accessToken)
      expect([403, 404]).toContain(result.status)
      expect(JSON.stringify(result.data)).not.toContain(bobHost.identityKey)
    }
    const renamed = await request(`/devices/${bobHost.deviceId}/name`, 'POST', { name: 'stolen' }, sessions[0])
    expect([403, 404]).toContain(renamed.status)
    expect((await request('/account/devices', 'GET', undefined, sessions[1])).data.items.find((d: any) => d.deviceId === bobHost.deviceId).name).toBe(bobHost.name)
    expect((await request(`/devices/${aliceHost.deviceId}/presence`, 'GET', undefined, aliceClient.accessToken)).status).toBe(200)
  })

  it('分页按设备 ID 排序、限制上限且游标不泄漏其他租户', async () => {
    const ids = [randomUUID(), randomUUID(), randomUUID()].sort((a, b) => a < b ? -1 : a > b ? 1 : 0)
    for (const id of ids) await register(0, 'host', id)
    const bob = await register(1, 'host')
    const aliceClient = await register(0, 'client')
    const first = await request('/devices?limit=1', 'GET', undefined, aliceClient.accessToken)
    expect(first.status).toBe(200)
    expect(first.data.items.map((item: any) => item.deviceId)).toEqual(ids.slice(0, 1))
    expect(first.data.nextCursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    expect(first.data.nextCursor).not.toBe(ids[0])
    const second = await request(`/devices?limit=1&cursor=${encodeURIComponent(first.data.nextCursor)}`, 'GET', undefined, aliceClient.accessToken)
    expect(second.data.items.map((item: any) => item.deviceId)).toEqual(ids.slice(1, 2))
    const third = await request(`/devices?limit=1&cursor=${encodeURIComponent(second.data.nextCursor)}`, 'GET', undefined, aliceClient.accessToken)
    expect(third.data.items.map((item: any) => item.deviceId)).toEqual(ids.slice(2))
    expect(third.data.nextCursor).toBeNull()
    const fromBob = await request(`/devices?limit=100&cursor=${encodeURIComponent(bob.deviceId)}`, 'GET', undefined, aliceClient.accessToken)
    expect(fromBob.status).toBe(400)
    const bobClient = await register(1, 'client')
    expect((await request(`/devices?cursor=${encodeURIComponent(first.data.nextCursor)}`, 'GET', undefined, bobClient.accessToken)).status).toBe(400)
    expect((await request(`/account/devices?cursor=${encodeURIComponent(first.data.nextCursor)}`, 'GET', undefined, sessions[0])).status).toBe(400)
    expect((await request('/devices?limit=101', 'GET', undefined, aliceClient.accessToken)).status).toBe(400)
    const accountPage = await request('/account/devices?limit=1', 'GET', undefined, sessions[1])
    expect(accountPage.data.items).toHaveLength(1)
    expect([bob.deviceId, bobClient.deviceId]).toContain(accountPage.data.items[0].deviceId)
    expect(accountPage.data.nextCursor).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  })

  it('已占用 deviceId 与跨账号 register-owned-role 均不能转移所有权', async () => {
    const aliceHost = await register(0, 'host'), bobClient = await register(1, 'client')
    for (const identityKey of [aliceHost.identityKey, generateKeyPair().publicKey]) {
      const collision = await request('/devices/register', 'POST', { v: 1, device: { deviceId: aliceHost.deviceId, identityKey, name: 'hijack', role: 'host', platform: 'linux', clientVersion: '0.6.3' } }, sessions[1])
      expect([403, 404, 409]).toContain(collision.status)
    }
    expect((await request('/devices', 'GET', undefined, aliceHost.accessToken)).status).toBe(403)
    const owned = await request('/devices/register-owned-role', 'POST', { v: 1, device: { deviceId: aliceHost.deviceId, identityKey: aliceHost.identityKey, name: 'hijack', role: 'host', platform: 'linux', clientVersion: '0.6.3' } }, bobClient.accessToken)
    expect([403, 404, 409]).toContain(owned.status)
    expect((await request('/me', 'GET', undefined, aliceHost.accessToken)).status).toBe(200)
    expect((await request('/account/devices', 'GET', undefined, sessions[1])).data.items.map((d: any) => d.deviceId)).not.toContain(aliceHost.deviceId)
  })

  it('refresh 拒绝错误设备、其他账号 token，密码变更和禁用仅使对应租户失效', async () => {
    const alice = await register(0, 'client'), bob = await register(1, 'client')
    expect((await request('/auth/refresh', 'POST', { deviceId: bob.deviceId, refreshToken: alice.refreshToken })).status).toBe(401)
    expect((await request('/auth/refresh', 'POST', { deviceId: alice.deviceId, refreshToken: bob.refreshToken })).status).toBe(401)
    await app.close()
    await start([accounts[0]!, { ...accounts[1]!, password: 'new-bob-password-123456' }])
    expect((await request('/devices', 'GET', undefined, alice.accessToken)).status).toBe(200)
    expect((await request('/devices', 'GET', undefined, bob.accessToken)).status).toBe(401)
    expect((await request('/auth/login', 'POST', { email: accounts[1]!.account, password: accounts[1]!.password })).status).toBe(401)
    expect((await request('/auth/login', 'POST', { email: accounts[1]!.account, password: 'new-bob-password-123456' })).status).toBe(200)
    expect((await request('/auth/refresh', 'POST', { deviceId: bob.deviceId, refreshToken: bob.refreshToken })).status).toBe(401)
    expect((await request('/auth/refresh', 'POST', { deviceId: alice.deviceId, refreshToken: alice.refreshToken })).status).toBe(200)
    expect((await request('/auth/login', 'POST', { email: accounts[0]!.account, password: accounts[0]!.password })).status).toBe(200)
    await app.close()
    await start([accounts[0]!, { ...accounts[1]!, disabled: true }])
    expect((await request('/devices', 'GET', undefined, alice.accessToken)).status).toBe(200)
    expect((await request('/auth/login', 'POST', { email: accounts[1]!.account, password: accounts[1]!.password })).status).toBe(401)
    expect((await request('/auth/refresh', 'POST', { deviceId: bob.deviceId, refreshToken: bob.refreshToken })).status).toBe(401)
  })

  it('跨账号连接请求在 Host 收到 incoming 前拒绝，同账号 Noise IK 密文往返', async () => {
    const aliceHost = await register(0, 'host'), aliceClient = await register(0, 'client'), bobClient = await register(1, 'client')
    const host = await connect(aliceHost), stranger = await connect(bobClient)
    stranger.send('connect.request', { hostDeviceId: aliceHost.deviceId, preferredTransports: ['relay'] })
    expect((await stranger.next('error')).code).toBe('MEMBERSHIP_REQUIRED')
    expect(host.messages.filter(message => message.type === 'connect.incoming')).toHaveLength(0)
    const client = await connect(aliceClient)
    client.send('connect.request', { hostDeviceId: aliceHost.deviceId, preferredTransports: ['relay'] })
    const { connectionId } = await host.next('connect.incoming')
    host.send('connect.accepted', { connectionId })
    await client.next('connect.accepted')
    const prologue = createNoisePrologue(connectionId, aliceHost.deviceId, aliceClient.deviceId)
    const initiator = new NoiseIkSession({ role: 'initiator', localPrivateKey: aliceClient.keys.privateKey, localPublicKey: aliceClient.identityKey, remotePublicKey: aliceHost.identityKey, prologue })
    const responder = new NoiseIkSession({ role: 'responder', localPrivateKey: aliceHost.keys.privateKey, localPublicKey: aliceHost.identityKey, remotePublicKey: aliceClient.identityKey, prologue })
    noiseSessions.push(initiator, responder)
    client.send('secure.handshake', { connectionId, targetDeviceId: aliceHost.deviceId, step: 1, data: toBase64Url(initiator.writeHandshake()) })
    responder.readHandshake(fromBase64Url((await host.next('secure.handshake')).data))
    host.send('secure.handshake', { connectionId, targetDeviceId: aliceClient.deviceId, step: 2, data: toBase64Url(responder.writeHandshake()) })
    initiator.readHandshake(fromBase64Url((await client.next('secure.handshake')).data))
    const text = new TextEncoder().encode('private message')
    client.send('relay', { connectionId, targetDeviceId: aliceHost.deviceId, counter: 0, ciphertext: toBase64Url(initiator.encrypt(text)) })
    const incoming = await host.next('relay')
    expect(incoming.ciphertext).not.toContain('private message')
    expect(new TextDecoder().decode(responder.decrypt(fromBase64Url(incoming.ciphertext)))).toBe('private message')
    host.send('relay', { connectionId, targetDeviceId: aliceClient.deviceId, counter: 0, ciphertext: toBase64Url(responder.encrypt(new TextEncoder().encode('private reply'))) })
    expect(new TextDecoder().decode(initiator.decrypt(fromBase64Url((await client.next('relay')).ciphertext)))).toBe('private reply')
  })

  it('同租户 LAN/P2P offer、answer、ICE 与 transport.selected 信令仍能转发', async () => {
    const hostDevice = await register(0, 'host'), clientDevice = await register(0, 'client')
    const { host, client, connectionId } = await link(hostDevice, clientDevice)
    client.send('signal.offer', { connectionId, targetDeviceId: hostDevice.deviceId, sdp: 'v=0 offer' })
    expect((await host.next('signal.offer')).sdp).toBe('v=0 offer')
    host.send('signal.answer', { connectionId, targetDeviceId: clientDevice.deviceId, sdp: 'v=0 answer' })
    expect((await client.next('signal.answer')).sdp).toBe('v=0 answer')
    const candidate = { candidate: 'candidate:1 1 udp 2122260223 192.0.2.1 50001 typ host', sdpMid: '0', sdpMLineIndex: 0 }
    client.send('signal.ice', { connectionId, targetDeviceId: hostDevice.deviceId, candidate })
    expect((await host.next('signal.ice')).candidate).toEqual(candidate)
    client.send('transport.selected', { connectionId, targetDeviceId: hostDevice.deviceId, transport: 'lan' })
    expect((await host.next('transport.selected')).transport).toBe('lan')
  })
})

describe('旧状态迁移', () => {
  it('保留 membershipId 和尚未过期的 access/refresh token，且创建不覆盖的 v1 备份', async () => {
    await app.close()
    const file = join(dir, 'state.json')
    rmSync(file)
    const legacy = new Store(file, accounts[0]!.account, accounts[0]!.password)
    const keys = generateKeyPair(), deviceId = randomUUID()
    const descriptor = { deviceId, identityKey: keys.publicKey, name: 'legacy', role: 'client' as const, platform: 'linux', clientVersion: '0.6.3' }
    const issued = legacy.register(descriptor)
    const modern = JSON.parse(readFileSync(file, 'utf8'))
    const { salt, verifier } = modern.accounts[hash(accounts[0]!.account)]
    const devices = Object.fromEntries(Object.entries(modern.devices).map(([id, entry]) => { const { accountId: _accountId, ...device } = entry as Record<string, unknown>; return [id, device] }))
    const tokens = Object.fromEntries(Object.entries(modern.tokens).map(([id, entry]) => { const { accountId: _accountId, ...token } = entry as Record<string, unknown>; return [id, token] }))
    const before = JSON.stringify({ version: 1, account: accounts[0]!.account, salt, verifier, devices, tokens })
    writeFileSync(file, before)
    const originalMembership = `account:${hash(accounts[0]!.account).slice(0, 16)}`
    await start()
    expect((await request('/me', 'GET', undefined, issued.accessToken)).data.membershipId).toBe(originalMembership)
    const state = JSON.parse(readFileSync(file, 'utf8'))
    expect(state.tokens[hash(issued.refreshToken)].expires).toBe(issued.refreshTokenExpiresAt)
    expect((await request('/auth/refresh', 'POST', { deviceId, refreshToken: issued.refreshToken })).status).toBe(200)
    expect(state.version).toBe(2)
    const backup = file + '.v1.bak'
    expect(existsSync(backup)).toBe(true)
    expect(readFileSync(backup, 'utf8')).toBe(before)
    await app.close()
    await start()
    expect(readFileSync(backup, 'utf8')).toBe(before)
  })

  it('若 v1 备份内容不同则拒绝迁移；相同内容允许安全重试', async () => {
    await app.close()
    const file = join(dir, 'state.json')
    rmSync(file)
    const legacy = new Store(file, accounts[0]!.account, accounts[0]!.password)
    legacy.register({ deviceId: randomUUID(), identityKey: generateKeyPair().publicKey, name: 'legacy', role: 'client', platform: 'linux', clientVersion: '0.6.3' })
    const modern = JSON.parse(readFileSync(file, 'utf8'))
    const { salt, verifier } = modern.accounts[hash(accounts[0]!.account)]
    const devices = Object.fromEntries(Object.entries(modern.devices).map(([id, entry]) => { const { accountId: _accountId, ...device } = entry as Record<string, unknown>; return [id, device] }))
    const tokens = Object.fromEntries(Object.entries(modern.tokens).map(([id, entry]) => { const { accountId: _accountId, ...token } = entry as Record<string, unknown>; return [id, token] }))
    const original = JSON.stringify({ version: 1, account: accounts[0]!.account, salt, verifier, devices, tokens })
    writeFileSync(file, original)
    const backup = file + '.v1.bak', sentinel = 'do not overwrite existing backup'
    writeFileSync(backup, sentinel)
    expect(() => createRemoteServer({ accounts, dataFile: file, publicUrl: 'http://localhost:8080' })).toThrow()
    expect(readFileSync(file, 'utf8')).toBe(original)
    expect(readFileSync(backup, 'utf8')).toBe(sentinel)
    writeFileSync(backup, original)
    await start()
    expect(readFileSync(backup, 'utf8')).toBe(original)
  })
})
