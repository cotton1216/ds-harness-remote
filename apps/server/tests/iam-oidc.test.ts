import { createHash, generateKeyPairSync, sign as signData } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { afterEach, describe, expect, it } from 'vitest'
import { OidcError, oidcIdentityFromCode, type OidcConfig } from '../src/iam-oidc.js'
import { createRemoteServer } from '../src/server.js'

/**
 * 这些用例不碰真 IAM：本地起一个假 IdP，自己签发 RS256 的 id_token。
 * 目的是把「换票 → 验签 → 校验 iss/aud/exp/nonce → 取 sub」这条链路钉死，
 * 等真 secret 到手只需要换配置，代码不用再动。
 */

const servers: Server[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))))
})

const b64url = (value: Buffer | string): string =>
  Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = { ...publicKey.export({ format: 'jwk' }) as Record<string, unknown>, kid: 'test-kid', use: 'sig', alg: 'RS256' }

interface IdpOptions {
  /** 覆盖 discovery 里的 token_endpoint，用来测「端点跑出 issuer」被拒。 */
  foreignTokenEndpoint?: string
  claimOverrides?: Record<string, unknown>
  /** 故意用错误的私钥签名，模拟伪造。 */
  tamperPayload?: boolean
}

function mintIdToken(issuer: string, clientId: string, nonce: string | undefined, options: IdpOptions): string {
  const now = Math.floor(Date.now() / 1000)
  const header = b64url(JSON.stringify({ alg: 'RS256', kid: 'test-kid', typ: 'JWT' }))
  const payload = b64url(JSON.stringify({
    iss: issuer,
    aud: clientId,
    sub: 'usr_test_0001',
    exp: now + 300,
    iat: now,
    ...(nonce === undefined ? {} : { nonce }),
    preferred_username: 'zhangsan',
    email: 'zhangsan@example.com',
    ...options.claimOverrides,
  }))
  const signature = signData('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey)
  const tail = options.tamperPayload
    // 换掉 payload 但保留原签名：必须被验签拦下。
    ? b64url(JSON.stringify({ iss: issuer, aud: clientId, sub: 'usr_attacker', exp: now + 300 }))
    : payload
  return `${header}.${tail}.${b64url(signature)}`
}

async function startIdp(options: IdpOptions = {}): Promise<{ issuer: string; config: OidcConfig; calls: string[] }> {
  const calls: string[] = []
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    calls.push(`${req.method} ${url.pathname}`)
    if (url.pathname === '/.well-known/openid-configuration') {
      const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        issuer: base,
        token_endpoint: options.foreignTokenEndpoint ?? `${base}/api/oidc/token`,
        jwks_uri: `${base}/api/oauth/jwks`,
        code_challenge_methods_supported: ['S256'],
      }))
      return
    }
    if (url.pathname === '/api/oauth/jwks') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ keys: [jwk] }))
      return
    }
    if (url.pathname === '/api/oidc/token' && req.method === 'POST') {
      let raw = ''
      req.on('data', chunk => { raw += chunk })
      req.on('end', () => {
        const form = new URLSearchParams(raw)
        const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
        // 假 IdP 也校验 PKCE：code_verifier 的 S256 必须等于发出去时的 challenge。
        const challenge = b64url(createHash('sha256').update(form.get('code_verifier') ?? '').digest())
        if (form.get('grant_type') !== 'authorization_code' || form.get('code') !== 'good-code'
          || challenge !== expectedChallenge) {
          res.writeHead(400, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'invalid_grant' }))
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'at', id_token: mintIdToken(base, 'client-1', nonceUsed, options) }))
      })
      return
    }
    res.writeHead(404).end()
  })
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  return { issuer: base, config: { issuer: base, clientId: 'client-1', clientSecret: 'secret-1', timeoutMs: 5000 }, calls }
}

let expectedChallenge = ''
let nonceUsed: string | undefined
const verifier = 'a'.repeat(43)
expectedChallenge = b64url(createHash('sha256').update(verifier).digest())

describe('oidcIdentityFromCode', () => {
  it('用授权码换到身份，并带回 preferred_username', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp()
    const identity = await oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
    })
    expect(identity).toEqual({ issuer: config.issuer, subject: 'usr_test_0001', username: 'zhangsan', email: 'zhangsan@example.com' })
  })

  it('验签失败时不返回身份', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp({ tamperPayload: true })
    await expect(oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
    })).rejects.toMatchObject({ code: 'AUTH_INVALID' })
  })

  it('aud 不匹配时拒绝', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp({ claimOverrides: { aud: 'another-client' } })
    await expect(oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
    })).rejects.toMatchObject({ code: 'AUTH_INVALID' })
  })

  it('nonce 不匹配时拒绝', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp()
    await expect(oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-2',
    })).rejects.toMatchObject({ code: 'AUTH_INVALID' })
  })

  it('过期 token 拒绝', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp({ claimOverrides: { exp: Math.floor(Date.now() / 1000) - 10 } })
    await expect(oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
    })).rejects.toMatchObject({ code: 'AUTH_INVALID' })
  })

  it('discovery 指向 issuer 之外的端点时拒绝（防授权码被送到别处）', async () => {
    nonceUsed = 'nonce-1'
    const { config } = await startIdp({ foreignTokenEndpoint: 'https://evil.example/token' })
    await expect(oidcIdentityFromCode(config, {
      code: 'good-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
    })).rejects.toMatchObject({ code: 'UNAVAILABLE' })
  })

  it('授权码或 PKCE 不对时按上游错误处理', async () => {
    nonceUsed = undefined
    const { config } = await startIdp()
    const error = await oidcIdentityFromCode(config, {
      code: 'bad-code', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback',
    }).catch(reason => reason)
    expect(error).toBeInstanceOf(OidcError)
    expect(error).toMatchObject({ code: 'AUTH_INVALID', status: 400 })
  })
})

describe('POST /api/v1/auth/iam/oidc', () => {
  const dirs: string[] = []
  afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }) })

  async function serve(oidc?: OidcConfig): Promise<{ base: string; close: () => Promise<void> }> {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-oidc-route-'))
    dirs.push(dir)
    const app = createRemoteServer({
      accounts: [{ account: 'breakglass', password: 'breakglass-password-1' }],
      dataFile: join(dir, 'state.json'),
      publicUrl: 'http://localhost:8080',
      ...(oidc === undefined ? {} : { oidc }),
    })
    app.server.listen(0, '127.0.0.1')
    await once(app.server, 'listening')
    const base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
    return { base, close: async () => { app.server.closeAllConnections(); await new Promise<void>(r => app.server.close(() => r())) } }
  }

  it('换票成功后签发账号会话，并把 sub 映射成 iam:<sub>', async () => {
    nonceUsed = 'nonce-1'
    const idp = await startIdp()
    const app = await serve(idp.config)
    try {
      const response = await fetch(`${app.base}/api/v1/auth/iam/oidc`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          code: 'good-code', codeVerifier: verifier,
          redirectUri: 'http://127.0.0.1:8765/callback', nonce: 'nonce-1',
        }),
      })
      expect(response.status).toBe(200)
      const session = await response.json() as { token: string; account: string }
      // 对外暴露的 account 是展示名；账号键 `iam:<sub>` 只在服务端内部使用。
      expect(session.account).toBe('zhangsan')
      const me = await fetch(`${app.base}/api/v1/auth/me`, { headers: { authorization: `Bearer ${session.token}` } })
      expect(me.status).toBe(200)
      expect((await me.json() as { account: string }).account).toBe('zhangsan')
      // 会话可用于注册本机设备：证明这条登录链路能直接接上设备发现。
      const register = await fetch(`${app.base}/api/v1/devices/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${session.token}` },
        body: JSON.stringify({
          v: 1,
          device: {
            deviceId: '01a1b5be-0000-7000-8000-00000000aa01',
            name: 'oidc-test-client',
            role: 'client',
            platform: 'probe',
            identityKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            clientVersion: 'test-0.1',
          },
        }),
      })
      expect(register.status).toBe(200)
      expect((await register.json() as { accessToken?: string }).accessToken).toEqual(expect.any(String))
    } finally { await app.close() }
  })

  it('未配置 OIDC 时路由不存在', async () => {
    const app = await serve()
    try {
      const response = await fetch(`${app.base}/api/v1/auth/iam/oidc`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: 'x', codeVerifier: verifier, redirectUri: 'http://127.0.0.1:8765/callback' }),
      })
      expect(response.status).toBe(404)
    } finally { await app.close() }
  })

  it('codeVerifier 太短直接按参数错误拒绝', async () => {
    nonceUsed = 'nonce-1'
    const idp = await startIdp()
    const app = await serve(idp.config)
    try {
      const response = await fetch(`${app.base}/api/v1/auth/iam/oidc`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: 'good-code', codeVerifier: 'short', redirectUri: 'http://127.0.0.1:8765/callback' }),
      })
      expect(response.status).toBeGreaterThanOrEqual(400)
      expect(response.status).toBeLessThan(500)
    } finally { await app.close() }
  })
})
