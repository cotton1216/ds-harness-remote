/**
 * 如意账号登录（AI-Server 桌面授权）的契约测试。
 *
 * 保护四条边界，不覆盖 UI 文案：
 *   1. 三件套不全就不启用，登录页拿到的 `aiserver` 是 null；
 *   2. 换到的 access_token 只用于读 profile，不落 cookie、不回传；
 *   3. redirect_uri 逐字比对，且校验收在发请求之前（不改写请求目的地）；
 *   4. 两条入口（OIDC / 如意账号）落到同一个账号主键上。
 *
 * 用一个本地 HTTP 服务扮演 AI-Server：测试不碰外网，也不依赖真实白名单。
 */
import { runScenarios, scenarioName } from '../../../scripts/test-scenarios.mjs'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { createRemoteServer, type Config } from '../src/server.js'
import { aiserverConfigFromEnv, exchangeDesktopCode, type AiserverDesktopConfig } from '../src/aiserver-desktop.js'

const account = 'owner@example.com'
const password = 'local-test-password'
const issuer = 'https://ai.thchengtay.com/iam'
const clientId = 'dsh-remote-web'
const redirectUri = 'http://localhost:8080/app/callback'
/** 手机端那条登记：AI-Server 白名单里的新回调（迁移 252 之后同一 client_id 可挂多条）。 */
const appClientId = 'ruyi-android'
const appRedirectUri = 'ruyiai://auth3/callback'

/** 有效的 code 与它换出的令牌：只有这一对能让假服务返回成功。 */
const GOOD_CODE = 'c'.repeat(43)
const GOOD_VERIFIER = 'v'.repeat(64)
const ACCESS_TOKEN = 'aiserver-access-token-for-test-only'

let dir: string
let mock: Server
let mockBase: string
let app: ReturnType<typeof createRemoteServer> | undefined
/** 假服务收到的请求：用来断言「校验失败时根本没发出去」。 */
let seen: { path: string; authorization: string; body: unknown }[]
/** 让 profile 这一步拒绝：验证「换到令牌 ≠ 登录成功」。 */
let profileRejects = false
/** 让换票这一步直接返回指定状态码：验证上游 5xx 不会被当成凭据错误。 */
let exchangeStatus: number | undefined

const aisrv = (base: string, withApp = false): AiserverDesktopConfig => ({
  baseUrl: base,
  web: { clientId, redirectUri },
  app: withApp ? { clientId: appClientId, redirectUri: appRedirectUri } : null,
  timeoutMs: 2000,
})

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise(resolve => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', chunk => { raw += chunk })
    req.on('end', () => resolve(raw))
  })
}

/** 扮演 AI-Server 的两个端点：桌面对换票 + 用户资料。 */
async function startMock(): Promise<void> {
  mock = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? '').split('?')[0] ?? ''
    const raw = await readBody(req)
    let body: unknown = undefined
    try { body = raw === '' ? undefined : JSON.parse(raw) } catch { body = raw }
    seen.push({ path, authorization: req.headers.authorization ?? '', body })
    const json = (status: number, payload: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(payload))
    }
    if (path === '/api/v1/auth/desktop/exchange') {
      if (exchangeStatus !== undefined) return json(exchangeStatus, { code: exchangeStatus, message: 'upstream down' })
      const input = body as { code?: string; code_verifier?: string; client_id?: string; redirect_uri?: string } | undefined
      // 白名单里两条登记：(网页 client, 网页回调)、(App client, App 回调)。
      const registeredClient = input?.redirect_uri === redirectUri ? clientId
        : input?.redirect_uri === appRedirectUri ? appClientId
        : undefined
      const okCode = input?.code === GOOD_CODE
        && input?.code_verifier === GOOD_VERIFIER
        && input?.client_id === registeredClient
      // 与真实实现一致：参数不符一律 400，且不区分是哪一项错了。
      if (!okCode) return json(400, { code: 400, message: 'Invalid desktop exchange request' })
      return json(200, { code: 0, data: { access_token: ACCESS_TOKEN, refresh_token: 'r', expires_in: 3600, token_type: 'Bearer' } })
    }
    if (path === '/api/v1/user/profile') {
      if (profileRejects || req.headers.authorization !== `Bearer ${ACCESS_TOKEN}`) {
        return json(401, { code: 'INVALID_TOKEN', message: 'Invalid token' })
      }
      return json(200, {
        code: 0,
        data: {
          id: 42, email: 'ruyi@example.com', username: '如意用户',
          identities: { oidc: { provider: 'oidc', bound: true, subject: 'sub-ruyi-1', issuer } },
        },
      })
    }
    return json(404, { code: 'NOT_FOUND' })
  })
  mock.listen(0, '127.0.0.1')
  await once(mock, 'listening')
  mockBase = `http://127.0.0.1:${(mock.address() as { port: number }).port}`
}

async function startServer(overrides: Partial<Config> = {}): Promise<string> {
  app = createRemoteServer({
    account, password, dataFile: join(dir, 'state.json'), publicUrl: 'http://localhost:8080',
    iam: { baseUrl: mockBase, timeoutMs: 2000, expectedIssuer: issuer },
    aiserver: aisrv(mockBase),
    ...overrides,
  })
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  return `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'dsh-aiserver-'))
  seen = []
  profileRejects = false
  exchangeStatus = undefined
  await startMock()
})
afterEach(async () => {
  await app?.close().catch(() => {})
  app = undefined
  await new Promise<void>(resolve => { mock.close(() => resolve()) })
  rmSync(dir, { recursive: true, force: true })
})

describe('如意账号登录配置', () => {
  it('三件套不全就不启用', () => runScenarios([
    { name: '全部缺失', run: async () => {
      expect(aiserverConfigFromEnv({})).toBeUndefined()
    } },
    { name: '缺回调', run: async () => {
      expect(aiserverConfigFromEnv({ DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: clientId })).toBeUndefined()
    } },
    { name: 'client_id 不符合 AI-Server 的命名规则', run: async () => {
      // AI-Server 侧是 ^[a-z0-9][a-z0-9._-]{1,63}$；大写会在对方页面报「未知客户端」，
      // 不如在自己这边就当作未配置。
      expect(aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: 'DSH-Web',
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri,
      })).toBeUndefined()
    } },
    { name: '齐全时去掉尾部斜杠', run: async () => {
      expect(aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver///', DSH_AISERVER_CLIENT_ID: clientId,
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri,
      })).toEqual({
        baseUrl: 'https://a.test/aiserver',
        web: { clientId, redirectUri },
        app: null,
        timeoutMs: 10_000,
      })
    } },
  ].map((scenario, index) => ({ ...scenario, name: scenarioName('aiserver-config', scenario.name, index) }))))

  it('手机端那组是可选的第二组登记', () => runScenarios([
    { name: '配上就多一条 app 登记', run: async () => {
      expect(aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: clientId,
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri,
        DSH_AISERVER_MOBILE_CLIENT_ID: appClientId, DSH_AISERVER_MOBILE_REDIRECT_URI: appRedirectUri,
      })).toMatchObject({ app: { clientId: appClientId, redirectUri: appRedirectUri } })
    } },
    { name: '只填一半直接报错，不静默关掉功能', run: async () => {
      // 网页那组缺项当作「没启用」是合理的；手机这组半填只会在 App 里变成
      // 「点了登录跳过去、再被告知未配置」，启动时就要喊。
      expect(() => aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: clientId,
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri, DSH_AISERVER_MOBILE_CLIENT_ID: appClientId,
      })).toThrow(/must be set together/)
    } },
    { name: '两条回调相同无法反查 client_id', run: async () => {
      expect(() => aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: clientId,
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri,
        DSH_AISERVER_MOBILE_CLIENT_ID: appClientId, DSH_AISERVER_MOBILE_REDIRECT_URI: redirectUri,
      })).toThrow(/must differ/)
    } },
    { name: '自定义 scheme 合法，但必须是 scheme://…', run: async () => {
      expect(() => aiserverConfigFromEnv({
        DSH_AISERVER_BASE: 'https://a.test/aiserver', DSH_AISERVER_CLIENT_ID: clientId,
        DSH_AISERVER_WEB_REDIRECT_URI: redirectUri,
        DSH_AISERVER_MOBILE_CLIENT_ID: appClientId, DSH_AISERVER_MOBILE_REDIRECT_URI: 'ruyiai:auth3',
      })).toThrow(/Invalid DSH_AISERVER_MOBILE_REDIRECT_URI/)
    } },
  ].map((scenario, index) => ({ ...scenario, name: scenarioName('aiserver-app-config', scenario.name, index) }))))

  it('只配换票不配 profile 时拒绝启动', async () => {
    // 换到 access_token 也读不出身份，等于配了个必然失败的按钮，启动时说清楚。
    expect(() => createRemoteServer({
      account, password, dataFile: join(dir, 'state.json'), publicUrl: 'http://localhost:8080',
      aiserver: aisrv('https://a.test/aiserver'),
    })).toThrow(/DSH_IDENTITY_BASE/)
  })

  it('登录页只拿到公开参数，且不含令牌', () => runScenarios([
    { name: '未启用时恒为 null', run: async () => {
      const base = await startServer({ aiserver: undefined })
      const body = await (await fetch(`${base}/api/v1/auth/config`)).json()
      expect(body.aiserver).toBeNull()
      expect(body.oidc).toBeNull()
    } },
    { name: '启用后下发授权端点', run: async () => {
      const base = await startServer()
      const text = await (await fetch(`${base}/api/v1/auth/config`)).text()
      const body = JSON.parse(text)
      expect(body.aiserver).toEqual({
        clientId,
        redirectUri,
        authorizeEndpoint: `${mockBase}/desktop/authorize`,
        // 没配手机那条登记时恒为 null（不省略字段，手机端据此判断支不支持）。
        app: null,
      })
      // 换票不需要 client_secret，响应里更不能出现任何令牌。
      expect(text).not.toContain(ACCESS_TOKEN)
      expect(text).not.toContain('secret')
    } },
    { name: '配了手机那条就一并下发', run: async () => {
      const base = await startServer({ aiserver: aisrv(mockBase, true) })
      const body = await (await fetch(`${base}/api/v1/auth/config`)).json()
      expect(body.aiserver.app).toEqual({
        clientId: appClientId,
        redirectUri: appRedirectUri,
        authorizeEndpoint: `${mockBase}/desktop/authorize`,
      })
    } },
  ].map((scenario, index) => ({ ...scenario, name: scenarioName('aiserver-auth-config', scenario.name, index) }))))
})

describe('如意账号换票', () => {
  it('未配置时路由不存在', async () => {
    const base = await startServer({ aiserver: undefined })
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    expect(response.status).toBe(404)
  })

  it('换票成功后建立会话，且不回传 AI-Server 令牌', async () => {
    const base = await startServer()
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    const text = await response.text()
    expect(response.status).toBe(200)
    // 中继自己签发会话（cookie），AI-Server 的 access_token 到此为止。
    expect(response.headers.get('set-cookie')).toContain('dsh_session')
    expect(text).not.toContain(ACCESS_TOKEN)
    const body = JSON.parse(text)
    expect(body.account).toBeTruthy()
    // profile 那一步必须真的带着换来的令牌去问，否则身份就是凭空造的。
    const profileCall = seen.find(call => call.path === '/api/v1/user/profile')
    expect(profileCall?.authorization).toBe(`Bearer ${ACCESS_TOKEN}`)
  })

  it('换票用的请求体与 AI-Server 契约一致', async () => {
    const base = await startServer()
    await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    const exchangeCall = seen.find(call => call.path === '/api/v1/auth/desktop/exchange')
    expect(exchangeCall?.body).toEqual({
      client_id: clientId, code: GOOD_CODE, code_verifier: GOOD_VERIFIER, redirect_uri: redirectUri,
    })
  })

  it('回调地址不符时拒绝，且不把请求发出去', async () => {
    const base = await startServer()
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri: 'https://evil.test/app/callback' }),
    })
    expect(response.status).toBe(401)
    expect((await response.json()).error.code).toBe('AUTH_INVALID')
    // 校验收在发请求之前：授权码不能被导向未声明的地址。
    expect(seen.some(call => call.path === '/api/v1/auth/desktop/exchange')).toBe(false)
  })

  it('code 无效时返回 401 而不是 500', async () => {
    const base = await startServer()
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: 'x'.repeat(43), codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    expect(response.status).toBe(401)
  })

  it('App 深链换票时自动用手机那条 client_id', async () => {
    const base = await startServer({ aiserver: aisrv(mockBase, true) })
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri: appRedirectUri }),
    })
    expect(response.status).toBe(200)
    expect(response.headers.get('set-cookie')).toContain('dsh_session')
    // 请求体里没有 client_id：用的是哪一条由服务端按回调地址反查，
    // 调用方无法拿网页的 client_id 去配手机的回调。
    const call = seen.find(item => item.path === '/api/v1/auth/desktop/exchange')
    expect(call?.body).toMatchObject({ client_id: appClientId, redirect_uri: appRedirectUri })
  })

  it('没登记的 scheme 不会被放行', async () => {
    const base = await startServer({ aiserver: aisrv(mockBase, true) })
    // 只放宽了「允许自定义 scheme」，不是「任意回调都行」：auth9 没登记就照拒不误。
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri: 'ruyiai://auth9/callback' }),
    })
    expect(response.status).toBe(401)
    expect(seen.some(item => item.path === '/api/v1/auth/desktop/exchange')).toBe(false)
  })

  it('没配手机那条登记时，App 回调一律拒绝', async () => {
    const base = await startServer() // aisrv(mockBase) → app: null
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri: appRedirectUri }),
    })
    expect(response.status).toBe(401)
  })

  it('AI-Server 自身故障时报身份服务不可用，且错误码不写成 IAM', async () => {
    // 这一跳打的是 AI-Server：把它标成 IAM 会让值班的人去查错的服务。
    exchangeStatus = 500
    const base = await startServer()
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    expect(response.status).toBe(503)
    const body = await response.json()
    expect(body.error.code).toBe('IDENTITY_UNAVAILABLE')
    expect(body.error.retryable).toBe(true)
    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('换到令牌但 profile 不认时同样拒绝', async () => {
    profileRejects = true
    const base = await startServer()
    const response = await fetch(`${base}/api/v1/auth/aiserver/exchange`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }),
    })
    // 「拿到了令牌」不等于「登录成功」：身份来自 profile，那一跳失败就不该发会话。
    expect(response.status).toBe(401)
    expect(response.headers.get('set-cookie')).toBeNull()
    expect(seen.map(call => call.path)).toEqual(['/api/v1/auth/desktop/exchange', '/api/v1/user/profile'])
  })
})

describe('换票函数', () => {
  it('HTTP 200 但信封 code 非 0 时视为失败', async () => {
    const fake = (() => Promise.resolve(new Response(JSON.stringify({ code: 400, message: 'no' }), { status: 200 }))) as unknown as typeof fetch
    // AI-Server 的失败可能是 200 + 信封里的 code；只看 HTTP 状态会把失败当成功。
    await expect(exchangeDesktopCode(aisrv('https://a.test'), { code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }, fake))
      .rejects.toMatchObject({ code: 'AUTH_INVALID', detail: 'envelope-code' })
  })

  it('200 但信封里没有 access_token 时视为失败', async () => {
    const fake = (() => Promise.resolve(new Response(JSON.stringify({ code: 0, data: {} }), { status: 200 }))) as unknown as typeof fetch
    await expect(exchangeDesktopCode(aisrv('https://a.test'), { code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }, fake))
      .rejects.toMatchObject({ code: 'AUTH_INVALID', detail: 'no-access-token' })
  })

  it('网络异常映射为不可用而不是凭据错误', async () => {
    const fake = (() => Promise.reject(new Error('ECONNREFUSED'))) as unknown as typeof fetch
    await expect(exchangeDesktopCode(aisrv('https://a.test'), { code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }, fake))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' })
  })

  it('429 单独归类，避免用户把限流当成密码错', async () => {
    const fake = (() => Promise.resolve(new Response('', { status: 429 }))) as unknown as typeof fetch
    await expect(exchangeDesktopCode(aisrv('https://a.test'), { code: GOOD_CODE, codeVerifier: GOOD_VERIFIER, redirectUri }, fake))
      .rejects.toMatchObject({ code: 'RATE_LIMITED' })
  })
})
