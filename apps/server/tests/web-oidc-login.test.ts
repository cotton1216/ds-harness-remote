/**
 * 浏览器 OIDC 登录的契约测试。
 *
 * 只保护三条安全边界，不覆盖 UI 文案或组件结构：
 *   1. `/auth/config` 只暴露公开参数，绝不回传 client_secret；
 *   2. 换票只接受声明过的 redirect_uri，授权码不能被换到别处；
 *   3. CSRF 拦截只作用于 API —— IAM 回跳 `/app/callback` 是跨站顶级导航，
 *      拦掉它就等于单点登录在回跳那一刻必然 403。
 */
import { runScenarios, scenarioName } from '../../../scripts/test-scenarios.mjs'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { createRemoteServer, normalizeWebRedirectUri, type Config } from '../src/server.js'
import { oidcAuthorizeEndpoint, oidcConfigFromEnv } from '../src/iam-oidc.js'
import { codeChallenge } from '../web/src/oidc.js'

const account = 'owner@example.com'
const password = 'local-test-password'
const webRedirect = 'https://relay.test/app/callback'
// 用必然拒绝连接的本地地址当 IAM：换票路径会立刻失败，测试不依赖外网也不留悬挂连接。
const issuer = 'http://127.0.0.1:1/iam'
const authorizeEndpoint = `${issuer}/api/oidc/authorize`
const oidc = { issuer, clientId: 'dsh-remote-mobile', clientSecret: '{{SECRET_7hgb9xgq}}', timeoutMs: 500, authorizationEndpoint: authorizeEndpoint }

let app: ReturnType<typeof createRemoteServer>, dir: string, base: string
/** 每个场景都会起一个实例；逐个收尾，已关闭的忽略即可。 */
const started: ReturnType<typeof createRemoteServer>[] = []

async function start(configOverrides: Partial<Config> = {}) {
  app = createRemoteServer({ account, password, dataFile: join(dir, 'state.json'), publicUrl: 'http://localhost:8080', ...configOverrides })
  started.push(app)
  app.server.listen(0, '127.0.0.1')
  await once(app.server, 'listening')
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`
}

/** 顶级导航：带上浏览器跨站回跳时一定会发的 Sec-Fetch-Site。 */
async function navigate(path: string, headers: Record<string, string> = {}) {
  return fetch(`${base}${path}`, { headers: { 'sec-fetch-site': 'cross-site', ...headers } })
}

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'dsh-web-oidc-')) })
afterEach(async () => {
  for (const instance of started.splice(0)) await instance.close().catch(() => {})
  rmSync(dir, { recursive: true, force: true })
})

describe('浏览器 OIDC 登录', () => {
  it('未配置浏览器回调时只报密码方式，且不泄漏 client_secret', () => runScenarios([
    { name: '纯密码部署', run: async () => {
      await start()
      const response = await fetch(`${base}/api/v1/auth/config`)
      const body = await response.json()
      expect(response.status).toBe(200)
      expect(body).toEqual({ password: true, oidc: null })
    } },
    { name: '配置 OIDC 后只返回公开参数', run: async () => {
      await start({ oidc, webRedirectUri: webRedirect })
      const response = await fetch(`${base}/api/v1/auth/config`)
      const text = await response.text()
      const body = JSON.parse(text)
      expect(response.status).toBe(200)
      // 只有 OIDC、没有本地账号时不该把密码入口露出来。
      expect(body.password).toBe(false)
      expect(body.oidc.clientId).toBe(oidc.clientId)
      expect(body.oidc.redirectUri).toBe(webRedirect)
      expect(body.oidc.scope).toBe('openid profile email')
      expect(body.oidc.authorizeEndpoint).toBe(authorizeEndpoint)
      expect(text).not.toContain(oidc.clientSecret)
    } },
    { name: '同时保留本地账号时密码方式可用', run: async () => {
      await start({ account: undefined, password: undefined, accounts: [{ account, password }], oidc, webRedirectUri: webRedirect })
      const body = await (await fetch(`${base}/api/v1/auth/config`)).json()
      expect(body.password).toBe(true)
      expect(body.oidc).not.toBeNull()
    } },
  ].map(scenario => ({ ...scenario, name: scenarioName('auth-config', scenario.name) }))))

  it('换票只接受声明过的 redirect_uri', () => runScenarios([
    { name: '未声明的地址被拒', run: async () => {
      await start({ oidc, webRedirectUri: webRedirect })
      const response = await fetch(`${base}/api/v1/auth/iam/oidc`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'x'.repeat(20), codeVerifier: 'v'.repeat(43), redirectUri: 'https://evil.test/app/callback' }),
      })
      // 校验发生在调用 IAM 之前，所以这里不会因为 discovery 失败而变成 503。
      expect(response.status).toBe(400)
      expect((await response.json()).error.code).toBe('INVALID_MESSAGE')
    } },
    { name: '手机自定义 scheme 仍然放行', run: async () => {
      await start({ oidc, webRedirectUri: webRedirect })
      const response = await fetch(`${base}/api/v1/auth/iam/oidc`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'x'.repeat(20), codeVerifier: 'v'.repeat(43), redirectUri: 'dshgo://auth/callback' }),
      })
      // 通过白名单后才会去换票；测试环境无法连上 IAM，因此得到 503 而不是 400。
      expect(response.status).toBe(503)
    } },
    { name: '未配置 OIDC 时端点不存在', run: async () => {
      await start()
      const response = await fetch(`${base}/api/v1/auth/iam/oidc`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'x'.repeat(20), codeVerifier: 'v'.repeat(43), redirectUri: 'dshgo://auth/callback' }),
      })
      expect(response.status).toBe(404)
    } },
  ].map(scenario => ({ ...scenario, name: scenarioName('oidc-redirect', scenario.name) }))))

  it('CSRF 拦截只作用于 API', () => runScenarios([
    { name: '跨站回跳到 SPA 路由不被拦', run: async () => {
      await start()
      const response = await navigate('/app/callback?code=abc&state=xyz')
      // 构建产物存在时返回页面，不存在时是 404；两者都证明 CSRF 没有误伤静态入口。
      expect(response.status).not.toBe(403)
      if (response.status === 200) expect(await response.text()).toContain('<div id="root">')
    } },
    { name: '跨站 POST 到 API 仍然被拒', run: async () => {
      await start()
      const response = await fetch(`${base}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'sec-fetch-site': 'cross-site' },
        body: JSON.stringify({ email: account, password }),
      })
      expect(response.status).toBe(403)
    } },
    { name: '跨站 GET 到 API 仍然被拒', run: async () => {
      await start()
      expect((await navigate('/api/v1/auth/config')).status).toBe(403)
    } },
  ].map(scenario => ({ ...scenario, name: scenarioName('csrf-scope', scenario.name) }))))
})

describe('authorize 端点解析', () => {
  const env = { DSH_IAM_OIDC_ISSUER: issuer, DSH_IAM_OIDC_CLIENT_ID: 'c', DSH_IAM_OIDC_CLIENT_SECRET: 's'.repeat(32) }
  it('显式配置的授权端点必须落在 issuer 之下', () => {
    expect(oidcConfigFromEnv({ ...env, DSH_IAM_OIDC_AUTHORIZE_ENDPOINT: 'https://evil.test/authorize' })?.authorizationEndpoint).toBeUndefined()
    expect(oidcConfigFromEnv({ ...env, DSH_IAM_OIDC_AUTHORIZE_ENDPOINT: authorizeEndpoint })?.authorizationEndpoint).toBe(authorizeEndpoint)
  })
  it('发现失败时回退到 issuer 下的标准路径', async () => {
    const failing = (async () => { throw new TypeError('offline') }) as unknown as typeof fetch
    expect(await oidcAuthorizeEndpoint({ ...oidc, authorizationEndpoint: undefined }, failing)).toBe(authorizeEndpoint)
  })
})

describe('浏览器 PKCE', () => {
  it('与 RFC 7636 附录 B 的示例向量一致', async () => {
    // 挑战值算错不会报错，只会让 IAM 在换票时拒绝——所以用标准向量钉住算法。
    expect(await codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})

describe('normalizeWebRedirectUri', () => {
  it('只接受不带 query / hash / 凭据的绝对 HTTP(S) 地址', () => {
    expect(normalizeWebRedirectUri(undefined)).toBeUndefined()
    expect(normalizeWebRedirectUri('  ')).toBeUndefined()
    expect(normalizeWebRedirectUri(webRedirect)).toBe(webRedirect)
    for (const bad of ['/app/callback', 'ftp://relay.test/app/callback', `${webRedirect}?next=x`, `${webRedirect}#frag`, 'https://user:pw@relay.test/app/callback']) {
      expect(() => normalizeWebRedirectUri(bad), bad).toThrow()
    }
  })
  it('配置浏览器回调却没有 OIDC 时启动即失败', () => {
    expect(() => createRemoteServer({ account, password, dataFile: join(dir, 'state.json'), publicUrl: 'http://localhost:8080', webRedirectUri: webRedirect })).toThrow(/DSH_WEB_REDIRECT_URI/)
  })
})
