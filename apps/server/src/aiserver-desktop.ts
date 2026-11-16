/**
 * 如意账号登录：AI-Server 桌面授权（`/desktop/authorize` + `/desktop/exchange`）。
 *
 * 与 `iam-oidc.ts` 的 IAM OIDC 是两条**平行**的入口，产物不同：
 *
 *   IAM OIDC      `POST {issuer}/api/oidc/token`       code + verifier + client_secret -> id_token
 *   如意账号      `POST {base}/api/v1/auth/desktop/exchange`  code + verifier          -> access_token
 *
 * 后者是**公开客户端 PKCE**：不校验 audience、没有 client_secret，(client_id,
 * redirect_uri) 二元组在 AI-Server 的 `desktop_redirect_whitelist` 表里精确匹配。
 * 换到的 access_token 与 AI-Server 网页端同一套 Bearer 身份，因此可以交给
 * `iamProfile` 换出 (issuer, subject)，最终和 OIDC 入口落到同一个账号主键上。
 *
 * 安全约定：
 *   - access_token 只在本次请求的内存里存在，拿到身份后立刻丢弃，不落库不打日志；
 *   - redirect_uri 逐字复用授权时的值，不允许换到未声明的地址；
 *   - 失败只回粗粒度类别，上游响应正文不进错误消息。
 */
import type { IamConfig } from './iam.js'

/**
 * 一条已登记的「客户端 + 回调」二元组。client_id 不是凭据，redirect_uri 是
 * 授权码唯一允许送达的地址，两者在 AI-Server 的白名单表里逐字匹配。
 */
export interface AiserverRegistration {
  /** `<产品>-<平台>`，须在 AI-Server 白名单表内。 */
  clientId: string
  /** 回跳地址：必须与白名单登记值逐字一致。 */
  redirectUri: string
}

/**
 * 一个 client_id 可以挂多条回调（迁移 252 之后），但**中继侧仍按一组一组的
 * 登记项配置**：换票时要同时知道「用哪个 client_id」和「码发到哪个地址」，
 * 只存其中一个都会串。
 */
export interface AiserverDesktopConfig {
  /** AI-Server 部署根，含反代前缀，不带尾部斜杠（如 `https://ai.thchengtay.com/aiserver`）。 */
  baseUrl: string
  /** 浏览器登录（本服务自己的 `/app/callback`）。必填。 */
  web: AiserverRegistration
  /** App 深链登录（自定义 scheme）。未配置为 `null`：手机端入口不启用。 */
  app: AiserverRegistration | null
  timeoutMs: number
}

export class AiserverError extends Error {
  constructor(
    readonly code: 'AUTH_INVALID' | 'UNAVAILABLE' | 'RATE_LIMITED',
    /** 上游 HTTP 状态，仅供日志，不回显给调用方。 */
    readonly status?: number,
    /** 粗粒度失败原因，仅供日志。 */
    readonly detail?: string,
  ) { super(code) }
}

type FetchLike = typeof fetch

/** 与 AI-Server 的 `desktopClientIDPattern` 一致。 */
const CLIENT_ID_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/
/** 网页回跳：本服务自己提供的页面，必须是 http(s)。 */
const WEB_REDIRECT_RE = /^https?:\/\/[^\s]+$/
/** App 回跳：自定义 scheme（`ruyiai://auth3/callback`）或 universal link。 */
const APP_REDIRECT_RE = /^[a-z][a-z0-9+.-]*:\/\/[^\s]+$/

/** 授权页地址：AI-Server 的桌面授权落地页（GET，页面内完成登录态判断与授权确认）。 */
export function aiserverAuthorizeEndpoint(config: AiserverDesktopConfig): string {
  return `${config.baseUrl}/desktop/authorize`
}

/** 换票地址。 */
export function aiserverExchangeEndpoint(config: AiserverDesktopConfig): string {
  return `${config.baseUrl}/api/v1/auth/desktop/exchange`
}

function normalizeBase(raw: string | undefined): string | undefined {
  const trimmed = raw?.trim().replace(/\/+$/, '')
  if (!trimmed) return undefined
  if (!/^https?:\/\/[^\s]+$/.test(trimmed)) return undefined
  return trimmed
}

/**
 * `DSH_AISERVER_BASE` + `DSH_AISERVER_CLIENT_ID` + `DSH_AISERVER_WEB_REDIRECT_URI`
 * 三者齐全才启用；缺任何一个都视为未配置，路由不注册、登录页不显示该按钮。
 *
 * 手机端是可选的第二组：`DSH_AISERVER_MOBILE_CLIENT_ID` +
 * `DSH_AISERVER_MOBILE_REDIRECT_URI`。这一组**半配直接报错**——网页那一组缺项
 * 当作「没启用」是合理的（可能压根不用这功能），但手机会话少填一行，只会让
 * 用户在 App 里点了登录、跳过去、再被告知「未配置」，不如启动时就喊。
 *
 * client_id 的格式与 AI-Server 侧 `desktopClientIDPattern` 保持一致：不符就当未配置，
 * 免得配错之后用户点了按钮才在对方页面报「未知客户端」。
 */
export function aiserverConfigFromEnv(env: NodeJS.ProcessEnv): AiserverDesktopConfig | undefined {
  const baseUrl = normalizeBase(env['DSH_AISERVER_BASE'])
  const clientId = env['DSH_AISERVER_CLIENT_ID']?.trim()
  const redirectUri = env['DSH_AISERVER_WEB_REDIRECT_URI']?.trim()
  if (!baseUrl || !clientId || !redirectUri) return undefined
  if (!CLIENT_ID_RE.test(clientId)) return undefined
  if (!WEB_REDIRECT_RE.test(redirectUri)) return undefined

  const mobileClientId = env['DSH_AISERVER_MOBILE_CLIENT_ID']?.trim()
  const mobileRedirectUri = env['DSH_AISERVER_MOBILE_REDIRECT_URI']?.trim()
  let app: AiserverRegistration | null = null
  if (mobileClientId || mobileRedirectUri) {
    if (!mobileClientId || !mobileRedirectUri) {
      throw new Error('DSH_AISERVER_MOBILE_CLIENT_ID and DSH_AISERVER_MOBILE_REDIRECT_URI must be set together.')
    }
    if (!CLIENT_ID_RE.test(mobileClientId)) throw new Error('Invalid DSH_AISERVER_MOBILE_CLIENT_ID.')
    // App 用自定义 scheme，网页那条仍要求 http(s)：这里放宽到任意 scheme，但必须带 `://`。
    if (!APP_REDIRECT_RE.test(mobileRedirectUri)) throw new Error('Invalid DSH_AISERVER_MOBILE_REDIRECT_URI.')
    // 两条登记共用同一个回调时无法按地址反查该用哪个 client_id，直接判配置错误。
    if (mobileRedirectUri === redirectUri) {
      throw new Error('DSH_AISERVER_MOBILE_REDIRECT_URI must differ from DSH_AISERVER_WEB_REDIRECT_URI.')
    }
    app = { clientId: mobileClientId, redirectUri: mobileRedirectUri }
  }

  return { baseUrl, web: { clientId, redirectUri }, app, timeoutMs: 10_000 }
}

/**
 * 按回调地址反查登记项。
 *
 * 换票请求体里**不带 client_id**：调用方只能声明「我用的是哪个回调地址」，
 * 用哪个客户端由服务端配置决定，避免有人拿网页的 client_id 配手机的回调。
 */
export function registrationFor(config: AiserverDesktopConfig, redirectUri: string): AiserverRegistration | undefined {
  if (redirectUri === config.web.redirectUri) return config.web
  if (config.app !== null && redirectUri === config.app.redirectUri) return config.app
  return undefined
}

interface ExchangeInput {
  code: string
  codeVerifier: string
  /** 授权请求里用过的回调地址；调用方必须原样传回，这里再做一次声明值比对。 */
  redirectUri: string
}

/** AI-Server 的成功响应外面套了一层 `{code:0, data:…}` 信封。 */
interface ExchangeEnvelope {
  code?: unknown
  message?: unknown
  data?: { access_token?: unknown; token_type?: unknown }
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  fetchImpl: FetchLike,
): Promise<{ status: number; body: unknown }> {
  let response: Response
  try {
    response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) })
  } catch (error) {
    throw new AiserverError('UNAVAILABLE', undefined, error instanceof Error ? error.name : 'network_error')
  }
  if (response.status === 429) throw new AiserverError('RATE_LIMITED', 429)
  const text = await response.text()
  let body: unknown = undefined
  try { body = text === '' ? undefined : JSON.parse(text) } catch { body = undefined }
  return { status: response.status, body }
}

/**
 * 用一次性 code + PKCE 换 AI-Server 账号令牌。
 *
 * 只返回 access_token 字符串；调用方必须立刻用它换身份并丢弃，不得持久化。
 * 401/400 都归为 `AUTH_INVALID`：code 过期、被撤销、PKCE 不匹配、回调不在白名单，
 * 对调用方来说都只意味着「重新登录」，区分细节只会给攻击者提供信息。
 */
export async function exchangeDesktopCode(
  config: AiserverDesktopConfig,
  input: ExchangeInput,
  fetchImpl: FetchLike = fetch,
): Promise<string> {
  // 纵深防御：AI-Server 侧已按白名单精确匹配，这里再确认一次调用方没有把授权码
  // 导向别的地址——两者不一致说明请求被改过，直接失败。
  // 顺带解决「用哪个 client_id」：只认登记过的回调地址，请求体里没有这个字段。
  const registration = registrationFor(config, input.redirectUri)
  if (registration === undefined) {
    throw new AiserverError('AUTH_INVALID', undefined, 'redirect-mismatch')
  }
  if (input.code === '' || input.code.length > 4096) {
    throw new AiserverError('AUTH_INVALID', undefined, 'bad-code')
  }
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier)) {
    throw new AiserverError('AUTH_INVALID', undefined, 'bad-verifier')
  }
  const { status, body } = await fetchJson(
    aiserverExchangeEndpoint(config),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: registration.clientId,
        code: input.code,
        code_verifier: input.codeVerifier,
        redirect_uri: registration.redirectUri,
      }),
    },
    config.timeoutMs,
    fetchImpl,
  )
  if (status === 400 || status === 401 || status === 403) throw new AiserverError('AUTH_INVALID', status)
  if (status !== 200) throw new AiserverError('UNAVAILABLE', status)
  const envelope = body as ExchangeEnvelope | undefined
  // `code` 缺失或非 0 都说明这次换票没有成功，哪怕 HTTP 是 200。
  if (envelope?.code !== 0 && envelope?.code !== undefined) {
    throw new AiserverError('AUTH_INVALID', status, 'envelope-code')
  }
  const token = envelope?.data?.access_token
  if (typeof token !== 'string' || token.trim() === '') {
    throw new AiserverError('AUTH_INVALID', status, 'no-access-token')
  }
  return token
}

/**
 * 该部署是否具备「如意账号登录」的完整条件：既要 AI-Server 换票配置，
 * 也要能从 profile 读出可信身份（`DSH_IDENTITY_BASE` + `DSH_IAM_ISSUER`）。
 * 缺后者时换到令牌也无法建立账号，登录页干脆不显示入口。
 */
export function aiserverLoginEnabled(
  aserver: AiserverDesktopConfig | undefined,
  iam: IamConfig | undefined,
): aserver is AiserverDesktopConfig {
  return aserver !== undefined && iam !== undefined && iam.expectedIssuer !== undefined
}
