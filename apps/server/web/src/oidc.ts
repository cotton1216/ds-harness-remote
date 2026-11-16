/**
 * 浏览器端 OIDC 授权码 + PKCE。
 *
 * 与手机端同一套 IAM 客户端：浏览器只负责生成谜题、把用户送到授权页、拿回一次性
 * code；`client_secret` 永远留在中继进程里，换票由 `/api/v1/auth/iam/oidc` 完成。
 * `code_verifier` / `state` / `nonce` 只存 `sessionStorage`：同一个标签页跨域跳转往返
 * 仍在，关掉标签页即失效，既不落缓存也不进 URL。
 */
import type { AiserverLoginConfig } from './aiserver'

export interface OidcLoginConfig {
  clientId: string
  redirectUri: string
  authorizeEndpoint: string
  scope: string
}

export interface AuthConfig {
  /** 是否配置了本地账号（break-glass）。 */
  password: boolean
  /** 为 null 表示该部署未启用浏览器单点登录。 */
  oidc: OidcLoginConfig | null
  /**
   * 如意账号登录（AI-Server 桌面授权）。与 [oidc] 并列的独立入口，`null` 表示未启用。
   * 两套可以同时开：优先显示这一套，失败时用户仍可退回 OIDC。
   */
  aiserver: AiserverLoginConfig | null
}

interface Pending {
  state: string
  nonce: string
  verifier: string
  /** 授权请求里用过的回调地址，换票时必须逐字复用同一个值。 */
  redirectUri: string
}

const PENDING_KEY = 'dsh.oidc.pending'

function base64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let text = ''
  for (const byte of view) text += String.fromCharCode(byte)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** 随机串直接取 base64url，避免 `+` `/` `=` 在 URL 与表单里的转义差异。 */
function randomToken(byteLength: number): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)))
}

/** `code_challenge = BASE64URL(SHA256(code_verifier))`，不带 `=` 填充。 */
export async function codeChallenge(verifier: string): Promise<string> {
  return base64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
}

/** 生成待校验参数并拼出授权地址。调用方负责跳转。 */
export async function buildAuthorizeUrl(config: OidcLoginConfig): Promise<string> {
  // 48 字节 → 64 个 base64url 字符，落在 IAM 与中继都接受的 43–128 区间中部。
  const verifier = randomToken(48)
  const pending: Pending = { state: randomToken(16), nonce: randomToken(16), verifier, redirectUri: config.redirectUri }
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending))
  const url = new URL(config.authorizeEndpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('scope', config.scope)
  url.searchParams.set('state', pending.state)
  url.searchParams.set('nonce', pending.nonce)
  url.searchParams.set('code_challenge', await codeChallenge(verifier))
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

/** 取出并立即清除本次登录的待校验参数：一个 verifier 只能用一次。 */
export function takePending(): Pending | undefined {
  const raw = sessionStorage.getItem(PENDING_KEY)
  sessionStorage.removeItem(PENDING_KEY)
  if (raw === null) return undefined
  try {
    const parsed = JSON.parse(raw) as Partial<Pending>
    if (typeof parsed.state !== 'string' || typeof parsed.nonce !== 'string' || typeof parsed.verifier !== 'string' || typeof parsed.redirectUri !== 'string') return undefined
    return { state: parsed.state, nonce: parsed.nonce, verifier: parsed.verifier, redirectUri: parsed.redirectUri }
  } catch { return undefined }
}
