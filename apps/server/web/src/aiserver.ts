/**
 * 如意账号登录：AI-Server 桌面授权（`/desktop/authorize` → `/desktop/exchange`）。
 *
 * 与 `oidc.ts` 的区别不只是换了个地址，参数集也不一样：
 *
 *   IAM OIDC     response_type / client_id / redirect_uri / scope / state / nonce
 *                / code_challenge / code_challenge_method
 *   如意账号      client_id / redirect_uri / state / code_challenge / code_challenge_method
 *
 * AI-Server 的授权页不认 `response_type`、`scope`、`nonce`，多传只会让地址更容易对不上，
 * 所以这里只拼它要的五个参数。
 *
 * 另一处硬约束来自 AI-Server 的校验式：`state` 必须 **32–128** 个 `[A-Za-z0-9_-]`，
 * `code_verifier` 必须 43–128 个 `[A-Za-z0-9._~-]`。`oidc.ts` 里 state 取 16 字节
 * （22 字符）会被直接判 400，所以这里 state 用 32 字节（43 字符）。
 *
 * 与 OIDC 的待校验参数分开存：两套流程的 state/verifier 互不通用，混在一起会在回调时
 * 用错谜题。发起登录前互相清理，保证同一时刻只有一个「进行中」的流程。
 */
export interface AiserverRegistration {
  clientId: string
  redirectUri: string
  authorizeEndpoint: string
}

export interface AiserverLoginConfig {
  clientId: string
  redirectUri: string
  authorizeEndpoint: string
  /**
   * App 深链那一条登记（自定义 scheme）。网页用不到，下发它是给手机端读的：
   * 未配置时为 `null`，手机端据此判断「这套中继支不支持 App 登录」。
   */
  app?: AiserverRegistration | null
}

interface Pending {
  state: string
  verifier: string
  /** 授权请求里用过的回调地址，换票时必须逐字复用同一个值。 */
  redirectUri: string
}

const PENDING_KEY = 'dsh.aiserver.pending'
/** 与 `oidc.ts` 内部的 pending key 同名；这里只用来在发起登录时清掉另一套流程。 */
const OIDC_PENDING_KEY = 'dsh.oidc.pending'

function base64Url(bytes: Uint8Array): string {
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** 随机串直接取 base64url，避免 `+` `/` `=` 在 URL 与表单里的转义差异。 */
function randomToken(byteLength: number): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)))
}

/** `code_challenge = BASE64URL(SHA256(code_verifier))`，不带 `=` 填充。 */
async function codeChallenge(verifier: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))
}

/** 清掉两套流程的待校验参数：新登录开始时不留下上一次的谜题。 */
export function clearLoginPending(): void {
  sessionStorage.removeItem(PENDING_KEY)
  sessionStorage.removeItem(OIDC_PENDING_KEY)
}

/**
 * 生成待校验参数并拼出 AI-Server 授权地址。调用方负责跳转。
 *
 * 注意：这个地址是 AI-Server 的一个**页面**（GET），不是 OAuth 的 authorize 端点。
 * 页面自己判断登录态、展示授权确认，然后由它把浏览器送回 `redirectUri`。
 */
export async function buildAiserverAuthorizeUrl(config: AiserverLoginConfig): Promise<string> {
  // 32 字节 → 43 个 base64url 字符，满足 AI-Server 对 state 的 32 字符下限。
  const state = randomToken(32)
  // 48 字节 → 64 个字符，落在 43–128 区间中部。
  const verifier = randomToken(48)
  sessionStorage.setItem(PENDING_KEY, JSON.stringify({
    state, verifier, redirectUri: config.redirectUri,
  } satisfies Pending))
  // 两套流程互斥：发起这套就把 OIDC 那套的谜题扔掉，回调时不会取错。
  sessionStorage.removeItem(OIDC_PENDING_KEY)
  const url = new URL(config.authorizeEndpoint)
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', await codeChallenge(verifier))
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

/** 取出并立即清除本次登录的待校验参数：一个 verifier 只能用一次。 */
export function takeAiserverPending(): Pending | undefined {
  const raw = sessionStorage.getItem(PENDING_KEY)
  sessionStorage.removeItem(PENDING_KEY)
  if (raw === null) return undefined
  try {
    const parsed = JSON.parse(raw) as Partial<Pending>
    if (typeof parsed.state !== 'string' || typeof parsed.verifier !== 'string' || typeof parsed.redirectUri !== 'string') return undefined
    return { state: parsed.state, verifier: parsed.verifier, redirectUri: parsed.redirectUri }
  } catch { return undefined }
}
