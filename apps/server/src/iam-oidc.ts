/**
 * 标准 OIDC 身份适配（授权码 + PKCE）。
 *
 * 与 `iam.ts` 的 AI-Server 口令接口不同，这里是 IAM 对外文档 §5.2 的 OIDC 流程：
 *
 *   POST {issuer}/api/oidc/token        code + code_verifier -> id_token
 *   GET  {issuer}/api/oauth/jwks        RS256 公钥
 *
 * 手机端只负责拿到一次性 `code`，换票放在这里做：`client_secret` 只存在于
 * 中继服务器的环境变量里，绝不进 App。换到 `id_token` 后本地验签，再取 `sub`
 * 作为账号主键——不额外调用 UserInfo，少一次网络往返也少一个失败点。
 */
import { createPublicKey, verify as verifySignature } from 'node:crypto'
import { validSubject } from './iam.js'

export interface OidcConfig {
  /** 例如 https://ai.thchengtay.com/iam，不带尾部斜杠。 */
  issuer: string
  clientId: string
  clientSecret: string
  timeoutMs: number
}

export interface OidcIdentity {
  /** 验签通过的 `iss`，与配置的 issuer 完全一致。 */
  issuer: string
  /** IAM 用户 ID（`id_token.sub`）。 */
  subject: string
  username?: string
  email?: string
}

export class OidcError extends Error {
  constructor(
    readonly code: 'AUTH_INVALID' | 'UNAVAILABLE' | 'RATE_LIMITED',
    /** 上游 HTTP 状态，仅供日志，不回显给调用方。 */
    readonly status?: number,
    /** 粗粒度失败原因，仅供日志。 */
    readonly detail?: string,
  ) { super(code) }
}

type FetchLike = typeof fetch

interface Jwk {
  kid?: string
  kty: string
  n?: string
  e?: string
}

const DISCOVERY_TTL_MS = 10 * 60_000
const JWKS_MIN_TTL_MS = 60_000

/** 缓存 discovery 与 JWKS：登录是高频路径，不能每次都打 IAM。 */
const discoveryCache = new Map<string, { value: { tokenEndpoint: string; jwksUri: string }; expires: number }>()
const jwksCache = new Map<string, { value: Map<string, Jwk>; expires: number }>()

/** 三个环境变量齐全才启用；缺任何一个就当作未配置，路由不注册。 */
export function oidcConfigFromEnv(env: NodeJS.ProcessEnv): OidcConfig | undefined {
  const issuer = env['DSH_IAM_OIDC_ISSUER']?.trim().replace(/\/+$/, '')
  const clientId = env['DSH_IAM_OIDC_CLIENT_ID']?.trim()
  const clientSecret = env['DSH_IAM_OIDC_CLIENT_SECRET']?.trim()
  if (!issuer || !clientId || !clientSecret) return undefined
  if (!/^https?:\/\/[^\s]+$/.test(issuer)) return undefined
  return { issuer, clientId, clientSecret, timeoutMs: 10_000 }
}

function b64urlToBuffer(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(normalized + '='.repeat((4 - (normalized.length % 4)) % 4), 'base64')
}

async function fetchJson(url: string, init: RequestInit, timeoutMs: number, fetchImpl: FetchLike): Promise<unknown> {
  let response: Response
  try {
    response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(timeoutMs) })
  } catch (error) {
    throw new OidcError('UNAVAILABLE', undefined, error instanceof Error ? error.name : 'network_error')
  }
  if (response.status === 429) throw new OidcError('RATE_LIMITED', 429)
  const text = await response.text()
  let body: unknown
  try { body = text === '' ? undefined : JSON.parse(text) } catch { body = undefined }
  if (!response.ok) {
    // 只保留错误码字段，绝不把 response body 原文写进日志或返回给调用方。
    const code = body !== null && typeof body === 'object' && typeof (body as Record<string, unknown>)['error'] === 'string'
      ? (body as Record<string, unknown>)['error'] as string
      : undefined
    throw new OidcError('AUTH_INVALID', response.status, code)
  }
  return body
}

async function discovery(config: OidcConfig, fetchImpl: FetchLike): Promise<{ tokenEndpoint: string; jwksUri: string }> {
  const cached = discoveryCache.get(config.issuer)
  if (cached !== undefined && cached.expires > Date.now()) return cached.value
  const body = await fetchJson(`${config.issuer}/.well-known/openid-configuration`, { headers: { accept: 'application/json' } }, config.timeoutMs, fetchImpl)
  const record = body as Record<string, unknown> | undefined
  const tokenEndpoint = record?.['token_endpoint']
  const jwksUri = record?.['jwks_uri']
  if (typeof tokenEndpoint !== 'string' || typeof jwksUri !== 'string') {
    throw new OidcError('UNAVAILABLE', 200, 'invalid-discovery')
  }
  // 端点必须落在 issuer 之下：discovery 被劫持时不能把授权码送到别的域。
  for (const endpoint of [tokenEndpoint, jwksUri]) {
    if (!endpoint.startsWith(`${config.issuer}/`)) throw new OidcError('UNAVAILABLE', 200, 'foreign-endpoint')
  }
  const value = { tokenEndpoint, jwksUri }
  discoveryCache.set(config.issuer, { value, expires: Date.now() + DISCOVERY_TTL_MS })
  return value
}

async function jwks(uri: string, config: OidcConfig, fetchImpl: FetchLike): Promise<Map<string, Jwk>> {
  const cached = jwksCache.get(uri)
  if (cached !== undefined && cached.expires > Date.now()) return cached.value
  const body = await fetchJson(uri, { headers: { accept: 'application/json' } }, config.timeoutMs, fetchImpl)
  const keys = (body as { keys?: unknown } | undefined)?.keys
  if (!Array.isArray(keys)) throw new OidcError('UNAVAILABLE', 200, 'invalid-jwks')
  const map = new Map<string, Jwk>()
  for (const key of keys) {
    if (key === null || typeof key !== 'object') continue
    const jwk = key as Jwk
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue
    map.set(jwk.kid ?? '', jwk)
  }
  if (map.size === 0) throw new OidcError('UNAVAILABLE', 200, 'no-rsa-key')
  jwksCache.set(uri, { value: map, expires: Date.now() + JWKS_MIN_TTL_MS })
  return map
}

/** 校验 RS256 签名与 iss/aud/exp；`nonce` 由调用方提供时一并比对。 */
function verifyIdToken(
  idToken: string,
  keys: Map<string, Jwk>,
  config: OidcConfig,
  nonce: string | undefined,
): OidcIdentity {
  const parts = idToken.split('.')
  if (parts.length !== 3) throw new OidcError('AUTH_INVALID', undefined, 'malformed-token')
  const [header, payload, signature] = parts as [string, string, string]
  let head: { alg?: unknown; kid?: unknown }
  let claims: Record<string, unknown>
  try {
    head = JSON.parse(b64urlToBuffer(header).toString('utf8')) as typeof head
    claims = JSON.parse(b64urlToBuffer(payload).toString('utf8')) as Record<string, unknown>
  } catch {
    throw new OidcError('AUTH_INVALID', undefined, 'malformed-json')
  }
  if (head.alg !== 'RS256') throw new OidcError('AUTH_INVALID', undefined, 'unexpected-alg')
  const jwk = keys.get(typeof head.kid === 'string' ? head.kid : '') ?? (keys.size === 1 ? [...keys.values()][0] : undefined)
  if (jwk === undefined) throw new OidcError('AUTH_INVALID', undefined, 'unknown-kid')
  let ok = false
  try {
    const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n!, e: jwk.e! }, format: 'jwk' })
    ok = verifySignature('RSA-SHA256', Buffer.from(`${header}.${payload}`), key, b64urlToBuffer(signature))
  } catch {
    ok = false
  }
  if (!ok) throw new OidcError('AUTH_INVALID', undefined, 'bad-signature')

  if (claims['iss'] !== config.issuer) throw new OidcError('AUTH_INVALID', undefined, 'issuer-mismatch')
  const audience = claims['aud']
  const audiences = Array.isArray(audience) ? audience : [audience]
  if (!audiences.includes(config.clientId)) throw new OidcError('AUTH_INVALID', undefined, 'audience-mismatch')
  const exp = claims['exp']
  if (typeof exp !== 'number' || exp * 1000 <= Date.now()) throw new OidcError('AUTH_INVALID', undefined, 'token-expired')
  if (nonce !== undefined && claims['nonce'] !== nonce) throw new OidcError('AUTH_INVALID', undefined, 'nonce-mismatch')
  const subject = claims['sub']
  // 与 AI-Server profile 共用同一套 subject 规则，避免两条入口对同一身份判断不一致。
  if (!validSubject(subject)) {
    throw new OidcError('AUTH_INVALID', undefined, 'missing-subject')
  }
  return {
    issuer: config.issuer,
    subject,
    ...(typeof claims['preferred_username'] === 'string' ? { username: claims['preferred_username'] } : {}),
    ...(typeof claims['email'] === 'string' ? { email: claims['email'] } : {}),
  }
}

/**
 * 用授权码换身份。`fetchImpl` 只为测试注入，生产走全局 fetch。
 */
export async function oidcIdentityFromCode(
  config: OidcConfig,
  input: { code: string; codeVerifier: string; redirectUri: string; nonce?: string },
  fetchImpl: FetchLike = fetch,
): Promise<OidcIdentity> {
  const { tokenEndpoint, jwksUri } = await discovery(config, fetchImpl)
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    code_verifier: input.codeVerifier,
  })
  const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')
  const body = await fetchJson(tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      authorization: `Basic ${basic}`,
    },
    body: form.toString(),
  }, config.timeoutMs, fetchImpl)
  const idToken = (body as Record<string, unknown> | undefined)?.['id_token']
  if (typeof idToken !== 'string' || idToken.length === 0) throw new OidcError('AUTH_INVALID', 200, 'missing-id-token')
  return verifyIdToken(idToken, await jwks(jwksUri, config, fetchImpl), config, input.nonce)
}
