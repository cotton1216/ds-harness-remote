/**
 * IAM (AI-Server) identity adapter.
 *
 * The relay never trusts a bearer token on its own: the only way to learn who a
 * caller is, is to ask IAM. Two entry points are used, both observed against the
 * live deployment:
 *
 *   POST {base}/api/v1/auth/login   { email, password } -> { access_token }
 *   GET  {base}/api/v1/user/profile Authorization: Bearer -> { id, email, username, identities }
 *
 * The login response carries no OIDC subject, so a password login must exchange
 * the returned `access_token` for the profile before an account can be derived.
 * The profile's nested `identities.oidc` record is the ONLY trusted identity:
 * the relay never falls back to the numeric user id or to caller-supplied text.
 * `identities.oidc.issuer` must exactly match a server-configured trusted issuer,
 * which keeps the same `sub` from two different issuers in separate accounts.
 */

export interface IamConfig {
  /** Deployment base URL including its reverse-proxy prefix, without trailing slash. */
  baseUrl: string
  timeoutMs: number
  /**
   * Issuer that `identities.oidc.issuer` must match exactly. Resolved from
   * `DSH_IAM_ISSUER`, falling back to the OIDC client's issuer. When IAM is
   * enabled but this is absent the server refuses to start: without a trusted
   * issuer the profile's identity cannot be authenticated.
   */
  expectedIssuer?: string
}

/** The nested identity the relay trusts. `subject` is preserved verbatim. */
export interface IamIdentity {
  issuer: string
  subject: string
}

export interface IamUser {
  /** AI-Server's numeric user id. Only used for the legacy account key when the OIDC binding is missing. */
  id?: number
  email: string
  username: string
  /** Trusted `(issuer, subject)` when the profile carries a valid OIDC binding for the configured issuer. */
  identity?: IamIdentity
  /** Why `identity` is absent. Logged only; never returned to a client. */
  identityProblem?: string
}

export interface IamGrant {
  accessToken: string
  expiresIn?: number
}

export class IamError extends Error {
  /**
   * `status` is the upstream HTTP status when there was a response at all; it is
   * logged for diagnosis but never echoed to the caller.
   */
  constructor(
    readonly code: 'AUTH_INVALID' | 'UNAVAILABLE' | 'RATE_LIMITED',
    readonly status?: number,
    /** Coarse failure kind (e.g. TimeoutError) for logs. Never contains credentials. */
    readonly detail?: string,
  ) { super(code) }
}

const DEFAULT_TIMEOUT_MS = 10_000
/** Profile endpoint is fixed by the server, never taken from input or discovery. */
const PROFILE_PATH = '/api/v1/user/profile'

/** Absolute http(s) issuer without credentials, query or fragment; trailing slashes removed. */
export function normalizeTrustedIssuer(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === '') return undefined
  let url: URL
  try { url = new URL(value.trim()) } catch { throw new Error('Invalid DSH_IAM_ISSUER.') }
  if (url.username || url.password || url.search || url.hash) throw new Error('Invalid DSH_IAM_ISSUER.')
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Invalid DSH_IAM_ISSUER.')
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`
}

/** Accepts only an absolute http(s) base URL; rejects credentials, query, hash and percent-escaped path separators. */
export function parseIamConfig(value: string | undefined, timeoutRaw?: string, expectedIssuerRaw?: string): IamConfig | undefined {
  const expectedIssuer = normalizeTrustedIssuer(expectedIssuerRaw)
  if (value === undefined || value.trim() === '') return undefined
  let url: URL
  try { url = new URL(value.trim()) } catch { throw new Error('Invalid DSH_IAM_BASE.') }
  if (url.username || url.password || url.search || url.hash || /%2f|%5c/i.test(url.pathname)) {
    throw new Error('Invalid DSH_IAM_BASE.')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Invalid DSH_IAM_BASE.')
  const timeoutMs = timeoutRaw === undefined || timeoutRaw.trim() === '' ? DEFAULT_TIMEOUT_MS : Number(timeoutRaw)
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new Error('Invalid DSH_IAM_TIMEOUT_MS.')
  return {
    baseUrl: `${url.origin}${url.pathname.replace(/\/+$/, '')}`,
    timeoutMs,
    ...(expectedIssuer === undefined ? {} : { expectedIssuer }),
  }
}

const envelope = (raw: unknown): unknown => {
  if (raw === null || typeof raw !== 'object') return raw
  const record = raw as Record<string, unknown>
  return 'data' in record ? record['data'] : raw
}

/**
 * A subject is opaque but must be a real value: no empty string, no whitespace
 * or control characters, no "***" masking, and a bounded length. It is never
 * trimmed or rewritten — two distinct subjects must never collapse to one.
 */
export function validSubject(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 200
    && !/[\s\u0000-\u001f\u007f]/.test(value) && !value.includes('*')
}

/** Extract and validate the nested `identities.oidc` record. Never falls back to `id`. */
function toIdentity(value: unknown, expectedIssuer: string | undefined): IamIdentity {
  if (expectedIssuer === undefined) throw new IamError('UNAVAILABLE', undefined, 'missing-trusted-issuer')
  if (value === null || typeof value !== 'object') throw new IamError('UNAVAILABLE', undefined, 'missing-profile')
  const identities = (value as Record<string, unknown>)['identities']
  if (identities === null || typeof identities !== 'object') throw new IamError('AUTH_INVALID', undefined, 'missing-identities')
  const oidc = (identities as Record<string, unknown>)['oidc']
  if (oidc === null || typeof oidc !== 'object') throw new IamError('AUTH_INVALID', undefined, 'missing-oidc-identity')
  const record = oidc as Record<string, unknown>
  if (record['provider'] !== 'oidc') throw new IamError('AUTH_INVALID', undefined, 'unexpected-provider')
  if (record['bound'] !== true) throw new IamError('AUTH_INVALID', undefined, 'identity-unbound')
  if (!validSubject(record['subject'])) throw new IamError('AUTH_INVALID', undefined, 'invalid-subject')
  const issuer = record['issuer']
  if (typeof issuer !== 'string') throw new IamError('AUTH_INVALID', undefined, 'missing-issuer')
  // Exact match after trailing-slash normalization. The slash is not part of the
  // issuer's authority (OIDC forbids a trailing slash), so IAM storing
  // `https://iam/` and the relay configuring `https://iam` are the same issuer.
  // Everything else — scheme, host, port, path — must match verbatim: no prefix
  // or host-only comparison, so a look-alike issuer cannot impersonate a subject
  // of the trusted one.
  const normalized = issuer.replace(/\/+$/, '')
  if (normalized !== expectedIssuer) throw new IamError('AUTH_INVALID', undefined, 'issuer-mismatch')
  return { issuer: normalized, subject: record['subject'] }
}

async function call(config: IamConfig, path: string, init: RequestInit): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${config.baseUrl}${path}`, {
      ...init,
      // Never follow a redirect: a 3xx could send the bearer token to another
      // origin. Treat it as an upstream failure instead.
      redirect: 'manual',
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(config.timeoutMs),
    })
  } catch (error) {
    throw new IamError('UNAVAILABLE', undefined, error instanceof Error ? error.name : 'unknown')
  }
  if (response.status >= 300 && response.status < 400) throw new IamError('UNAVAILABLE', response.status, 'redirect-not-followed')
  let payload: unknown
  try { payload = await response.json() } catch { payload = undefined }
  if (response.status === 401 || response.status === 403) throw new IamError('AUTH_INVALID', response.status, reasonOf(response.status, payload))
  // Keep throttling distinct: a burst of retries must not look like an outage to the user.
  if (response.status === 429) throw new IamError('RATE_LIMITED', 429)
  // A 404 here means the deployment does not expose the expected API; treat it as
  // unavailability rather than as a bad credential so operators see a 503, not a 401.
  if (!response.ok) throw new IamError('UNAVAILABLE', response.status)
  return payload
}

/**
 * A short, log-safe reason for an upstream rejection: the HTTP status plus the
 * upstream's machine code when it looks like an identifier. Free-text messages
 * are deliberately dropped — they can echo caller input and are not needed for
 * diagnosis. This never reaches a client response.
 */
function reasonOf(status: number, payload: unknown): string {
  const codes: string[] = []
  const take = (value: unknown): void => {
    if (typeof value === 'string' && /^[A-Za-z0-9_.-]{1,40}$/.test(value)) codes.push(value)
  }
  if (payload !== null && typeof payload === 'object') {
    const record = payload as Record<string, unknown>
    take(record['error'])
    take(record['code'])
    const inner = record['error']
    if (inner !== null && typeof inner === 'object') take((inner as Record<string, unknown>)['code'])
  }
  return [`http-${status}`, ...codes].join(':')
}

/**
 * Password grant. IAM returns only a token: identity comes from the profile
 * call, because the login response carries no OIDC subject.
 */
export async function iamLogin(config: IamConfig, email: string, password: string): Promise<IamGrant> {
  const payload = await call(config, '/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
  const data = envelope(payload) as Record<string, unknown> | undefined
  // Field names only (never values) so an unexpected success shape is diagnosable from logs.
  const keys = data && typeof data === 'object' ? Object.keys(data).join(',') : String(typeof data)
  if (!data || typeof data !== 'object') throw new IamError('UNAVAILABLE', 200, `empty-data:${keys}`)
  const accessToken = data['access_token']
  if (typeof accessToken !== 'string' || accessToken.length === 0) throw new IamError('UNAVAILABLE', 200, `no-access-token:${keys}`)
  const expiresIn = typeof data['expires_in'] === 'number' && Number.isFinite(data['expires_in']) ? data['expires_in'] : undefined
  return { accessToken, ...(expiresIn === undefined ? {} : { expiresIn }) }
}

/**
 * Resolve a token to its owner.
 *
 * HTTP-level rejections still throw: a forged or expired bearer must never be
 * turned into an account. A profile that authenticates but carries no usable
 * OIDC binding returns without `identity` and with `identityProblem`, so the
 * caller can keep the legacy account key instead of refusing the login.
 */
export async function iamProfile(config: IamConfig, accessToken: string): Promise<IamUser> {
  const data = envelope(await call(config, PROFILE_PATH, {
    method: 'GET', headers: { Authorization: `Bearer ${accessToken}` },
  }))
  if (data === null || typeof data !== 'object') throw new IamError('UNAVAILABLE', 200, 'missing-profile')
  const record = data as Record<string, unknown>
  const rawId = record['id']
  let identity
  let identityProblem
  try {
    identity = toIdentity(record, config.expectedIssuer)
  } catch (error) {
    // Only identity-shape problems are downgraded; IamError with UNAVAILABLE
    // still means the deployment is misconfigured and must surface as a failure.
    if (!(error instanceof IamError) || error.code !== 'AUTH_INVALID') throw error
    identityProblem = error.detail ?? error.code
  }
  return {
    ...(typeof rawId === 'number' && Number.isInteger(rawId) && rawId > 0 ? { id: rawId } : {}),
    email: typeof record['email'] === 'string' ? record['email'] : '',
    username: typeof record['username'] === 'string' ? record['username'] : '',
    ...(identity === undefined ? { identityProblem } : { identity }),
  }
}
