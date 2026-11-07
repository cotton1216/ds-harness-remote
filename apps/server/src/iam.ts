/**
 * IAM (AI-Server) identity adapter.
 *
 * The relay never trusts a bearer token on its own: the only way to learn who a
 * caller is, is to ask IAM. Two entry points are used, both observed against the
 * live deployment:
 *
 *   POST {base}/api/v1/auth/login   { email, password } -> { access_token, user }
 *   GET  {base}/api/v1/user/profile  Authorization: Bearer -> { id, username, email }
 *
 * The second call is what makes token verification possible at all: IAM signs
 * with HS256 and publishes no JWKS, so a local signature check is impossible,
 * but any service can ask `/user/profile` to resolve a token to a user id.
 */

export interface IamConfig {
  /** Deployment base URL including its reverse-proxy prefix, without trailing slash. */
  baseUrl: string
  timeoutMs: number
}

export interface IamUser {
  id: number
  email: string
  username: string
}

export interface IamGrant {
  user: IamUser
  accessToken: string
  expiresIn?: number
}

export class IamError extends Error {
  constructor(readonly code: 'AUTH_INVALID' | 'UNAVAILABLE') { super(code) }
}

const DEFAULT_TIMEOUT_MS = 10_000

/** Accepts only an absolute http(s) base URL; rejects credentials, query, hash and percent-escaped path separators. */
export function parseIamConfig(value: string | undefined, timeoutRaw?: string): IamConfig | undefined {
  if (value === undefined || value.trim() === '') return undefined
  let url: URL
  try { url = new URL(value.trim()) } catch { throw new Error('Invalid DSH_IAM_BASE.') }
  if (url.username || url.password || url.search || url.hash || /%2f|%5c/i.test(url.pathname)) {
    throw new Error('Invalid DSH_IAM_BASE.')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Invalid DSH_IAM_BASE.')
  const timeoutMs = timeoutRaw === undefined || timeoutRaw.trim() === '' ? DEFAULT_TIMEOUT_MS : Number(timeoutRaw)
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new Error('Invalid DSH_IAM_TIMEOUT_MS.')
  return { baseUrl: `${url.origin}${url.pathname.replace(/\/+$/, '')}`, timeoutMs }
}

const envelope = (raw: unknown): unknown => {
  if (raw === null || typeof raw !== 'object') return raw
  const record = raw as Record<string, unknown>
  return 'data' in record ? record['data'] : raw
}

function toUser(value: unknown): IamUser {
  if (value === null || typeof value !== 'object') throw new IamError('UNAVAILABLE')
  const record = value as Record<string, unknown>
  const id = record['id']
  if (typeof id !== 'number' || !Number.isInteger(id) || id <= 0) throw new IamError('UNAVAILABLE')
  return {
    id,
    email: typeof record['email'] === 'string' ? record['email'] : '',
    username: typeof record['username'] === 'string' ? record['username'] : '',
  }
}

async function call(config: IamConfig, path: string, init: RequestInit): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${config.baseUrl}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
      signal: AbortSignal.timeout(config.timeoutMs),
    })
  } catch {
    throw new IamError('UNAVAILABLE')
  }
  let payload: unknown
  try { payload = await response.json() } catch { payload = undefined }
  if (response.status === 401 || response.status === 403) throw new IamError('AUTH_INVALID')
  // A 404 here means the deployment does not expose the expected API; treat it as
  // unavailability rather than as a bad credential so operators see a 503, not a 401.
  if (!response.ok) throw new IamError('UNAVAILABLE')
  return payload
}

/** Password grant. Used when the caller typed an IAM e-mail and password. */
export async function iamLogin(config: IamConfig, email: string, password: string): Promise<IamGrant> {
  const data = envelope(await call(config, '/api/v1/auth/login', {
    method: 'POST', body: JSON.stringify({ email, password }),
  })) as Record<string, unknown> | undefined
  if (!data || typeof data !== 'object') throw new IamError('UNAVAILABLE')
  const accessToken = data['access_token']
  if (typeof accessToken !== 'string' || accessToken.length === 0) throw new IamError('UNAVAILABLE')
  const expiresIn = typeof data['expires_in'] === 'number' && Number.isFinite(data['expires_in']) ? data['expires_in'] : undefined
  return { user: toUser(data['user']), accessToken, ...(expiresIn === undefined ? {} : { expiresIn }) }
}

/** Resolve an existing token to its owner. This is the verification path. */
export async function iamProfile(config: IamConfig, accessToken: string): Promise<IamUser> {
  const data = envelope(await call(config, '/api/v1/user/profile', {
    method: 'GET', headers: { Authorization: `Bearer ${accessToken}` },
  }))
  return toUser(data)
}
