import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID } from 'node:crypto'
import { isIP } from 'node:net'
import { z } from 'zod'
import { accountDeviceDescriptorSchema, deviceRegistrationRequestSchema, deviceRefreshRequestSchema, PROTOCOL_VERSION } from '@dsh-remote/protocol'
import { ApiError, Store, hash, secret, validateAccounts, type AccountConfig } from './store.js'
import { IamError, iamLogin, iamProfile, type IamConfig, type IamIdentity, type IamUser } from './iam.js'
import { OidcError, oidcAuthorizeEndpoint, oidcConfigFromEnv, oidcIdentityFromCode, type OidcConfig } from './iam-oidc.js'
import {
  AiserverError,
  aiserverAuthorizeEndpoint,
  aiserverConfigFromEnv,
  aiserverLoginEnabled,
  exchangeDesktopCode,
  type AiserverDesktopConfig,
} from './aiserver-desktop.js'
import { Gateway } from './gateway.js'
import { buildIceServers, parseIceConfig, type IceConfig } from './ice.js'
import { Logger, type LogLevel } from './logger.js'
import {
  FORCE_TERMINATE_GRACE_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  MAX_FRAMES_PER_SEC_RANGE,
  normalizeForceTerminateGraceMs,
  normalizeGatewayOptions,
  normalizeHeartbeatDisconnectMs,
  normalizeHeartbeatIntervalMs,
  normalizeHelloTimeoutMs,
  normalizeMaxFramesPerSec,
} from './config.js'

export interface Config {
  account?: string
  password?: string
  accounts?: AccountConfig[]
  dataFile: string
  publicUrl: string
  trustedProxyIps?: readonly string[]
  helloTimeoutMs?: number
  heartbeatIntervalMs?: number
  heartbeatDisconnectMs?: number
  forceTerminateGraceMs?: number
  maxFramesPerSec?: number
  logLevel?: LogLevel
  ice?: IceConfig
  /** When set, logins are delegated to this IAM deployment instead of local accounts. */
  iam?: IamConfig
  /**
   * 标准 OIDC 换票配置（`/api/v1/auth/iam/oidc`）。缺省时从
   * `DSH_IAM_OIDC_*` 环境变量读取；都没有就视为未启用，路由返回 404。
   */
  oidc?: OidcConfig
  /**
   * 如意账号登录（AI-Server 桌面授权，`/api/v1/auth/aiserver/exchange`）。缺省时从
   * `DSH_AISERVER_*` 环境变量读取；都没有就视为未启用，路由返回 404、登录页不显示入口。
   *
   * 与 `oidc` 是两条平行入口，产物不同：OIDC 换 id_token（中继自己就是 IAM 客户端），
   * 如意账号换 AI-Server 的 access_token（公开客户端 PKCE，无需 client_secret）。
   */
  aiserver?: AiserverDesktopConfig
  /**
   * 浏览器侧 OIDC 回跳地址（例如 `https://relay.example.com/app/callback`）。
   * 配置后 Web 登录页显示「企业统一登录」，并把它加入 redirect_uri 白名单；
   * 留空则表示该部署只支持手机 App 的 `dshgo://` 回调。
   */
  webRedirectUri?: string
  /**
   * 覆盖换票默认允许的 redirect_uri 集合（默认只有手机端的 `dshgo://auth/callback`）。
   * 仅供测试与自建客户端使用；`DSH_WEB_REDIRECT_URI` 会额外加入，不受此处影响。
   */
  allowedRedirectUris?: readonly string[]
  /**
   * Allow a device to move to another account when it re-presents the same identity
   * key. Off by default: only enable it while migrating accounts deliberately.
   */
  allowDeviceRebind?: boolean
}

/**
 * Timing configuration is normalized in one place (`config.ts`) so the CLI and
 * programmatic callers share the same bounds and fallbacks. These wrappers keep
 * the env-var parsing API used by `main.ts` and the tests, and never echo the
 * offending input in their warnings.
 */
export function parseHelloTimeout(val: string | undefined): number {
  return normalizeHelloTimeoutMs(val)
}

export function parseHeartbeatInterval(val: string | undefined): number {
  return normalizeHeartbeatIntervalMs(val)
}

export function parseHeartbeatDisconnect(val: string | undefined, heartbeatIntervalMs: number = HEARTBEAT_INTERVAL_MS_RANGE.fallback): number {
  return normalizeHeartbeatDisconnectMs(val, heartbeatIntervalMs)
}

export function parseForceTerminateGrace(val: string | undefined): number {
  return normalizeForceTerminateGraceMs(val)
}

export function parseMaxFramesPerSec(val: string | undefined): number {
  return normalizeMaxFramesPerSec(val)
}

export {
  normalizeGatewayOptions,
  normalizeHelloTimeoutMs,
  normalizeHeartbeatIntervalMs,
  normalizeHeartbeatDisconnectMs,
  normalizeForceTerminateGraceMs,
  normalizeMaxFramesPerSec,
  HELLO_TIMEOUT_MS_RANGE,
  HEARTBEAT_INTERVAL_MS_RANGE,
  HEARTBEAT_DISCONNECT_MS_MAX,
  FORCE_TERMINATE_GRACE_MS_RANGE,
  MAX_FRAMES_PER_SEC_RANGE,
}
export type { GatewayTimingOptions, NormalizedGatewayOptions } from './config.js'

const loginSchema = z.object({ email: z.string().min(1).max(254), password: z.string().min(1).max(1024) }).strict()
const publicDir = fileURLToPath(new URL('../dist/public/', import.meta.url))
function readAssets(): Map<string, Buffer> {
  if (!existsSync(publicDir)) return new Map()
  const assets = new Map<string, Buffer>()
  for (const entry of readdirSync(publicDir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue
    const file = join(entry.parentPath, entry.name)
    const path = file.slice(publicDir.length).replaceAll('\\', '/')
    assets.set(path, readFileSync(file))
  }
  return assets
}
async function body(req: IncomingMessage): Promise<unknown> {
  if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) throw new ApiError('INVALID_MESSAGE', 415)
  let length = 0
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    length += chunk.length
    if (length > 16384) throw new ApiError('FRAME_TOO_LARGE', 413)
    chunks.push(chunk)
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw new ApiError('INVALID_MESSAGE') }
}
/**
 * Normalize one bare IPv4/IPv6 literal to a single canonical form. IPv4-mapped
 * IPv6 addresses (e.g. ::ffff:127.0.0.1) collapse to plain IPv4, so a peer
 * observed through a dual-stack socket and a config entry compare equal.
 * Returns null for anything that is not a single IP literal: hostnames, ports,
 * CIDR ranges, comma-separated lists, bracketed hosts and zone identifiers.
 */
export function normalizeIp(value: string): string | null {
  const family = isIP(value)
  if (family === 4) return value.toLowerCase()
  if (family !== 6) return null
  let canonical: string
  try {
    canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1)
  } catch { return null }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical)
  if (!mapped) return canonical
  const high = Number.parseInt(mapped[1]!, 16), low = Number.parseInt(mapped[2]!, 16)
  return `${high >>> 8}.${high & 0xff}.${low >>> 8}.${low & 0xff}`
}
/** Validate and normalize the trusted proxy list at startup. Empty means disabled. */
export function normalizeTrustedProxyIps(values: readonly string[] = []): ReadonlySet<string> {
  const result = new Set<string>()
  for (const raw of values) {
    const value = raw.trim()
    const normalized = value === '' ? null : normalizeIp(value)
    if (normalized === null) throw new Error(`Invalid DSH_SERVER_TRUSTED_PROXY_IPS entry "${raw}": expected a bare IPv4/IPv6 address (no port, CIDR or hostname).`)
    result.add(normalized)
  }
  return result
}
/**
 * 浏览器 OIDC 回调地址必须是绝对 HTTP(S) URL，且不带 query / hash / 凭据：
 * IAM 的 redirect_uri 白名单是逐字比对，任何附加片段都会让授权请求直接失败。
 * 空值表示「不启用浏览器登录」，不是错误。
 */
export function normalizeWebRedirectUri(raw: string | undefined): string | undefined {
  const value = raw?.trim()
  if (!value) return undefined
  let parsed: URL
  try { parsed = new URL(value) } catch { throw new Error('Invalid DSH_WEB_REDIRECT_URI.') }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.search || parsed.hash || parsed.username || parsed.password) {
    throw new Error('Invalid DSH_WEB_REDIRECT_URI: expected an absolute HTTP(S) URL without query, hash or credentials.')
  }
  return value
}
function readSingleForwardedFor(req: IncomingMessage): string {
  let value: string | undefined
  let count = 0
  const raw = req.rawHeaders
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if (raw[i]!.toLowerCase() !== 'x-forwarded-for') continue
    count++
    value = raw[i + 1]
  }
  if (count !== 1) throw new ApiError('INVALID_MESSAGE')
  return value!
}
/**
 * Resolve the address used for rate limiting. X-Forwarded-For is honored only
 * when the socket peer is a configured trusted proxy; that peer must send one
 * header holding exactly one IP literal, otherwise the request is rejected.
 */
export function clientAddress(req: IncomingMessage, trustedProxyIps: ReadonlySet<string>): string {
  const peer = normalizeIp(req.socket.remoteAddress ?? '')
  if (peer === null) throw new ApiError('INVALID_MESSAGE')
  if (!trustedProxyIps.has(peer)) return peer
  const forwarded = normalizeIp(readSingleForwardedFor(req))
  if (forwarded === null) throw new ApiError('INVALID_MESSAGE')
  return forwarded
}
export function createRemoteServer(config: Config) {
  if (config.accounts !== undefined && (config.account !== undefined || config.password !== undefined)) throw new Error('DSH_SERVER_ACCOUNTS_JSON cannot be combined with DSH_SERVER_ACCOUNT or DSH_SERVER_PASSWORD.')
  // OIDC 三个环境变量齐全才启用；缺省时 /auth/iam/oidc 返回 404。
  const oidcConfig = config.oidc ?? oidcConfigFromEnv(process.env)
  // 如意账号登录三件套齐全才启用；与上面完全独立，可以只开一套，也可以两套并存。
  const aiserverConfig = config.aiserver ?? aiserverConfigFromEnv(process.env)
  /**
   * The AI-Server profile does not tell us which issuer is trustworthy, so one
   * must be configured server-side. `DSH_IAM_ISSUER` overrides it; otherwise the
   * OIDC client's issuer (already verified against id_tokens) is reused. Without
   * either, IAM logins cannot be authenticated, so startup fails loudly instead
   * of silently accepting a profile-supplied issuer.
   */
  const trustedIssuer = config.iam?.expectedIssuer ?? oidcConfig?.issuer
  if (config.iam !== undefined && trustedIssuer === undefined) {
    throw new Error('DSH_IAM_ISSUER (or DSH_IAM_OIDC_ISSUER) is required when DSH_IDENTITY_BASE (legacy DSH_IAM_BASE) is set.')
  }
  const iam = config.iam === undefined ? undefined : { ...config.iam, expectedIssuer: trustedIssuer! }
  /**
   * 如意账号登录换到的是 AI-Server 的 access_token：那只能证明「谁在 AI-Server 上」，
   * 还要读一次 profile 才能拿到可信的 (issuer, subject)。没有 `DSH_IDENTITY_BASE`
   * 就换不出身份，路由会 404 —— 启动时直接说清楚，别等用户点了按钮才失败。
   */
  if (aiserverConfig !== undefined && iam === undefined) {
    throw new Error('DSH_AISERVER_BASE requires DSH_IDENTITY_BASE (legacy DSH_IAM_BASE) and DSH_IAM_ISSUER to resolve the account identity.')
  }
  /**
   * 浏览器回调地址与 OIDC 配置是一体的：没有 OIDC 就没有换票端点，配了回调也
   * 登录不了。启动时直接报错，避免线上「按钮点了没反应」这种隐性故障。
   */
  const webRedirectUri = normalizeWebRedirectUri(config.webRedirectUri ?? process.env['DSH_WEB_REDIRECT_URI'])
  if (webRedirectUri !== undefined && oidcConfig === undefined) {
    throw new Error('DSH_WEB_REDIRECT_URI requires DSH_IAM_OIDC_ISSUER, DSH_IAM_OIDC_CLIENT_ID and DSH_IAM_OIDC_CLIENT_SECRET.')
  }
  /**
   * 允许换票的 redirect_uri。手机 App 的自定义 scheme 是固定值，浏览器地址由
   * DSH_WEB_REDIRECT_URI 声明。换票时逐字比对，授权码不能被换到未声明的地址。
   * `allowedRedirectUris` 只给测试和自建客户端留口子，生产靠上面两个来源。
   */
  const allowedRedirectUris = new Set<string>(config.allowedRedirectUris ?? ['dshgo://auth/callback'])
  if (webRedirectUri !== undefined) allowedRedirectUris.add(webRedirectUri)
  const accounts = validateAccounts(
    config.accounts ?? (iam !== undefined || oidcConfig !== undefined ? [] : [{ account: config.account ?? '', password: config.password ?? '' }]),
    { allowEmpty: iam !== undefined || oidcConfig !== undefined },
  )
  const url = new URL(config.publicUrl)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('DSH_SERVER_PUBLIC_URL must be an HTTP(S) origin.')
  const trustedProxyIps = normalizeTrustedProxyIps(config.trustedProxyIps)
  const ice = config.ice ?? parseIceConfig({})
  // `iam: true` means "external identities are enabled", covering OIDC-only
  // deployments so their accounts are not disabled by the local-account pass.
  const store = new Store(config.dataFile, accounts, { iam: iam !== undefined || oidcConfig !== undefined, rebind: config.allowDeviceRebind === true })
  const assets = readAssets()
  const sessions = new Map<string, { expires: number; account: string; accountId: string; displayName: string }>()
  /**
   * Single-use device authorization codes. Kept in memory on purpose: a code that
   * does not survive a restart is safer than one accidentally persisted, and the
   * whole point is a short hand-off between an already-authenticated device and a
   * new one (the desktop can mint a code for a phone, or vice versa).
   */
  const registrationCodes = new Map<string, { accountId: string; expires: number }>()
  const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  /**
   * Pairing-code lifetime. Longer codes are more forgiving for someone walking
   * to another room, but a code is a bearer credential until redeemed, so keep a
   * hard ceiling and clamp garbage instead of failing startup.
   */
  const codeTtlMs = ((): number => {
    const raw = Number(process.env['DSH_REGISTRATION_CODE_TTL_MS'])
    if (!Number.isSafeInteger(raw) || raw <= 0) return 10 * 60_000
    return Math.min(Math.max(raw, 60_000), 60 * 60_000)
  })()
  const limits = new Map<string, { count: number; until: number }>()
  function rate(key: string, max: number) {
    for (const [k, v] of limits) if (v.until < Date.now()) limits.delete(k)
    let entry = limits.get(key)
    if (!entry) { if (limits.size >= 4096) throw new ApiError('RATE_LIMITED', 429); entry = { count: 0, until: Date.now() + 60_000 }; limits.set(key, entry) }
    if (++entry.count > max) throw new ApiError('RATE_LIMITED', 429)
  }
  function token(req: IncomingMessage): string {
    const authorization = req.headers.authorization
    if (authorization) return authorization.startsWith('Bearer ') ? authorization.slice(7) : ''
    return /(?:^|;\s*)dsh_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie ?? '')?.[1] ?? ''
  }
  function accountAuth(req: IncomingMessage) {
    const key = hash(token(req))
    const session = sessions.get(key)
    if (!session || session.expires <= Date.now()) { sessions.delete(key); throw new ApiError('ACCOUNT_AUTH_REQUIRED', 401) }
    try { store.getAccount(session.account) } catch { sessions.delete(key); throw new ApiError('ACCOUNT_AUTH_REQUIRED', 401) }
    return session
  }
  type Identity = { account: string; accountId: string; displayName: string }
  function openSession(res: ServerResponse, identity: Identity) {
    for (const [key, session] of sessions) if (session.expires <= Date.now()) sessions.delete(key)
    if (sessions.size >= 256) throw new ApiError('RATE_LIMITED', 429)
    const value = secret(), expiresAt = Date.now() + 8 * 3600_000
    sessions.set(hash(value), { expires: expiresAt, ...identity })
    res.setHeader('Set-Cookie', cookie(value, 8 * 3600))
    return { ...profile(identity.account, identity.displayName), token: value, expiresAt }
  }
  /**
   * Map an AI-Server identity failure onto the relay's own error vocabulary,
   * never echoing AI-Server's body. The code is `IDENTITY_UNAVAILABLE`, not
   * `IAM_UNAVAILABLE`: the dependency that failed is AI-Server, and calling it
   * IAM sent operators looking at the wrong service.
   */
  function identityFailure(error: unknown): never {
    if (error instanceof IamError) {
      // 只记录错误类别与上游状态码，绝不记录凭据或上游的响应正文。
      logger.warn('identity_auth_failed', { code: error.code, status: error.status ?? null, detail: error.detail ?? null })
      if (error.code === 'AUTH_INVALID') throw new ApiError('AUTH_INVALID', 401)
      if (error.code === 'RATE_LIMITED') throw new ApiError('RATE_LIMITED', 429)
    } else {
      logger.warn('identity_auth_failed', { code: 'UNEXPECTED' })
    }
    throw new ApiError('IDENTITY_UNAVAILABLE', 503)
  }
  /**
   * Single owner mapping for every external identity. The key deliberately
   * includes the issuer, so equal subjects from different issuers stay separate.
   * It is built here and nowhere else: profile and id_token paths must agree.
   */
  function externalIdentity(identity: IamIdentity, user: { username?: string; email?: string } = {}): Identity {
    const account = `iam:${hash(JSON.stringify([identity.issuer, identity.subject]))}`
    const displayName = user.username?.trim() || user.email?.trim() || account
    return { account, accountId: store.ensureExternalAccount(account, displayName), displayName }
  }
  function iamIdentity(user: IamUser): Identity {
    if (user.identity !== undefined) return externalIdentity(user.identity, user)
    // Authenticated, but no usable OIDC binding: keep the legacy key so the
    // login still works. Two devices only unify once the binding exists.
    if (user.id !== undefined) {
      logger.warn('iam_profile_without_binding', { reason: user.identityProblem ?? 'unknown' })
      const account = `iam:${user.id}`
      const displayName = user.username?.trim() || user.email?.trim() || account
      return { account, accountId: store.ensureLegacyIamAccount(account, displayName), displayName }
    }
    throw new IamError('AUTH_INVALID', undefined, user.identityProblem ?? 'missing-identity')
  }
  async function iamFromToken(config: IamConfig, accessToken: string): Promise<Identity> {
    try { return iamIdentity(await iamProfile(config, accessToken)) } catch (error) { return identityFailure(error) }
  }
  /**
   * Password login. AI-Server wins when configured; a locally configured account
   * is kept as a break-glass path so an identity outage does not lock every
   * operator out. Only when neither accepts the credentials do we surface the
   * identity error shape — and we keep the original IamError, not the local 401,
   * so 401-vs-503 stays meaningful.
   */
  async function passwordIdentity(config: IamConfig | undefined, email: string, password: string): Promise<Identity> {
    const local = (): Identity => ({ account: email, accountId: store.verifyLogin(email, password), displayName: email })
    if (!config) return local()
    let failure: unknown
    try {
      // Login returns only a token; the trusted identity comes from the profile.
      const grant = await iamLogin(config, email, password)
      return iamIdentity(await iamProfile(config, grant.accessToken))
    } catch (error) { failure = error }
    try { return local() } catch { return identityFailure(failure) }
  }
  /** Mint a `XXXX-XXXX` hand-off code bound to one account. */
  function issueRegistrationCode(accountId: string): { code: string; expiresAt: number } {
    for (const [key, entry] of registrationCodes) if (entry.expires <= Date.now()) registrationCodes.delete(key)
    if (registrationCodes.size >= 256) throw new ApiError('RATE_LIMITED', 429)
    const random = (): string => randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()
    // Rewrite hex digits that are not in the unambiguous alphabet so the protocol
    // regex (`[A-Z0-9]{4}-[A-Z0-9]{4}`) always matches.
    const normalize = (raw: string): string => [...raw].map(ch => CODE_ALPHABET[ch.charCodeAt(0) % CODE_ALPHABET.length]!).join('')
    let code = ''
    do {
      const body = normalize(random())
      code = `${body.slice(0, 4)}-${body.slice(4, 8)}`
    } while (registrationCodes.has(code))
    const expiresAt = Date.now() + codeTtlMs
    registrationCodes.set(code, { accountId, expires: expiresAt })
    return { code, expiresAt }
  }
  /** Consume a code exactly once; the owner comes from the code, never from the request. */
  function redeemRegistrationCode(raw: string): string {
    const code = raw.trim().toUpperCase()
    const entry = registrationCodes.get(code)
    // 过期、已用、不存在三者对外表现一致，避免用码探测有效性。
    if (!entry || entry.expires <= Date.now()) throw new ApiError('AUTH_INVALID', 401)
    registrationCodes.delete(code)
    return entry.accountId
  }
  /** Who may mint a pairing code: an account session or an already-authorized device. */
  function codeIssuerAccount(req: IncomingMessage): string {
    const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined
    if (bearer === undefined) throw new ApiError('AUTH_REQUIRED', 401)
    // 设备令牌与会话令牌互不通用，先按设备校验，失败再按会话校验。
    try { return store.authenticate(bearer).accountId } catch { /* 不是设备令牌，下面按账号会话处理 */ }
    try { return accountAuth(req).accountId } catch { /* 两种都不是 */ }
    throw new ApiError('AUTH_REQUIRED', 401)
  }
  function deviceAuth(req: IncomingMessage) {
    if (!req.headers.authorization?.startsWith('Bearer ')) throw new ApiError('AUTH_REQUIRED', 401)
    return store.authenticate(req.headers.authorization.slice(7))  }
  function cookie(value: string, age: number): string { return `dsh_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${url.protocol === 'https:' ? '; Secure' : ''}` }
  const profile = (account: string, displayName = account) => ({ account: displayName, profile: { displayName }, isAdmin: false })
  const server = createServer({ requestTimeout: 15000, headersTimeout: 10000 }, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    void route(req, res).catch(error => {
      if (res.headersSent || res.destroyed) return
      const e = error instanceof ApiError ? error : error instanceof z.ZodError ? new ApiError('INVALID_MESSAGE') : new ApiError('INTERNAL_ERROR', 500)
      if (e.status === 429) res.setHeader('Retry-After', '60')
      json(res, e.status, { error: { code: e.code, message: e.code, requestId: randomUUID(), retryable: e.status === 429 || e.status >= 500 } })
    })
  })
  const logger = new Logger('server', config.logLevel ?? 'info')
  // Normalize at this boundary as well: a programmatic caller may pass NaN,
  // Infinity or a negative value straight through the Config object.
  const timing = normalizeGatewayOptions({
    helloTimeoutMs: config.helloTimeoutMs,
    heartbeatIntervalMs: config.heartbeatIntervalMs,
    heartbeatDisconnectMs: config.heartbeatDisconnectMs,
    forceTerminateGraceMs: config.forceTerminateGraceMs,
  })
  const gateway = new Gateway(server, store, url.origin, {
    ...timing,
    maxFramesPerSec: normalizeMaxFramesPerSec(config.maxFramesPerSec),
    logLevel: config.logLevel,
    logger: logger.child('gateway'),
    turnEnabled: ice.turnUrls.length > 0,
  })
  function descriptor(d: ReturnType<Store['get']>) {
    return { ...d.descriptor, membershipId: `account:${d.accountId.slice(0, 16)}`, online: gateway.peers.has(d.descriptor.deviceId), lastSeenAt: d.lastSeenAt }
  }
  function paginationLimit(requestUrl: URL): number {
    const raw = requestUrl.searchParams.get('limit')
    if (raw === null) return 50
    const limit = Number(raw)
    if (!/^[1-9][0-9]*$/.test(raw) || limit > 100) throw new ApiError('INVALID_MESSAGE')
    return limit
  }
  function paginationCursor(requestUrl: URL): string | undefined {
    const raw = requestUrl.searchParams.get('cursor')
    if (raw === null) return undefined
    if (!raw || raw.length > 512) throw new ApiError('INVALID_MESSAGE')
    return raw
  }
  async function route(req: IncomingMessage, res: ServerResponse) {
    const requestUrl = new URL(req.url ?? '/', url)
    const path = requestUrl.pathname
    const method = req.method
    // CSRF 防护只作用于 API。浏览器从 IAM 域回跳 `/app/callback` 是跨站顶级导航，
    // Sec-Fetch-Site 必然是 `cross-site`；把它一并拦掉会让单点登录在回跳那一刻 403。
    // 静态入口没有副作用，不需要 CSRF 保护。
    const isApi = path.startsWith('/api/')
    if (isApi && req.headers.origin && req.headers.origin !== url.origin) throw new ApiError('AUTH_INVALID', 403)
    if (isApi && req.headers['sec-fetch-site'] === 'cross-site') throw new ApiError('AUTH_INVALID', 403)
    const staticAsset = path.startsWith('/assets/') || ['/icon.png', '/brand-ruyi.png', '/landing-atmosphere.webp'].includes(path)
    // SPA fallback: any GET that is not API / WebSocket / health-check returns index.html.
    // Without this, refreshing a client route such as /app/remote hits the unknown-method branch and yields METHOD_NOT_FOUND.
    const spaRoute = method === 'GET' && !staticAsset && !path.startsWith('/api/') && !path.startsWith('/ws/') && !['/health', '/healthz', '/ready'].includes(path)
    if (method === 'GET' && (spaRoute || staticAsset)) {
      const name = staticAsset ? path.slice(1) : 'index.html'
      const asset = assets.get(name)
      if (!asset) throw new ApiError('METHOD_NOT_FOUND', 404)
      const contentType = name.endsWith('.js') ? 'text/javascript; charset=utf-8' : name.endsWith('.css') ? 'text/css; charset=utf-8' : name.endsWith('.png') ? 'image/png' : name.endsWith('.webp') ? 'image/webp' : name.endsWith('.svg') ? 'image/svg+xml' : 'text/html; charset=utf-8'
      if (!staticAsset) res.setHeader('Cache-Control', 'no-cache')
      res.setHeader('Content-Type', contentType)
      res.end(asset); return
    }
    if (method === 'GET' && (path === '/health' || path === '/healthz' || path === '/ready')) { json(res, 200, { status: 'ok' }); return }
    const client = clientAddress(req, trustedProxyIps)
    rate(`api:${client}`, 240)
    // 登录页先问「这台中继支持哪些登录方式」，再决定渲染统一登录按钮还是只有密码框。
    // 只回传公开参数：client_secret 永远留在进程环境里。
    if (method === 'GET' && path === '/api/v1/auth/config') {
      rate(`config:${client}`, 120)
      // 如意账号登录要求「换票 + 读 profile」两件事都配好，缺一件就当作未启用：
      // 否则按钮能点、换到令牌也建不了账号，只会把用户送进死胡同。
      const aserver = aiserverLoginEnabled(aiserverConfig, iam) ? aiserverConfig : undefined
      json(res, 200, {
        // 只有真的配了本地账号才暴露密码入口，否则给出一个点了必然 401 的表单。
        password: accounts.length > 0,
        oidc: webRedirectUri === undefined ? null : {
          clientId: oidcConfig!.clientId,
          redirectUri: webRedirectUri,
          authorizeEndpoint: await oidcAuthorizeEndpoint(oidcConfig!),
          scope: 'openid profile email',
        },
        /**
         * 如意账号登录：不是标准 OIDC，所以单列一段。`authorizeEndpoint` 是 AI-Server
         * 的授权落地页（GET），页面参数由客户端拼：client_id / redirect_uri / state /
         * code_challenge / code_challenge_method=S256 —— 没有 response_type 与 scope。
         */
        aiserver: aserver === undefined ? null : {
          clientId: aserver.web.clientId,
          redirectUri: aserver.web.redirectUri,
          authorizeEndpoint: aiserverAuthorizeEndpoint(aserver),
          /**
           * App 深链那一条登记，未配置为 null。`client_id` 与自定义 scheme 都是
           * 公开信息（APK 里就能读到），下发它们只是让手机端不必把地址写死。
           */
          app: aserver.app === null ? null : {
            clientId: aserver.app.clientId,
            redirectUri: aserver.app.redirectUri,
            authorizeEndpoint: aiserverAuthorizeEndpoint(aserver),
          },
        },
      }); return
    }
    if (method === 'POST' && path === '/api/v1/auth/login') {
      rate(`login:${client}`, 20)
      const credentials = loginSchema.parse(await body(req))
      const account = credentials.email.trim()
      const identity = await passwordIdentity(iam, account, credentials.password)
      json(res, 200, openSession(res, identity)); return
    }
    // Token exchange for a caller that already holds an IAM grant (the desktop Host).
    if (method === 'POST' && path === '/api/v1/auth/iam') {
      if (!iam) throw new ApiError('METHOD_NOT_FOUND', 404)
      rate(`identity:${client}`, 60)
      const { token: accessToken } = z.object({ token: z.string().min(20).max(8192) }).strict().parse(await body(req))
      json(res, 200, openSession(res, await iamFromToken(iam, accessToken))); return
    }
    // 标准 OIDC 换票：手机只送来一次性 code 与 PKCE verifier，
    // client_secret 只在本进程内存里，绝不进 App。
    if (method === 'POST' && path === '/api/v1/auth/iam/oidc') {
      if (oidcConfig === undefined) throw new ApiError('METHOD_NOT_FOUND', 404)
      rate(`oidc:${client}`, 30)
      const input = z.object({
        code: z.string().min(1).max(4096),
        codeVerifier: z.string().min(43).max(128),
        redirectUri: z.string().url().max(2048),
        nonce: z.string().min(1).max(256).optional(),
      }).strict().parse(await body(req))
      // 只接受声明过的回调地址：授权码不能换到别处去。
      if (!allowedRedirectUris.has(input.redirectUri)) throw new ApiError('INVALID_MESSAGE', 400)
      let identity
      try {
        identity = await oidcIdentityFromCode(oidcConfig, input)
      } catch (error) {
        if (!(error instanceof OidcError)) throw error
        logger.warn('iam_oidc_failed', { code: error.code, status: error.status ?? null, detail: error.detail ?? null })
        if (error.code === 'RATE_LIMITED') throw new ApiError('RATE_LIMITED', 429)
        if (error.code === 'AUTH_INVALID') throw new ApiError('AUTH_INVALID', 401)
        // 这里是唯一真打 IAM 的路径（换的是 IAM 的 id_token），所以保留 IAM 这个名。
        throw new ApiError('IAM_UNAVAILABLE', 503)
      }
      // Same helper and same key as the AI-Server profile path: an id_token and
      // a profile naming the same (issuer, subject) must resolve to one account.
      json(res, 200, openSession(res, externalIdentity({ issuer: identity.issuer, subject: identity.subject }, identity)))
      return
    }
    /**
     * 如意账号登录换票：AI-Server 桌面授权（公开客户端 PKCE，无 client_secret）。
     *
     * 与 `/auth/iam/oidc` 的区别只在「怎么拿到凭证」：那边换 id_token，这边换
     * access_token。拿到之后一律交给同一个 `iamFromToken` 读 profile，因此两条入口
     * 产出的账号主键完全一致，不会出现「换个登录方式就变成另一个人」。
     *
     * access_token 只在本请求里活一次，验完身份即丢弃：不入库、不进 cookie、不打日志。
     */
    if (method === 'POST' && path === '/api/v1/auth/aiserver/exchange') {
      if (aiserverConfig === undefined || iam === undefined) throw new ApiError('METHOD_NOT_FOUND', 404)
      rate(`aserver:${client}`, 30)
      const input = z.object({
        code: z.string().min(1).max(4096),
        codeVerifier: z.string().min(43).max(128),
        redirectUri: z.string().url().max(2048),
      }).strict().parse(await body(req))
      let accessToken: string
      try {
        accessToken = await exchangeDesktopCode(aiserverConfig, input)
      } catch (error) {
        if (!(error instanceof AiserverError)) throw error
        logger.warn('aiserver_exchange_failed', { code: error.code, status: error.status ?? null, detail: error.detail ?? null })
        if (error.code === 'RATE_LIMITED') throw new ApiError('RATE_LIMITED', 429)
        if (error.code === 'AUTH_INVALID') throw new ApiError('AUTH_INVALID', 401)
        // 换票这一跳打的是 AI-Server，不是 IAM：错误码如实说是身份服务。
        throw new ApiError('IDENTITY_UNAVAILABLE', 503)
      }
      json(res, 200, openSession(res, await iamFromToken(iam, accessToken)))
      return
    }
    if (method === 'GET' && path === '/api/v1/auth/me') {
      const session = accountAuth(req); json(res, 200, profile(session.account, session.displayName)); return
    }
    if (method === 'POST' && path === '/api/v1/auth/logout') {
      sessions.delete(hash(token(req))); res.setHeader('Set-Cookie', cookie('', 0)); json(res, 200, { status: 'ok' }); return
    }
    // 设备令牌或账号会话都可以读自己账号的显示名。授权码换来的设备只有设备
    // 令牌，用它渲染账号名，避免界面只剩一个 `code` 占位。
    if (method === 'GET' && path === '/api/v1/account/profile') {
      let accountId: string
      try {
        accountId = deviceAuth(req).accountId
      } catch {
        accountId = accountAuth(req).accountId
      }
      let account = ''
      try { account = store.accountName(accountId) } catch { /* 账号被禁用时只给显示名 */ }
      json(res, 200, { account, displayName: store.displayNameOf(accountId) }); return
    }
    if (method === 'GET' && path === '/api/v1/account/devices') {
      const session = accountAuth(req)
      const { items, nextCursor } = store.page(session.account, undefined, paginationCursor(requestUrl), paginationLimit(requestUrl))
      json(res, 200, { items: items.map(descriptor), nextCursor, serverUrl: url.origin, transport: 'webrtc' }); return
    }
    // 已登录的账号会话、或**已授权的设备**都可以发码。
    // 设备发码是扫码配对的基础：桌面上只有设备令牌（授权码绑定拿不到账号会话），
    // 但这台设备本来就属于该账号，它有权再拉一台设备进来。
    if (method === 'POST' && path === '/api/v1/account/registration-codes') {
      rate(`code:${client}`, 10)
      json(res, 200, issueRegistrationCode(codeIssuerAccount(req))); return
    }
    // 协议既有端点：插件/客户端本来就会调它，只是上游服务端没实现。
    if (method === 'POST' && path === '/api/v1/devices/register-with-code') {
      rate(`redeem:${client}`, 20)
      const request = z.object({
        v: z.literal(PROTOCOL_VERSION), code: z.string().min(1).max(32), device: accountDeviceDescriptorSchema,
      }).strict().parse(await body(req))
      const accountId = redeemRegistrationCode(request.code)
      json(res, 200, store.register(request.device, store.accountName(accountId))); return
    }
    if (method === 'POST' && (path === '/api/v1/devices/register' || path === '/api/v1/devices/register-owned-role')) {
      const source = path.endsWith('register-owned-role') ? deviceAuth(req) : undefined
      const account = source ? store.accountName(source.accountId) : accountAuth(req).account
      const { device } = deviceRegistrationRequestSchema.parse(await body(req))
      if (source && (source.descriptor.deviceId === device.deviceId || source.descriptor.role === device.role)) throw new ApiError('INVALID_MESSAGE', 409)
      json(res, 200, store.register(device, account)); return
    }
    if (method === 'POST' && path === '/api/v1/auth/refresh') {
      const data = deviceRefreshRequestSchema.parse(await body(req))
      json(res, 200, store.refresh(data.deviceId, data.refreshToken)); return
    }
    if (method === 'DELETE' && path === '/api/v1/devices/self') {
      store.revoke(deviceAuth(req).descriptor.deviceId); json(res, 200, { status: 'revoked' }); return
    }
    if (method === 'GET' && path === '/api/v1/me') { json(res, 200, descriptor(deviceAuth(req))); return }
    if (method === 'GET' && path === '/api/v1/turn/credentials') {
      const source = deviceAuth(req)
      const connectionId = requestUrl.searchParams.get('connection_id') ?? ''
      if (!connectionId || connectionId.length > 128) throw new ApiError('INVALID_MESSAGE')
      if (!gateway.authorizeIce(source.descriptor.deviceId, connectionId)) throw new ApiError('CONNECTION_NOT_FOUND', 404)
      json(res, 200, { iceServers: buildIceServers(ice, source.descriptor.deviceId) }); return
    }
    if (method === 'GET' && path === '/api/v1/devices') {
      const source = deviceAuth(req)
      if (source.descriptor.role !== 'client') throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const page = store.page(store.accountName(source.accountId), 'host', paginationCursor(requestUrl), paginationLimit(requestUrl))
      const items = page.items.map(d => {
        const { identityKey: _key, ...item } = descriptor(d)
        return item
      })
      json(res, 200, { items, nextCursor: page.nextCursor }); return
    }
    const renameMatch = /^\/api\/v1\/devices\/([^/]+)\/name$/.exec(path)
    if (method === 'POST' && renameMatch) {
      const session = accountAuth(req)
      store.getOwned(renameMatch[1]!, session.accountId)
      const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(await body(req))
      store.rename(renameMatch[1]!, name)
      json(res, 200, descriptor(store.getOwned(renameMatch[1]!, session.accountId))); return
    }
    const match = /^\/api\/v1\/devices\/([^/]+)(\/presence)?$/.exec(path)
    if (method === 'GET' && match) {
      const source = deviceAuth(req), target = store.getOwned(match[1]!, source.accountId)
      if (source.descriptor.role === target.descriptor.role) throw new ApiError('MEMBERSHIP_REQUIRED', 403)
      const d = descriptor(target)
      json(res, 200, match[2] ? { deviceId: d.deviceId, online: d.online, lastSeenAt: d.lastSeenAt } : d); return
    }
    throw new ApiError('METHOD_NOT_FOUND', 404)
  }
  return { server, store, gateway, logger, close: async () => { gateway.close(); server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) } }
}
function json(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value))
}
