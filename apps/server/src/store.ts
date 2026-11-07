import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { accountDeviceDescriptorSchema, type AccountDeviceDescriptor } from '@dsh-remote/protocol'
import { z } from 'zod'

export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 400) { super(code) }
}
export const hash = (value: string): string => createHash('sha256').update(value).digest('hex')
export const secret = (): string => randomBytes(32).toString('base64url')
export const equal = (left: string, right: string): boolean => timingSafeEqual(Buffer.from(hash(left)), Buffer.from(hash(right)))
export type AccountConfig = { account: string; password: string; disabled?: boolean }
export interface StoreOptions {
  /**
   * Enables externally authenticated accounts (IAM). Those records carry no
   * password verifier, are created on first successful identity check and are
   * never disabled by the local-account configuration pass.
   */
  iam?: boolean
  /**
   * Allows an existing device to change owner, but only when it re-presents the
   * same identity public key. Off by default: turning it on trades a strict
   * "devices never change accounts" rule for a smooth account migration
   * (e.g. local account -> IAM) without touching server state by hand.
   */
  rebind?: boolean
}

export function validateAccounts(accounts: readonly AccountConfig[], options?: { allowEmpty?: boolean }): AccountConfig[] {
  if (!Array.isArray(accounts) || (accounts.length === 0 && options?.allowEmpty !== true)) throw new Error('At least one DSH_SERVER account is required.')
  const seen = new Set<string>()
  const normalized = accounts.map((entry) => {
    if (!entry || typeof entry.account !== 'string' || !entry.account.trim() || entry.account.length > 254 ||
      typeof entry.password !== 'string' || entry.password.length < 12 || entry.password.length > 1024 ||
      (entry.disabled !== undefined && typeof entry.disabled !== 'boolean')) {
      throw new Error('Invalid DSH_SERVER account configuration (account and password of at least 12 characters required).')
    }
    const account = entry.account.trim()
    if (seen.has(account)) throw new Error('Duplicate DSH_SERVER account configuration.')
    seen.add(account)
    return { account, password: entry.password, disabled: entry.disabled ?? false }
  })
  if (normalized.length > 0 && normalized.every(entry => entry.disabled)) throw new Error('At least one enabled DSH_SERVER account is required.')
  return normalized
}

export function parseAccountsEnvironment(raw: string | undefined, legacyAccount?: string, legacyPassword?: string): AccountConfig[] {
  if (raw !== undefined) {
    if (legacyAccount !== undefined || legacyPassword !== undefined) throw new Error('DSH_SERVER_ACCOUNTS_JSON cannot be combined with DSH_SERVER_ACCOUNT or DSH_SERVER_PASSWORD.')
    let parsed: unknown
    try { parsed = JSON.parse(raw) } catch { throw new Error('Invalid DSH_SERVER_ACCOUNTS_JSON.') }
    const schema = z.array(z.object({ account: z.string(), password: z.string(), disabled: z.boolean().optional() }).strict())
    const result = schema.safeParse(parsed)
    if (!result.success) throw new Error('Invalid DSH_SERVER_ACCOUNTS_JSON.')
    return validateAccounts(result.data)
  }
  return validateAccounts([{ account: legacyAccount ?? '', password: legacyPassword ?? '' }])
}

const tokenSchema = z.object({
  kind: z.enum(['access', 'refresh']), deviceId: z.string(), expires: z.number(), used: z.boolean(),
  recovery: z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/), accessExpires: z.number().int().positive() }).optional(),
})
const savedDeviceSchema = z.object({ descriptor: accountDeviceDescriptorSchema, revoked: z.boolean(), lastSeenAt: z.number() })
const oldStateSchema = z.object({ version: z.literal(1), account: z.string(), salt: z.string(), verifier: z.string(), devices: z.record(z.string(), savedDeviceSchema), tokens: z.record(z.string(), tokenSchema) })
const accountSchema = z.object({
  account: z.string(), salt: z.string(), verifier: z.string(), disabled: z.boolean(),
  // Defaulted so a v2 file written before IAM support still parses unchanged.
  kind: z.enum(['local', 'iam']).default('local'), displayName: z.string().optional(),
})
const ownedDeviceSchema = savedDeviceSchema.extend({ accountId: z.string().length(64) })
const ownedTokenSchema = tokenSchema.extend({ accountId: z.string().length(64) })
const stateSchema = z.object({ version: z.literal(2), accounts: z.record(z.string(), accountSchema), devices: z.record(z.string(), ownedDeviceSchema), tokens: z.record(z.string(), ownedTokenSchema) })
export type SavedDevice = z.infer<typeof ownedDeviceSchema>
type SavedToken = z.infer<typeof ownedTokenSchema>
type State = z.infer<typeof stateSchema>

// Domain-separated HMACs keyed by the presented bearer, NOT its stored digest.
// The nonce alone cannot recover credentials from a copy of state.json.
function successor(token: string, nonce: string, deviceId: string) {
  const derive = (kind: string) => createHmac('sha256', token)
    .update(JSON.stringify(['ds-harness-remote/refresh/v1', deviceId, nonce, kind])).digest('base64url')
  return { accessToken: derive('access'), refreshToken: derive('refresh') }
}

/** Single-process store. Only token digests and public identities reach disk. */
export class Store {
  private state: State
  private devicesByAccount = new Map<string, Set<string>>()
  private tokensByDevice = new Map<string, Set<string>>()
  private sortedDevices = new Map<string, { all: string[]; host: string[]; client: string[] }>()
  private readonly dummySalt = secret()
  private readonly legacyAccount: string | undefined
  private readonly iam: boolean
  private readonly rebind: boolean
  readonly account: string
  onInvalidate: (id: string) => void = () => {}
  constructor(file: string, account: string, password: string, options?: StoreOptions)
  constructor(file: string, accounts: readonly AccountConfig[], options?: StoreOptions)
  constructor(private readonly file: string, accountOrAccounts: string | readonly AccountConfig[], passwordOrOptions?: string | StoreOptions, explicitOptions?: StoreOptions) {
    const legacyInput = typeof accountOrAccounts === 'string'
    // 三参构造沿用 password: string；数组构造的第三个参数是 options。
    const options: StoreOptions = legacyInput
      ? (explicitOptions ?? {})
      : ((passwordOrOptions as StoreOptions | undefined) ?? {})
    this.iam = options.iam === true
    this.rebind = options.rebind === true
    const accounts = validateAccounts(legacyInput
      ? [{ account: accountOrAccounts, password: typeof passwordOrOptions === 'string' ? passwordOrOptions : '' }]
      : accountOrAccounts, { allowEmpty: this.iam })
    this.legacyAccount = legacyInput ? accounts[0]!.account : undefined
    this.account = accounts.length === 1 ? accounts[0]!.account : ''
    const original = existsSync(file) ? readFileSync(file) : undefined
    const existing = original ? JSON.parse(original.toString('utf8')) as { version?: unknown } : undefined
    if (existing?.version === 1) {
      const old = oldStateSchema.parse(existing)
      const accountId = hash(old.account)
      this.state = {
        version: 2,
        accounts: { [accountId]: { account: old.account, salt: old.salt, verifier: old.verifier, disabled: true, kind: 'local' as const } },
        devices: Object.fromEntries(Object.entries(old.devices).map(([id, device]) => [id, { ...device, accountId }])),
        tokens: Object.fromEntries(Object.entries(old.tokens).map(([id, record]) => [id, { ...record, accountId }])),
      }
    } else if (original !== undefined) this.state = stateSchema.parse(existing)
    else this.state = { version: 2, accounts: {}, devices: {}, tokens: {} }
    // 配置变更前验证全部旧记录，不能用令牌清理掩盖损坏的归属。
    for (const [id, entry] of Object.entries(this.state.accounts)) {
      if (id !== hash(entry.account)) throw new Error('Invalid stored account identity.')
    }
    for (const [id, device] of Object.entries(this.state.devices)) {
      if (id !== device.descriptor.deviceId || !Object.hasOwn(this.state.accounts, device.accountId)) throw new Error('Invalid stored device ownership.')
    }
    for (const record of Object.values(this.state.tokens)) {
      if (!Object.hasOwn(this.state.devices, record.deviceId) || this.state.devices[record.deviceId]!.accountId !== record.accountId) throw new Error('Invalid stored token ownership.')
    }
    const previousEnabled = new Set(Object.entries(this.state.accounts).filter(([, entry]) => !entry.disabled).map(([id]) => id))
    // IAM 账号不在本地配置里出现，其启用状态只由「是否开启 IAM」决定，不能被这轮配置重置关掉。
    for (const entry of Object.values(this.state.accounts)) entry.disabled = entry.kind === 'iam' ? !this.iam : true
    for (const entry of accounts) {
      const id = hash(entry.account)
      const previous = this.state.accounts[id]
      const salt = previous?.salt ?? secret()
      const verifier = scryptSync(entry.password, salt, 32).toString('hex')
      if (previous && (!equal(previous.verifier, verifier) || (!previousEnabled.has(id) && existing?.version !== 1))) {
        for (const [key, record] of Object.entries(this.state.tokens)) {
          if (record.accountId === id) delete this.state.tokens[key]
        }
      }
      this.state.accounts[id] = { account: entry.account, salt, verifier, disabled: entry.disabled ?? false, kind: 'local' }
    }
    for (const [key, record] of Object.entries(this.state.tokens)) {
      if (this.state.accounts[record.accountId]!.disabled) delete this.state.tokens[key]
    }
    if (existing?.version === 1) {
      const backup = `${file}.v1.bak`
      if (existsSync(backup)) {
        if (!lstatSync(backup).isFile() || !readFileSync(backup).equals(original!)) throw new Error('Existing v1 backup differs from source.')
        chmodSync(backup, 0o600)
      } else {
        const fd = openSync(backup, 'wx', 0o600)
        try {
          try { writeFileSync(fd, original!); fsyncSync(fd) } finally { closeSync(fd) }
        } catch (error) {
          // 只清理本次创建但未完整写入的备份；既有备份永不覆盖。
          try { unlinkSync(backup) } catch { /* 保留原错误。 */ }
          throw error
        }
      }
    }
    this.save(this.state)
    this.reindexDevices()
    this.reindexTokens()
  }
  private save(state: State): void {
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 })
    const tmp = `${this.file}.tmp`
    const fd = openSync(tmp, 'wx', 0o600)
    try {
      try { writeFileSync(fd, JSON.stringify(state)); fsyncSync(fd) } finally { closeSync(fd) }
      renameSync(tmp, this.file)
    } catch (error) {
      // 只清理由本次独占创建的临时文件，不触碰已有文件或目录。
      try { unlinkSync(tmp) } catch { /* 保留原错误。 */ }
      throw error
    }
  }
  private commit(next: State): void {
    this.save(next)
    this.state = next
  }
  private reindexDevices(): void {
    this.devicesByAccount.clear()
    this.sortedDevices.clear()
    for (const [id, device] of Object.entries(this.state.devices)) {
      let owned = this.devicesByAccount.get(device.accountId)
      if (!owned) { owned = new Set(); this.devicesByAccount.set(device.accountId, owned) }
      owned.add(id)
      if (device.revoked) continue
      let sorted = this.sortedDevices.get(device.accountId)
      if (!sorted) { sorted = { all: [], host: [], client: [] }; this.sortedDevices.set(device.accountId, sorted) }
      sorted.all.push(id)
      sorted[device.descriptor.role].push(id)
    }
    for (const sorted of this.sortedDevices.values()) { sorted.all.sort(); sorted.host.sort(); sorted.client.sort() }
  }
  private reindexAccountDevices(accountId: string): void {
    const sorted: { all: string[]; host: string[]; client: string[] } = { all: [], host: [], client: [] }
    for (const id of this.devicesByAccount.get(accountId) ?? []) {
      const device = this.state.devices[id]!
      if (device.revoked) continue
      sorted.all.push(id)
      sorted[device.descriptor.role].push(id)
    }
    sorted.all.sort(); sorted.host.sort(); sorted.client.sort()
    this.sortedDevices.set(accountId, sorted)
  }
  getAccount(account: string): string {
    const id = hash(account)
    const record = Object.hasOwn(this.state.accounts, id) ? this.state.accounts[id] : undefined
    if (!record || record.disabled || record.account !== account) throw new ApiError('AUTH_INVALID', 401)
    return id
  }
  accountName(accountId: string): string {
    const record = Object.hasOwn(this.state.accounts, accountId) ? this.state.accounts[accountId] : undefined
    if (!record || record.disabled) throw new ApiError('AUTH_INVALID', 401)
    return record.account
  }
  /** Human-readable label for an account id (falls back to the login string). */
  displayNameOf(accountId: string): string {
    const record = Object.hasOwn(this.state.accounts, accountId) ? this.state.accounts[accountId] : undefined
    return record?.displayName ?? record?.account ?? ''
  }
  /**
   * Provision (or look up) an externally authenticated account.
   *
   * The caller has already proven the identity against IAM, so this is the only
   * path that can materialise an account at runtime. The record carries a random
   * verifier, which makes password login impossible for it by construction.
   */
  ensureIamAccount(account: string, displayName?: string): string {
    if (!this.iam) throw new ApiError('AUTH_INVALID', 401)
    if (!/^iam:[1-9][0-9]{0,18}$/.test(account)) throw new ApiError('AUTH_INVALID', 401)
    return this.upsertIamAccount(account, displayName)
  }

  /**
   * OIDC 登录建立的账号。`sub` 是不透明字符串（如 `usr_01J...`），不能用上面的
   * 数字规则；身份已由 id_token 验签证明，所以这里不再要求 IAM 口令通道已配置。
   */
  ensureOidcAccount(subject: string, displayName?: string): string {
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(subject)) throw new ApiError('AUTH_INVALID', 401)
    return this.upsertIamAccount(`iam:${subject}`, displayName)
  }

  private upsertIamAccount(account: string, displayName?: string): string {
    const id = hash(account)
    const existing = Object.hasOwn(this.state.accounts, id) ? this.state.accounts[id] : undefined
    if (existing) {
      if (existing.disabled || existing.kind !== 'iam') throw new ApiError('AUTH_INVALID', 401)
      if (displayName !== undefined && displayName !== existing.displayName) {
        // 只更新展示名，不改动 salt/verifier，避免影响分页游标的签名密钥。
        this.commit({ ...this.state, accounts: { ...this.state.accounts, [id]: { ...existing, displayName } } })
      }
      return id
    }
    const record = {
      account, salt: secret(), verifier: secret(), disabled: false, kind: 'iam' as const,
      ...(displayName === undefined ? {} : { displayName }),
    }
    this.commit({ ...this.state, accounts: { ...this.state.accounts, [id]: record } })
    return id
  }
  verifyLogin(account: string, password: string): string {
    const id = hash(account)
    const stored = this.state.accounts[id]
    const candidate = scryptSync(password, stored?.salt ?? this.dummySalt, 32).toString('hex')
    const valid = equal(stored?.verifier ?? '0'.repeat(64), candidate)
    // IAM 账号没有口令，必须显式拒绝，不能依赖随机 verifier 的不可能性。
    if (!valid || !stored || stored.disabled || stored.account !== account || stored.kind === 'iam') throw new ApiError('AUTH_INVALID', 401)
    return id
  }
  get(id: string): SavedDevice {
    const d = Object.hasOwn(this.state.devices, id) ? this.state.devices[id] : undefined
    if (!d) throw new ApiError('DEVICE_NOT_FOUND', 404)
    if (d.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    if (this.state.accounts[d.accountId]?.disabled) throw new ApiError('AUTH_INVALID', 401)
    return d
  }
  owns(id: string, accountId: string): boolean {
    const d = Object.hasOwn(this.state.devices, id) ? this.state.devices[id] : undefined
    return !!d && !d.revoked && d.accountId === accountId && Object.hasOwn(this.state.accounts, accountId) && !this.state.accounts[accountId]!.disabled
  }
  getOwned(id: string, accountId: string): SavedDevice {
    if (!this.owns(id, accountId)) throw new ApiError('DEVICE_NOT_FOUND', 404)
    return this.get(id)
  }
  private selectedAccount(account?: string): string {
    if (account !== undefined) return this.getAccount(account)
    if (this.legacyAccount === undefined) throw new ApiError('ACCOUNT_AUTH_REQUIRED', 401)
    return this.getAccount(this.legacyAccount)
  }
  list(account?: string): SavedDevice[] {
    const id = this.selectedAccount(account)
    return [...(this.devicesByAccount.get(id) ?? [])].map(deviceId => this.state.devices[deviceId]!).filter(d => !d.revoked)
  }
  page(account: string, role?: 'host' | 'client', cursor?: string, limit = 50): { items: SavedDevice[]; nextCursor: string | null } {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100 || (cursor !== undefined && cursor.length > 512)) throw new ApiError('INVALID_MESSAGE')
    const owner = this.getAccount(account), scope = role ?? 'all'
    const sign = (payload: string) => createHmac('sha256', this.state.accounts[owner]!.salt)
      .update(JSON.stringify(['dsh/page/v1', owner, scope, payload])).digest('base64url')
    let last = ''
    if (cursor !== undefined) {
      const parts = cursor.split('.')
      if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]!) || !equal(sign(parts[0]!), parts[1]!)) throw new ApiError('INVALID_MESSAGE')
      last = Buffer.from(parts[0]!, 'base64url').toString('utf8')
      if (!last || last.length > 128) throw new ApiError('INVALID_MESSAGE')
    }
    const ids = this.sortedDevices.get(owner)?.[scope] ?? []
    let low = 0, high = ids.length
    while (low < high) {
      const mid = (low + high) >>> 1
      if (ids[mid]! <= last) low = mid + 1
      else high = mid
    }
    const selected = ids.slice(low, low + limit)
    const payload = selected.length ? Buffer.from(selected.at(-1)!).toString('base64url') : ''
    return {
      items: selected.map(id => this.state.devices[id]!),
      nextCursor: low + limit < ids.length ? `${payload}.${sign(payload)}` : null,
    }
  }
  register(descriptor: AccountDeviceDescriptor, account?: string): ReturnType<Store['issue']> {
    const accountId = this.selectedAccount(account)
    const old = Object.hasOwn(this.state.devices, descriptor.deviceId) ? this.state.devices[descriptor.deviceId] : undefined
    const previousOwner = old?.accountId
    if (old && old.accountId !== accountId) {
      // 同一物理设备换账号只认「设备公钥一致」，否则一律按不存在处理，不暴露归属差异。
      if (!this.rebind || old.descriptor.identityKey !== descriptor.identityKey) throw new ApiError('DEVICE_NOT_FOUND', 404)
    }
    if (old?.revoked) throw new ApiError('DEVICE_REVOKED', 403)
    if (old && (old.descriptor.identityKey !== descriptor.identityKey || old.descriptor.role !== descriptor.role)) throw new ApiError('PEER_IDENTITY_MISMATCH', 409)
    if ((!old || previousOwner !== accountId) && (this.devicesByAccount.get(accountId)?.size ?? 0) >= 256) throw new ApiError('RATE_LIMITED', 429)
    const devices = { ...this.state.devices, [descriptor.deviceId]: { descriptor: structuredClone(descriptor), accountId, revoked: false, lastSeenAt: old?.lastSeenAt ?? 0 } }
    const tokens = { ...this.state.tokens }
    for (const key of this.tokensByDevice.get(descriptor.deviceId) ?? []) delete tokens[key]
    const result = this.issue(descriptor.deviceId, undefined, undefined, { ...this.state, devices, tokens })
    let owned = this.devicesByAccount.get(accountId)
    if (!owned) { owned = new Set(); this.devicesByAccount.set(accountId, owned) }
    owned.add(descriptor.deviceId)
    this.reindexAccountDevices(accountId)
    // 换账号时必须把旧账号的索引也重建，否则旧账号仍能在自己的列表里看到这台设备。
    if (previousOwner !== undefined && previousOwner !== accountId) {
      this.devicesByAccount.get(previousOwner)?.delete(descriptor.deviceId)
      this.reindexAccountDevices(previousOwner)
    }
    this.onInvalidate(descriptor.deviceId)
    return result
  }
  private issue(deviceId: string, refreshTokenExpiresAt = Date.now() + 30 * 86400_000, previous?: { token: string; record: SavedToken }, base: State = this.state) {
    const tokens = { ...base.tokens }
    for (const [key, value] of Object.entries(tokens)) if (value.expires <= Date.now()) delete tokens[key]
    if (Object.keys(tokens).length + 2 > 16384) throw new ApiError('RATE_LIMITED', 429)
    const accessTokenExpiresAt = Date.now() + 60 * 60_000
    const nonce = secret()
    const { accessToken, refreshToken } = previous
      ? successor(previous.token, nonce, deviceId)
      : { accessToken: secret(), refreshToken: secret() }
    if (previous) tokens[hash(previous.token)] = {
      ...previous.record, used: true, recovery: { nonce, accessExpires: accessTokenExpiresAt },
    }
    const accountId = base.devices[deviceId]!.accountId
    tokens[hash(accessToken)] = { kind: 'access', deviceId, accountId, expires: accessTokenExpiresAt, used: false }
    tokens[hash(refreshToken)] = { kind: 'refresh', deviceId, accountId, expires: refreshTokenExpiresAt, used: false }
    // 设备注册、旧令牌消费和后继令牌作为一次事务持久化。
    this.commit({ ...base, tokens })
    this.reindexTokens()
    return { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt }
  }
  private reindexTokens(): void {
    this.tokensByDevice.clear()
    for (const [key, record] of Object.entries(this.state.tokens)) {
      let set = this.tokensByDevice.get(record.deviceId)
      if (!set) { set = new Set(); this.tokensByDevice.set(record.deviceId, set) }
      set.add(key)
    }
  }
  authenticate(token: string): SavedDevice {
    const digest = hash(token)
    const record = Object.hasOwn(this.state.tokens, digest) ? this.state.tokens[digest] : undefined
    if (!record || record.kind !== 'access') throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    const device = this.get(record.deviceId)
    if (record.accountId !== device.accountId) throw new ApiError('AUTH_INVALID', 401)
    return device
  }
  refresh(deviceId: string, token: string) {
    const digest = hash(token)
    const record = Object.hasOwn(this.state.tokens, digest) ? this.state.tokens[digest] : undefined
    if (!record || record.kind !== 'refresh' || record.deviceId !== deviceId) throw new ApiError('AUTH_INVALID', 401)
    const device = this.get(deviceId)
    if (record.accountId !== device.accountId) throw new ApiError('AUTH_INVALID', 401)
    if (record.expires <= Date.now()) throw new ApiError('TOKEN_EXPIRED', 401)
    if (!record.used) return this.issue(deviceId, record.expires, { token, record })
    if (!record.recovery) throw new ApiError('AUTH_INVALID', 401)
    const pair = successor(token, record.recovery.nonce, deviceId)
    const next = this.state.tokens[hash(pair.refreshToken)]
    if (!next || next.kind !== 'refresh' || next.accountId !== device.accountId || next.deviceId !== deviceId || next.expires !== record.expires) {
      throw new ApiError('INTERNAL_ERROR', 503)
    }
    if (next.used) throw new ApiError('AUTH_INVALID', 401)
    const access = this.state.tokens[hash(pair.accessToken)]
    if (access ? access.kind !== 'access' || access.accountId !== device.accountId || access.deviceId !== deviceId || access.expires !== record.recovery.accessExpires
      : record.recovery.accessExpires > Date.now()) throw new ApiError('INTERNAL_ERROR', 503)
    return { ...pair, accessTokenExpiresAt: record.recovery.accessExpires, refreshTokenExpiresAt: next.expires }
  }
  invalidate(deviceId: string): void {
    const tokens = { ...this.state.tokens }
    for (const key of this.tokensByDevice.get(deviceId) ?? []) delete tokens[key]
    this.commit({ ...this.state, tokens })
    this.tokensByDevice.delete(deviceId)
    this.onInvalidate(deviceId)
  }
  revoke(id: string): void {
    const device = this.get(id), tokens = { ...this.state.tokens }
    for (const key of this.tokensByDevice.get(id) ?? []) delete tokens[key]
    this.commit({ ...this.state, tokens, devices: { ...this.state.devices, [id]: { ...device, revoked: true } } })
    this.tokensByDevice.delete(id)
    this.reindexAccountDevices(device.accountId)
    this.onInvalidate(id)
  }
  rename(id: string, name: string): void {
    const device = this.get(id)
    this.commit({ ...this.state, devices: { ...this.state.devices, [id]: { ...device, descriptor: { ...device.descriptor, name } } } })
  }
  touch(id: string, clientVersion?: string, harnessVersion?: string): void {
    const device = this.get(id), descriptor = { ...device.descriptor }
    if (clientVersion) descriptor.clientVersion = clientVersion.slice(0, 64)
    if (descriptor.role === 'host' && harnessVersion) descriptor.harnessVersion = harnessVersion.slice(0, 64)
    this.commit({ ...this.state, devices: { ...this.state.devices, [id]: { ...device, descriptor, lastSeenAt: Date.now() } } })
  }
}
