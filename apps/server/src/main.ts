import { resolve } from 'node:path'
import {
  createRemoteServer,
  parseHelloTimeout,
  parseHeartbeatInterval,
  parseHeartbeatDisconnect,
  parseForceTerminateGrace,
  parseMaxFramesPerSec,
} from './server.js'
import { parseLogLevel } from './logger.js'
import { parseIceConfig } from './ice.js'
import { parseAccountsEnvironment } from './store.js'
import { identityBaseFromEnv, parseIamConfig } from './iam.js'
import { aiserverConfigFromEnv } from './aiserver-desktop.js'
import { oidcConfigFromEnv } from './iam-oidc.js'

const port = Number(process.env.DSH_SERVER_PORT ?? '8080')
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid DSH_SERVER_PORT.')

const heartbeatIntervalMs = parseHeartbeatInterval(process.env.DSH_SERVER_HEARTBEAT_INTERVAL_MS)
const heartbeatDisconnectMs = parseHeartbeatDisconnect(process.env.DSH_SERVER_HEARTBEAT_DISCONNECT_MS, heartbeatIntervalMs)
const helloTimeoutMs = parseHelloTimeout(process.env.DSH_SERVER_HELLO_TIMEOUT_MS)
const forceTerminateGraceMs = parseForceTerminateGrace(process.env.DSH_SERVER_FORCE_TERMINATE_GRACE_MS)
const maxFramesPerSec = parseMaxFramesPerSec(process.env.DSH_SERVER_MAX_FRAMES_PER_SEC)
const logLevel = parseLogLevel(process.env.DSH_SERVER_LOG_LEVEL)
// AI-Server 的 profile 不声明可信 issuer：优先 DSH_IAM_ISSUER，否则沿用 OIDC 的 issuer。
const oidcConfigured = oidcConfigFromEnv(process.env) !== undefined
const identityBase = identityBaseFromEnv(process.env)
if (identityBase.legacy) {
  console.warn('[dsh] DSH_IAM_BASE is deprecated and has always held the AI-Server base, not the IAM issuer. Rename it to DSH_IDENTITY_BASE.')
}
const iam = parseIamConfig(
  identityBase.value,
  process.env.DSH_IAM_TIMEOUT_MS,
  process.env.DSH_IAM_ISSUER ?? process.env.DSH_IAM_OIDC_ISSUER,
)
// 如意账号登录同样是外部身份入口：配了这一套就不该再要求本地口令账号。
// 少了这一项，只配 DSH_AISERVER_* 的部署会先撞上「Invalid DSH_SERVER account configuration」，
// 真正该报的「DSH_AISERVER_BASE requires DSH_IDENTITY_BASE …」被遮在后面，排查时完全误导。
const aiserverConfigured = aiserverConfigFromEnv(process.env) !== undefined
// 外部身份部署不需要本地口令账号；显式配置了本地账号时仍然并存，作为身份服务不可用时的退路。
const localAccounts = (iam || oidcConfigured || aiserverConfigured) && process.env.DSH_SERVER_ACCOUNTS_JSON === undefined && process.env.DSH_SERVER_ACCOUNT === undefined
  ? []
  : parseAccountsEnvironment(process.env.DSH_SERVER_ACCOUNTS_JSON, process.env.DSH_SERVER_ACCOUNT, process.env.DSH_SERVER_PASSWORD)

const app = createRemoteServer({
  accounts: localAccounts,
  iam,
  allowDeviceRebind: process.env.DSH_ALLOW_DEVICE_REBIND === '1',
  publicUrl: process.env.DSH_SERVER_PUBLIC_URL ?? `http://localhost:${port}`,
  dataFile: resolve(process.env.DSH_SERVER_DATA_FILE ?? 'data/state.json'),
  trustedProxyIps: (process.env.DSH_SERVER_TRUSTED_PROXY_IPS ?? '').split(',').map(value => value.trim()).filter(Boolean),
  helloTimeoutMs,
  heartbeatIntervalMs,
  heartbeatDisconnectMs,
  forceTerminateGraceMs,
  maxFramesPerSec,
  logLevel,
  ice: parseIceConfig(process.env),
})
app.server.listen(port, process.env.DSH_SERVER_HOST ?? '127.0.0.1', () => console.info(`Remote Server listening on port ${port}`))
app.server.on('error', () => { console.error('Remote Server could not listen. Check address and port.'); process.exitCode = 1; app.gateway.close() })
let stopping = false
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (stopping) return
  stopping = true
  void app.close().then(() => { process.exitCode = 0 }, () => { process.exitCode = 1 })
})
