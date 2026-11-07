import { resolve } from 'node:path'
import {
  createRemoteServer,
  parseHelloTimeout,
  parseHeartbeatInterval,
  parseHeartbeatDisconnect,
  parseForceTerminateGrace,
} from './server.js'
import { parseLogLevel } from './logger.js'
import { parseIceConfig } from './ice.js'
import { parseAccountsEnvironment } from './store.js'
import { parseIamConfig } from './iam.js'

const port = Number(process.env.DSH_SERVER_PORT ?? '8080')
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid DSH_SERVER_PORT.')

const heartbeatIntervalMs = parseHeartbeatInterval(process.env.DSH_SERVER_HEARTBEAT_INTERVAL_MS)
const heartbeatDisconnectMs = parseHeartbeatDisconnect(process.env.DSH_SERVER_HEARTBEAT_DISCONNECT_MS, heartbeatIntervalMs)
const helloTimeoutMs = parseHelloTimeout(process.env.DSH_SERVER_HELLO_TIMEOUT_MS)
const forceTerminateGraceMs = parseForceTerminateGrace(process.env.DSH_SERVER_FORCE_TERMINATE_GRACE_MS)
const logLevel = parseLogLevel(process.env.DSH_SERVER_LOG_LEVEL)
const iam = parseIamConfig(process.env.DSH_IAM_BASE, process.env.DSH_IAM_TIMEOUT_MS)
// 纯 IAM 部署不需要本地口令账号；显式配置了本地账号时仍然并存，作为 IAM 不可用时的退路。
const localAccounts = iam && process.env.DSH_SERVER_ACCOUNTS_JSON === undefined && process.env.DSH_SERVER_ACCOUNT === undefined
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
