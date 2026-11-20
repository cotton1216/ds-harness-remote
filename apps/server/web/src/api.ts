import type { AuthConfig } from './oidc'
export interface Account { account: string }
export interface Device {
  deviceId: string; name: string; role: 'host' | 'client'; platform: string;
  clientVersion: string; harnessVersion?: string; online: boolean; lastSeenAt?: number;
}
export interface DeviceList { items: Device[]; serverUrl: string; transport: string }
export class RequestError extends Error {
  constructor(message: string, readonly status: number) { super(message) }
}
export async function api<T>(path: string, body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(`/api/v1${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(10000),
    })
  } catch { throw new RequestError('连接失败，请重试。', 0) }
  const data = await response.json()
  if (!response.ok) {
    // 两个码都保留：`IDENTITY_UNAVAILABLE` 是 AI-Server 侧失败，`IAM_UNAVAILABLE`
    // 只剩真打 IAM 的 OIDC 换票路径还在用，对用户是同一句话。
    const messages: Record<string, string> = { AUTH_INVALID: '账号或密码错误，请重试。', ACCOUNT_AUTH_REQUIRED: '登录已过期，请重新登录。', RATE_LIMITED: '请求频繁，请稍后重试。', IDENTITY_UNAVAILABLE: '统一身份服务暂时不可用，请稍后重试。', IAM_UNAVAILABLE: '统一身份服务暂时不可用，请稍后重试。' }
    throw new RequestError(messages[data.error?.code] ?? '请求失败，请稍后重试。', response.status)
  }
  return data as T
}
/** 登录页先问可用登录方式，再决定渲染统一登录按钮还是只有本地账号。 */
export function authConfig(): Promise<AuthConfig> {
  return api<AuthConfig>('/auth/config')
}
/**
 * 用浏览器拿到的授权码换本服务会话。`codeVerifier` 是与授权请求配套的那个，
 * `client_secret` 不在这里出现——它只存在于中继进程的环境变量中。
 */
export function exchangeOidcCode(input: { code: string; codeVerifier: string; redirectUri: string; nonce: string }): Promise<Account> {
  return api<Account>('/auth/iam/oidc', input)
}
/**
 * 如意账号登录换票：code 来自 AI-Server 授权页，`codeVerifier` 是与授权请求配套的那个。
 * 这里同样没有 `client_secret` —— AI-Server 的桌面授权是公开客户端 PKCE。
 */
export function exchangeAiserverCode(input: { code: string; codeVerifier: string; redirectUri: string }): Promise<Account> {
  return api<Account>('/auth/aiserver/exchange', input)
}
