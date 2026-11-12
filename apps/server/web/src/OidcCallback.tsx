/**
 * `/app/callback`：IAM 授权完成后浏览器回跳的落地点。
 *
 * 这里只做三件事：校验 `state` 与本地待校验参数一致、把 code 交给中继换票、
 * 成功后进入设备页。授权页放弃登录（`error=access_denied`）时也要给用户
 * 一个能回到登录页的出口，而不是停在空白页。
 */
import { Alert, Button, Result, Spin, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import { exchangeOidcCode, type Account } from './api'
import { takePending } from './oidc'
import { navigate } from './main'

const { Text } = Typography

export function OidcCallback({ onAuthSuccess }: { onAuthSuccess: (account: Account) => void }) {
  const [error, setError] = useState('')
  const started = useRef(false)

  useEffect(() => {
    // React 严格模式下 effect 会跑两次；换票的 code 是一次性的，必须只跑一次。
    if (started.current) return
    started.current = true
    const params = new URLSearchParams(window.location.search)
    const denied = params.get('error')
    if (denied !== null) {
      setError(denied === 'access_denied' ? '你取消了统一身份登录。' : '统一身份登录未能完成，请重试。')
      return
    }
    const code = params.get('code')
    if (!code) { setError('回调缺少授权码，请重新登录。'); return }
    const pending = takePending()
    if (pending === undefined) { setError('登录会话已过期，请重新发起登录。'); return }
    // state 不匹配说明这个回调不是本次登录发起的，直接拒绝而不是尝试换票。
    if (params.get('state') !== pending.state) { setError('登录状态校验失败，请重新登录。'); return }
    void (async () => {
      try {
        const account = await exchangeOidcCode({
          code,
          codeVerifier: pending.verifier,
          // 复用授权请求里那个值：IAM 与中继都按逐字比对，重新拼一次就可能差一个斜杠。
          redirectUri: pending.redirectUri,
          nonce: pending.nonce,
        })
        onAuthSuccess(account)
      } catch (err) {
        setError(err instanceof Error ? err.message : '统一身份登录失败，请重试。')
      }
    })()
  }, [onAuthSuccess])

  if (error === '') {
    return <main className="auth-page"><section className="auth-content auth-callback">
      <Spin size="large" />
      <Text className="auth-callback-hint">正在完成统一身份登录…</Text>
    </section></main>
  }
  return <main className="auth-page"><section className="auth-content auth-callback">
    <Result
      status="warning"
      title="无法完成登录"
      subTitle={<Alert type="error" showIcon message={error} />}
      extra={<Button type="primary" onClick={() => navigate('/app/login')}>返回登录</Button>}
    />
  </section></main>
}
