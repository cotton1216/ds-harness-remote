/**
 * `/app/callback`：账号授权完成后浏览器回跳的落地点。
 *
 * 两条登录流程共用这一个地址，靠 `sessionStorage` 里的待校验参数区分：
 * 有「如意账号」的 pending 就走 AI-Server 换票，否则走 IAM OIDC。两者互斥写入，
 * 发起登录时会清掉另一套，所以这里不会取错谜题。
 *
 * 除校验 `state`、换票、进设备页之外，还要处理授权页拒绝（`error=access_denied`），
 * 给用户一个能回到登录页的出口，而不是停在空白页。
 */
import { Alert, Button, Result, Spin, Typography } from 'antd'
import { useEffect, useRef, useState } from 'react'
import { exchangeAiserverCode, exchangeOidcCode, type Account } from './api'
import { takeAiserverPending } from './aiserver'
import { takePending } from './oidc'
import { navigate } from './main'

const { Text } = Typography

/**
 * 回调参数可能在 query，也可能在 fragment。
 *
 * 自定义 scheme（`ruyiai://auth2/callback`）只能走 `#code=…`，AI-Server 的授权页
 * 对深链就是这么回传的；浏览器回跳是否也这样取决于授权页实现。两种都读，
 * 免得出现「明明跳回来了却提示缺授权码」。
 */
function readCallbackParams(): URLSearchParams {
  const search = new URLSearchParams(window.location.search)
  if (search.get('code') !== null || search.get('error') !== null) return search
  return new URLSearchParams(window.location.hash.replace(/^#/, ''))
}

export function OidcCallback({ onAuthSuccess }: { onAuthSuccess: (account: Account) => void }) {
  const [error, setError] = useState('')
  const started = useRef(false)

  useEffect(() => {
    // React 严格模式下 effect 会跑两次；换票的 code 是一次性的，必须只跑一次。
    if (started.current) return
    started.current = true
    const params = readCallbackParams()
    const denied = params.get('error')
    if (denied !== null) {
      setError(denied === 'access_denied' ? '你取消了账号登录。' : '账号登录未能完成，请重试。')
      return
    }
    const code = params.get('code')
    if (!code) { setError('回调缺少授权码，请重新登录。'); return }

    // 先看是不是如意账号登录发起的：这套的 pending 独立存放，存在就优先用。
    const aserver = takeAiserverPending()
    if (aserver !== undefined) {
      // state 不匹配说明这个回调不是本次登录发起的，直接拒绝而不是尝试换票。
      if (params.get('state') !== aserver.state) { setError('登录状态校验失败，请重新登录。'); return }
      void (async () => {
        try {
          const account = await exchangeAiserverCode({
            code,
            codeVerifier: aserver.verifier,
            // 复用授权请求里那个值：AI-Server 按逐字比对，重新拼一次就可能差一个斜杠。
            redirectUri: aserver.redirectUri,
          })
          onAuthSuccess(account)
        } catch (err) {
          setError(err instanceof Error ? err.message : '如意账号登录失败，请重试。')
        }
      })()
      return
    }

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
      <Text className="auth-callback-hint">正在完成登录…</Text>
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
