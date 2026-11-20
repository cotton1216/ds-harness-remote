// 如意 AI 登录页：主路径是「如意账号登录」（AI-Server 桌面授权），企业统一身份（IAM OIDC）
// 保留为后备入口，本地账号仅作 break-glass 兜底。三套可以任意组合，页面按实际可用的渲染。
import { Alert, Button, Card, Divider, Form, Input, Typography } from 'antd'
import { SafetyCertificateOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import { api, authConfig, type Account } from './api'
import { buildAiserverAuthorizeUrl, clearLoginPending, type AiserverLoginConfig } from './aiserver'
import { buildAuthorizeUrl, type OidcLoginConfig } from './oidc'
import { ThemeToggle } from './ThemeToggle'
import { SiteFooter } from './SiteFooter'

const BRAND = '如意 AI'

export function LoginPanel({ onAuthSuccess, initialError }: { onAuthSuccess: (account: Account) => void; initialError?: string }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(initialError ?? '')
  const [oidc, setOidc] = useState<OidcLoginConfig | null>()
  const [aserver, setAserver] = useState<AiserverLoginConfig | null>()
  const [localAccount, setLocalAccount] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [form] = Form.useForm<{ email: string; password: string }>()

  // 先问中继支持哪些登录方式：没配 OIDC 就不显示统一登录按钮，没配本地账号就不显示密码框。
  useEffect(() => {
    let alive = true
    authConfig()
      .then(config => {
        if (!alive) return
        setOidc(config.oidc); setAserver(config.aiserver); setLocalAccount(config.password)
        // 没有任何单点登录时，密码就是唯一入口，别再让人多点一次链接。
        setShowPassword(config.oidc === null && config.aiserver === null)
      })
      // 拿不到配置就不能猜登录方式：给一句能自救的提示，而不是渲染一个空卡片。
      .catch(() => { if (alive) { setOidc(null); setAserver(null); setError('无法获取登录配置，请刷新页面重试。') } })
    return () => { alive = false }
  }, [])

  async function submit(values: { email: string; password: string }) {
    setLoading(true); setError('')
    try {
      const result = await api<Account>('/auth/login', { email: values.email.trim(), password: values.password })
      form.resetFields(['password']); onAuthSuccess(result)
    } catch (err) { setError(err instanceof Error ? err.message : '登录失败，请重试。') }
    finally { setLoading(false) }
  }

  async function ssoAiserver() {
    if (aserver === null || aserver === undefined) return
    setLoading(true); setError('')
    try {
      // 两套流程互斥：开始这一套就把另一套的谜题清掉，回调时才不会取错。
      clearLoginPending()
      window.location.assign(await buildAiserverAuthorizeUrl(aserver))
    } catch { setError('无法发起如意账号登录，请刷新页面重试。'); setLoading(false) }
  }

  async function ssoOidc() {
    if (oidc === null || oidc === undefined) return
    setLoading(true); setError('')
    try {
      clearLoginPending()
      window.location.assign(await buildAuthorizeUrl(oidc))
    } catch { setError('无法发起统一身份登录，请刷新页面重试。'); setLoading(false) }
  }

  const aserverAvailable = aserver !== undefined && aserver !== null
  const oidcAvailable = oidc !== undefined && oidc !== null
  const ssoAvailable = aserverAvailable || oidcAvailable
  const passwordForm = showPassword && localAccount
  // 副标题要说实话：没有单点登录时不该还写「使用企业统一身份账号继续」。
  const subtitle = aserver === undefined || oidc === undefined ? ''
    : aserverAvailable ? '使用如意账号继续'
    : oidcAvailable ? '使用企业统一身份账号继续'
    : '使用本地管理员账号登录'

  return <><main className="auth-page">
    <div className="auth-language-menu"><ThemeToggle className="auth-theme-toggle" /></div>
    <section className="auth-content">
      <div className="auth-logo-stack"><a className="auth-home-link" href="/" aria-label="返回首页"><img className="auth-brand-icon" src="/brand-ruyi.png" alt="" width="48" height="48" /><Typography.Title>{BRAND}</Typography.Title></a></div>
      <Card className="auth-panel">
        <div className="auth-intro"><Typography.Title level={3} className="auth-title">登录</Typography.Title>{subtitle !== '' && <Typography.Paragraph className="auth-subtitle" type="secondary">{subtitle}</Typography.Paragraph>}</div>
        {error && <Alert className="selfhost-auth-error" type="error" showIcon message={error} />}
        {aserver === undefined || oidc === undefined
          ? <div className="auth-sso-loading" role="status">正在检查登录方式…</div>
          : ssoAvailable && <div className="auth-sso">
              <Button
                className="auth-sso-button" size="large" block type="primary" loading={loading}
                icon={<SafetyCertificateOutlined />}
                onClick={() => void (aserverAvailable ? ssoAiserver() : ssoOidc())}
              >使用 {BRAND} 账号登录</Button>
              <Typography.Paragraph className="auth-sso-hint" type="secondary">
                {aserverAvailable
                  ? '将跳转到如意账号授权页面，登录后自动返回。'
                  : '将跳转到企业统一身份认证页面，登录后自动返回。'}
              </Typography.Paragraph>
              {/* 两套都可用时，把企业统一身份降级成后备入口：主路径统一走如意账号，
                  但 IAM 侧出问题时还能从这条进来，不用等我们改配置。 */}
              {aserverAvailable && oidcAvailable && <Button type="link" className="auth-break-glass" disabled={loading} onClick={() => void ssoOidc()}>使用企业统一身份账号登录</Button>}
            </div>}
        {passwordForm && <>
          {ssoAvailable && <Divider plain className="auth-divider">或</Divider>}
          <Form form={form} layout="vertical" onFinish={submit} requiredMark={false} className="auth-form">
            <Form.Item name="email" label="账号" rules={[{ required: true, whitespace: true, message: '请输入账号' }, { max: 254, message: '账号不能超过 254 个字符' }]}><Input size="large" placeholder="请输入账号" autoComplete="username" /></Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }, { max: 1024, message: '密码不能超过 1024 个字符' }]}><Input.Password size="large" placeholder="请输入密码" autoComplete="current-password" /></Form.Item>
            <Form.Item className="auth-submit-item"><Button loading={loading} block type="primary" size="large" htmlType="submit">登录</Button></Form.Item>
          </Form>
        </>}
        {/* break-glass 入口：统一身份不可用时管理员仍能进去处理，平时不占版面。 */}
        {localAccount && !showPassword && <Button type="link" className="auth-break-glass" onClick={() => setShowPassword(true)}>使用本地管理员账号</Button>}
      </Card>
    </section>
  </main><SiteFooter /></>
}
