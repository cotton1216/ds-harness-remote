import { CheckCircleOutlined, LinkOutlined, RightOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { Layout } from 'antd'
import { navigate } from './main'
import { SiteFooter } from './SiteFooter'
import { ThemeToggle } from './ThemeToggle'

const BRAND = '如意 AI'

function internal(event: React.MouseEvent<HTMLAnchorElement>, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault(); navigate(path)
}

export function HomePage() {
  return <div className="site-shell landing-shell">
    <Layout.Header className="topbar marketing-topbar site-topbar"><div className="topbar-inner"><div className="topbar-brand-group"><a className="topbar-brand" href="/" aria-label={`${BRAND} 首页`}><img className="topbar-brand-mark" src="/brand-ruyi.png" alt="" width="40" height="40" /><span className="topbar-brand-word">{BRAND}</span></a></div><div className="topbar-actions"><ThemeToggle /></div></div></Layout.Header>
    <Layout.Content className="home-content"><main className="home-page">
      <section className="landing-hero" aria-labelledby="landing-title"><div className="landing-hero-inner">
        <div className="landing-hero-copy">
          <h1 id="landing-title">一次连接，随时可用。</h1>
          <p className="landing-hero-sub">用手机或另一台电脑安全连接到运行{BRAND}的工作电脑，随时查看进度并继续工作。</p>
          <div className="landing-hero-actions">
            <a className="landing-action landing-action-primary" href="/app/login" onClick={event => internal(event, '/app/login')}>开始使用</a>
            <a className="landing-action landing-action-secondary" href="/app/remote" onClick={event => internal(event, '/app/remote')}>我的设备</a>
          </div>
          <p className="landing-hero-workspace-note">使用企业统一身份账号登录，无需单独申请。</p>
        </div>
        <aside className="landing-plugin" aria-label="接入步骤"><div className="landing-plugin-panel"><section className="landing-plugin-pane is-active">
          <div className="landing-plugin-heading"><div className="landing-plugin-meta"><LinkOutlined /><span className="landing-plugin-status">由 IT 统一部署</span></div><h2>连接你的工作电脑</h2></div>
          <p className="landing-plugin-description">在工作电脑上启用远程插件后，就能用企业账号从手机或其他电脑接入。</p>
          <ol className="landing-plugin-steps">
            <li><CheckCircleOutlined />用企业统一身份账号登录</li>
            <li><CheckCircleOutlined />在工作电脑启用 {BRAND} 远程插件</li>
            <li><CheckCircleOutlined />在设备列表中选择要连接的主机</li>
          </ol>
          <a className="landing-plugin-action" href="/app/login" onClick={event => internal(event, '/app/login')}>打开登录页面 <RightOutlined /></a>
        </section></div></aside>
      </div></section>
      <section className="landing-security" aria-labelledby="security-title"><div className="landing-security-inner">
        <div className="landing-security-heading"><h2 id="security-title">安全连接，代码仍留在你的电脑上</h2><p>只传输经过授权的加密业务数据。</p></div>
        <dl className="landing-security-list">
          <div><dt>工作区不离开电脑</dt><dd>源码和工作区文件保留在主机上。</dd></div>
          <div><dt>设备明确可见</dt><dd>登录后可查看已授权设备及在线状态。</dd></div>
          <div><dt>连接端到端加密</dt><dd><SafetyCertificateOutlined /> 只有经过授权的设备可以继续工作。</dd></div>
        </dl>
      </div></section>
    </main></Layout.Content><SiteFooter />
  </div>
}
