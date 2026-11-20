import { LinkOutlined } from '@ant-design/icons'

export function SiteFooter() {
  return <footer className="site-footer app-footer">
    <span>© 如意 AI</span>
    <div className="site-footer-links">
      <a href="/" className="site-footer-link" aria-label="返回首页"><LinkOutlined aria-hidden="true" /><span>返回首页</span></a>
    </div>
    <span className="site-footer-credit">企业远程连接服务</span>
  </footer>
}
