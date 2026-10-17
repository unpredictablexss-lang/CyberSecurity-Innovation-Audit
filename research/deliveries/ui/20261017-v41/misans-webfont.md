# MiSans 实际 Web 字体接入（2026-10-17）

用户要求与工作区 HTML 同款字体，故使用原 HTML 完全相同的锁版本样式资源：
`https://cdn.jsdelivr.net/npm/misans@5.0.0/lib/Normal/MiSansVF.min.css`。

此前只声明 MiSans 字体名，没有加载 Web 字体，缺少本机字体时会回退；现从 style.css 的首条 @import 实际加载 MiSans VF。
body 与 Ant Design ConfigProvider 均优先使用 `MiSans VF`，标题、表单、按钮、菜单共用，Monaco/哈希继续等宽字体。
不下载或打包字体二进制，不修改系统字体或浏览器缩放。本次用户明确要求与 HTML 同款加载方式，取代之前仅本机字体的决定。
与原 HTML 一样需要浏览器访问 jsDelivr；首次离线/阻断 CDN 时仍可能显示系统回退，不声称离线字体交付。

验证：锁版本 CSS 与抽取的 WOFF2 子集返回 200，签名 wOF2、CORS *；UI/integration npm test 各 14/14，TypeScript/生产构建通过，构建及实际 HTTP CSS 保留同一 @import。
实际浏览器 document.fonts.load/check 与截图未验收：Work 设置仍禁用浏览器工具。网络资源可用不冒充浏览器渲染已核验。
无后端变更；未 push、merge main 或 Ready。
