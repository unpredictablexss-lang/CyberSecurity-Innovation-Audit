# 默认比例与 HTML V8 风格调整（2026-10-17）

参考原件 `E:/读研/网络安全创新大赛/面板ui功能.html`，SHA-256 `f0ceb638508ced6f7bc432955249a3e122376bc7bb838c247585b58832bf90ba`；不修改原件。
本轮从 UI 9b2dbf6 / integration 30fe085 开始，两个 worktree 起始干净。

- 侧栏 242 → 228px，顶栏 68 → 58px，正文基础字号 13px，标题 25px，控制高度 32px。
- 撤下首页三张高入口卡，统计放首位，最近任务/能力摘要作两栏；三个入口保留为紧凑快捷按钮与侧栏子菜单。
- Ant Design token 统一为 HTML V8 的 #315fea 主色、#f4f6fa 底色与浅蓝选中状态；调整菜单分区、O. 标识、工作区卡、表格与卡片留白。
- 统计在中等宽度保持四列，窄屏两列；侧栏在 992px 以下折叠至 64px，表格内部滚动。
- MiSans VF / MiSans / MiSans L3 优先，缺少字体时走系统回退；未下载或打包字体二进制，也未引入 CDN。没有修改浏览器缩放或用 CSS zoom/transform 缩小整页。
- 能力状态复用服务实际 detector 元数据，不使用原型中的示意统计或百分比。所有原有表单与 API 保持。

代码 UI `93b19cdad532988ad9707f29845bdcb1099bd307`；集成 `e87a770a5465ad40217cba6fa522245e5690e3f0`。修改仅 WorkbenchApp.tsx、WorkspaceViews.tsx、style.css。
UI 和集成各自 npm test 14/14；TypeScript/生产构建通过；UI 原始不可变基线 scope check 与 diff check 通过。
本轮只改前端显示，未重复跑 Python；之前 519 passed / 4 skipped 为上一交付记录。
**本轮浏览器视觉/响应式复测未运行：Work 设置禁用本地浏览器工具。不能把旧版截图或旧窄屏验收作为新样式验收。**
当前 18773 从 integration/dist 提供新构建，服务/静态包通过 HTTP 读取并与磁盘哈希核对。
刷新入口 http://localhost:18773/#/overview 。后续在浏览器 100% 缩放下复查 1366×768、1440×900、390×844 与详情抽屉。
本轮未 push / merge main / Ready，未修改原 A/B 或负责人 worktree。
