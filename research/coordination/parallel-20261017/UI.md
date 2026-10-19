# UI 线：审计流程与页面模块

使用自己的 worktree、env.sh、18773 和数据目录。不要连接 8765 正式数据库跑写操作。
先阅读产品参考 PRD 和 HTML；HTML 是原型，不能直接作为已接好后端的面板交付。

第一交付：在当前基线做运营页 browser smoke（新仓库/Ref 切换、日期预览、跨分支比较、矩阵、运行中取消、查看任务再创建新任务），
把实际缺陷和未覆盖项分开记录。随后只提取新建审计表单/范围与预算/结果入口为 web/src/features 下独立组件，
复用现有 API 和真实数据；一次只迁一个流程，保持现有深链接可用。
如果要改变产品导航，先交最小路由申请，由集成人修改 web/src/main.tsx。

边界：不修改 web/package*.json、全局 API 客户端、全局路由，不自行发明后端字段或模型成功结果。
空数据、失败、partial、unknown、未配置模型等状态必须可见；candidate 和 confirmed 文案分开。

验收：`cd web && npm ci && npm test && npm run build`；再启动自己的 start.sh 做浏览器表单提交到 Worker/报告。
保留旧任务详情、异步响应不得覆盖新选中项、仓库切换清空关联 Ref、矩阵不传表单辅助字段、取消实际发 POST。
浏览器结论必须附实际步骤、源基线、隔离数据位置、通过/失败/未测；API 回归通过不冒充 browser smoke。
提交前跑 scope check，并按模板交付。原型菜单整体替换现有 main.tsx 不属于本次授权范围。
