# D 首轮：Native 敏感材料日志局部数据流候选（Draft）

本轮新增敏感来源/日志Sink模型及 data.log.sensitive-value 单规则，输出来源→赋值/复制/格式化→public日志操作数的受限证据链。排除密钥长度、状态、布尔比较和纯关键字匹配；未知宏、格式、调用/类型/运行配置保留partial/unknown。

基线：e510c99c67f31ec6c73365f9ab749c79ca6ff0a1。Detector拟议ID为 ohscanner.data.sensitive_exposure，尚需负责人确认；未注册Catalog，未修改公共API/Runner/UI及A/B/C检测器。

验证：32个合成控制/10个新增测试方法；全量522项，511通过、11环境/历史证据/Docker限制跳过；compileall通过。固定官方dsoftbus提交0e0c18c4的9文件双跑0候选，coverage complete0/partial3/not_analyzed6，候选/覆盖一致。详见research/data_sensitive/validation.json和fixed_scope_summary.json。

限制：无已确认真实漏洞/独立holdout/真实漏洞修复对；不提供Precision/Recall。日志读权限、API绑定、初始化和产品CIA影响待审查。源/日志模型审批、可选共享表达式事实和partial AST策略见frontend_request.md。第三方源码仅本地缓存，未提交。

请先确认ID与模型/接口边界，再决定正式注册或选择性迁入。保持Draft，不自动ready/merge。

## 审核入口

- 第一阶段验收：`research/data_sensitive/phase1_acceptance_zh.md`
- 初步接口需求：`research/data_sensitive/interface_requirements_zh.md`
- 后续研究方案：`research/data_sensitive/research_plan_zh.md`

用户本次明确授权发布到独立分支并创建 Draft PR，供队长审核；这不表示拟议 ID 已通过负责人确认或允许注册上线。
