# CyberSecurity-Innovation-Audit

面向 2026 年研究生网络安全创新大赛“OpenHarmony 开源代码漏洞挖掘”赛题的研究与工具设计仓库。

当前状态：**架构与两周实施方案已形成，漏洞检测器和 PoC 验证器尚未实现。** 文档中的功能、指标、案例和目录代表设计目标；后续以固定 OpenHarmony 版本上的实际运行记录判断进展。

## 两周目标

3–4 人小组优先选择一个能在 Linux 上构建和测试的真实 OpenHarmony C/C++ 组件，跑通：

~~~text
固定源码/构建配置
→ 静态候选或独立 fuzz
→ 解释源、约束和危险操作
→ 使用原组件代码构造合法输入
→ 记录运行证据与安全影响
→ 检查修复前后及其他版本
→ 输出可复现报告
~~~

研究创新选择“历史安全补丁中的安全约束迁移”：抽取修复所保证的性质，再检查别处代码是否满足同类性质，并用安全反例与动态实验检验。该方法仍是研究假设，当前没有效果数据。

可选第二路线是 IPC/权限语义审计，只有取得匹配版本的系统环境、低权限调用主体和真实服务入口后才纳入主线。开发板和服务器的作用见环境文档。

## 从哪里读

1. [2026 架构与取舍](docs/architecture_2026.md)：赛题理解、总体方案、证据与验证闭环。
2. [路线比较](docs/technical_routes.md)：静态、fuzz、补丁约束迁移、权限审计的适用条件。
3. [两周路线](docs/roadmap.md)：D1–D14 工作、分工、硬切换点。
4. [环境与开发板入门](docs/environment_guide.md)：先用 Windows/WSL2，按实际需要准备 Linux 服务器或目标设备。
5. [模块与数据契约](docs/design.md)：TargetSnapshot、Candidate、Evidence、RunRecord、VulnerabilityCase。
6. [实验评价](docs/evaluation_criteria.md)：覆盖、精度、PoC、性能、消融与未知真值。
7. [赛题要求](docs/competition_requirements.md)、[漏洞范围](docs/vulnerability_scope.md)、[交付清单](docs/deliverables_checklist.md)。

## 比赛成果的三个层级

- **工具能力**：在公开历史修复前后和安全对照上可复现，证明分析链可运行。
- **当前源码研究**：候选的数量、来源、审核状态与排除理由如实记录。
- **正式漏洞案例**：目标版本、原组件 PoC、安全影响、CWE、已知 CVE、版本分析和修复建议具备证据。

公开历史漏洞重现不等于新发现；未找到 CVE 不等于 0-day；宿主机 sanitizer 结果不自动等于真实系统入口可利用。进展与限制都应从运行记录提取。

## 现有目录

仓库当前的 src、rules、samples、tests、scripts、config、models、outputs 等目录多数仍为空骨架。具体模块只有在两周路线的真实组件闭环中需要时才实施，不按目录名推定功能已经存在。

项目用于授权范围内的源码研究与赛事验证。真实新发现按 OpenHarmony 官方安全流程处理；相关运行包和报告在审核前由团队管理。

