# 系统设计与数据契约

> 本文规定两周原型各模块交换什么事实。字段是设计契约，不表示仓库中已经实现。主架构见 [architecture_2026.md](architecture_2026.md)，技术取舍见 [technical_routes.md](technical_routes.md)。

## 1. 三个边界清楚的子系统

### A. 目标与发现

输入为 TargetSnapshot 和 ScanScope。目标层记录固定源码、manifest、构建配置；发现层通过静态规则、成熟分析器、补丁约束迁移、独立 fuzz 产生 Candidate。发现器不写“已确认漏洞”字段。

### B. 调查与验证

CaseAssembler 按疑似根因合并候选；EvidenceStore 保存源代码证据、分析路径、反证和运行 artifact；ValidationPlanner 选择缺失事实；Runner 只执行明确的构建/运行计划，并产出不可变 RunRecord。人工复核决定哪些事实支持报告。

### C. 输出与评估

VersionAnalyzer 对每个目标版本建立独立状态；Classifier 产生 CWE/CVE 候选与依据；Remediation 记录修复建议和前后对照；ReportBuilder 从已存数据生成案例报告、性能说明及覆盖清单。报告不向模型“自由补全”。

单机 SQLite 可存元数据、关系和状态；原始日志、输入、二进制 hash、报告和可重现包保存在以内容 hash 命名的 artifact 目录。后续若规模需要，再换数据库而不改契约。

## 2. 目标与扫描范围

### TargetSnapshot

必需字段：

- target_id：manifest hash + 各 repo commit + target config 的稳定标识；
- source_origin：官方/镜像 URL、获取日期、是否核对官方范围；
- manifest_ref 与 manifest_hash；
- repositories：repo、commit、路径及归属 subsystem/component；
- build_profile：产品、架构、ABI、宏、编译器、sysroot、依赖、生成文件、构建目标；
- capability_mode：syntax_only、semantic_partial、build_verified；
- snapshot_artifacts：锁定清单、构建/导出日志及 hash。

这里不要求所有项目都能完整系统构建，但必须记录分析究竟覆盖哪个版本和配置。

### ScanScope

- scope_type：snapshot 或 commit_window；
- selector：仓库/组件/路径/语言/时间起止/时区/起止 SHA；
- eligible_files 与 excluded_files；
- exclusion_reason：generated、vendor、unsupported_language、too_large、missing_dependency 等；
- denominator_policy：统计中包含哪些文件和 LOC；
- scan_run_id、rule_set_version、analyzer_versions。

时间窗口模式应输出实际枚举提交数和选用快照，不把“窗口内改动文件”当整个安全上下文。

## 3. Candidate、Evidence、Case

### Candidate

一条发现器输出包含 candidate_id、target_id、origin（rule、analyzer、patch_pattern、fuzz、manual）、primary_location、suspected_root_cause、candidate_cwe、input_contract、potential_effect、evidence_ids、unknowns、next_action、stage。

primary_location 至少有 repo、commit、文件路径、函数或符号、起止行和代码 hash。行号随版本改变，所以不能作为跨版本唯一键。

多个发现器命中同一位置只能增加来源信息；相同底层关系的重复证据不得简单累积分数。

### Evidence

统一字段：

- evidence_id、case_id/candidate_id、type 与 producer/version；
- target_id、build_profile_id、source_location；
- proposition：这条证据支持或反驳的具体命题；
- observation：简明观察；
- artifact_uri 与 content_hash；
- assumptions、limitations、depends_on；
- observed_at、reviewer/status。

Evidence 类型可以是 code、AST、dataflow、guard、callsite、build、runtime、permission_policy、git、advisory、human_review、llm_suggestion。LLM 建议默认不作为漏洞事实，只提供待验假设。

### VulnerabilityCase

以根因归并，包含 case_id、root_cause、violated_invariant、related_candidates、attack_prerequisites、affected_object、trigger_condition、security_effect、evidence_ids、counter_evidence_ids、weakness/CWE、CVE 状态、版本矩阵、PoC、修复、结论与披露状态。

一条 Case 可涉及多个调用点和多个版本。拆分/合并时保留旧 ID 引用与理由；不要因目录不同自动算两个漏洞。

## 4. 验证任务与运行记录

### ValidationPlan

记录要测试的一个命题、目标代码 SHA、原始组件构建目标、合法调用契约、harness 来源、输入和环境要求、运行资源上限、oracle、正常对照与失败时的下一步。动态实验前先写 oracle，避免看见某个 crash 后倒过来改成功标准。

计划可由模型提出，但有一名成员审核“是否保留关键检查与真实入口”。运行器只能读取批准的计划，不能让模型任意拼接 shell 命令。

### RunRecord

每次执行独立保存：

- plan_id、target_id、toolchain/OS/架构、容器或镜像 digest；
- build command、exit code、stdout/stderr、二进制 hash；
- run command、输入 hash、seed、timeout/内存上限；
- oracle_version、observed_result、sanitizer trace、栈/服务日志；
- outcome：build_failed、environment_blocked、harness_invalid、timeout、not_triggered、triggered、inconclusive；
- 运行时间、峰值内存、操作者、artifact hash。

RunRecord 是事件，不被后续“修正结论”覆盖。分析结论另建 ReviewRecord 引用它。

### ReproductionPackage

包内有目标仓库与 SHA、构建配置、README、合法输入生成方式、harness/PoC、正常与异常输入、执行命令、预期与实际输出、原始日志、依赖清单、实验限制。未公开新漏洞的包可以内部保存，在完成官方报告流程前仅输出受控摘要。

## 5. 版本与补丁状态

VersionAssessment 每个目标 manifest/仓库 SHA 一条，字段包括 target_id、feature_presence、guard_status、path_status、poc_retest_status、assessment、evidence_ids、unknowns、reviewer。assessment 允许 affected、fixed、not_present、not_applicable、unknown。

PatchAssessment 记录原始行为、补丁 SHA、构建结果、恶意输入对照、正常输入对照、边界变体、功能回归与剩余限制。补丁无法编译时是验证失败，不是修复成功。

CVEAssociation 独立存候选编号、公告 URL、代码/补丁/版本/行为匹配证据和审查状态。严重度也单独存事实与评分模型版本，不混入发现置信度。

## 6. 状态迁移与报告门槛

候选状态允许：

~~~text
candidate → triaged → investigation → validated_component → validated_target → reportable
             ↘ refuted / quality_issue / duplicate / inconclusive / blocked
~~~

- candidate：某通道产生线索。
- triaged：人工或程序说明拟验证的安全性质与入口。
- investigation：补上下文、构建、调用约定或测试。
- validated_component：原组件代码在说明的配置下真实触发。
- validated_target：目标配置或真实系统入口验证，依案例而定。
- reportable：比赛要求的 PoC、分类、影响、版本、修复与报告字段齐备，且有人工复核。
- refuted：针对原命题找到具体反证。
- quality_issue：确有软件问题但没有足够安全影响。
- inconclusive/blocked：实验或环境尚不能回答，不自动归为阴性。

状态变更写审计记录：操作者、时间、前后状态、依据和可复查 artifact。允许回退；例如后续发现 harness 绕开真实检查时，Case 应降级。

## 7. 模块接口与故障行为

| 模块 | 输入 | 输出 | 故障时 |
|---|---|---|---|
| AssetAdapter | 官方来源与版本选择 | TargetSnapshot | 标记无法锁定版本 |
| BuildAdapter | Snapshot、目标 target | 编译信息/构建记录 | 降级 partial，保留日志 |
| SyntaxIndexer | 源码 hash | 语法/符号索引 | 标记解析失败文件 |
| CandidateProviders | 索引或 fuzz artifact | Candidate/Evidence | 单通道失败不遮盖其他通道 |
| ContextResolver | Candidate、编译信息 | 调用/约束摘要 | unknown 与未解析边显式输出 |
| ValidationPlanner | Case、未知项 | ValidationPlan | 无法构造时说明缺什么 |
| Runner | 审核后的 Plan | RunRecord | 失败分门别类，不修改 Candidate |
| VersionAnalyzer | Case、目标版本组 | VersionAssessment[] | unknown，不猜已修复 |
| ReportBuilder | 结构化 Case | 报告与复现包 | 缺必填字段时拒绝“正式”标签 |
| MetricsCollector | Scan/Run 事件 | 覆盖/性能记录 | 保留缺失项，不能填零 |

第一版不必实现所有适配器。设计边界保证今后替换具体工具时报告格式仍一致。

## 8. 缓存与可重复性

语法、编译语义、检测、运行四级缓存分别设置完整依赖 key。尤其是编译语义涉及传递头文件、生成源码、宏、编译器版本和目标 ABI；缺少依赖时对相关缓存保守失效。实验输出包含所有缓存命中/未命中信息，冷运行与暖运行分别报告。

同一次目标扫描包含 run_id、工具配置 hash、目标快照、CPU/内存/墙钟和每个阶段事件。报告结果的行号、证据与 PoC 应从相同 target_id 引用，避免从后来更新的 master 取代码片段。

## 9. 两周内不必实现的部分

完整统一 CPG、图数据库、跨语言全程序别名分析、全自动漏洞发布、复杂 Web Dashboard 不在本轮必做范围。文档保留接口和数据契约，让三四人能先围绕一个真实案例验证方案是否成立。

