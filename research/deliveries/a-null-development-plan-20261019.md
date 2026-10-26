# A-NULL 开发线计划（D，2026-10-19）

## 任务范围与现状

本线只负责 A-owned C/C++ NULL detector、专属回归、方法卡和开发证据。共同状态和 D/T 交接见 [A-NULL 总计划](a-null-development-test-plan-20261018.md)；真实漏洞根因/cJSON 任务见 [A 线总计划](cpp/a-lane-development-test-plan-20261019.md)，不可混用样本或结论。

当前 detector 为 0.6.0，强候选 rule 为 1.4.0。unknown-return 独立为弱观察；限定名或多重同名函数的返回值无法可靠绑定时保留 unknown/partial。无 compile DB/CFG 上下文时也保留 unknown/partial。宏、模板、跨函数及同名限定调用边界有 6 个固定哈希 controls；25 项 pinned main 对照已生成，after source hash 与当前 detector 一致，T 线 source-identities-only replay 已逐项复现输出。最新 pinned main 对照也已从 `4593a7c9` 重放到当前代码，18 个 A-NULL-01 fixtures 与 19 个 A-NULL-02 controls 的结果见 `research/evidence/cpp/a_null_03_unknown_return_20261018/pinned_before_after_main_20261019.json`。NULL/unsafe 专项 28/28、研究选择与 NULL controls 23/23、A-NULL-02 verifier 19 项通过。全规则研究 UI 显示弱候选/待复核、显式启用原因，并将未绑定历史量级 546,559 与可核验另一 run 的 403,360 条 NULL 原始观察/403,359 唯一 ID 分别标注；本轮 `web` 构建通过。D4 已保留 manifest v1 并增加 v2：四类计数 JSON Schema 与 stdlib validator 接入抽样生成器，v2 为跨仓相同源码计数保存逐簇 rule/source hash/repository/row evidence。9,323 provisional frame 的临时重建通过校验，仍保留 expected 8,994 / observed 9,323 / provisional=true；独立审计脚本已复算通过 schema、身份字段和四类计数，输出见 `research/evidence/cpp/a_unsafe_memory_review_20261018/v2_independent_audit/`。产品 compile DB/CFG 接入、公共报告接线仍未完成；owner 接口申请待评审。

## 本轮增量核验（2026-10-19）

- `web` 全规则研究预警明确把 546,559（报告提及但 run 身份未绑定）与 403,360 原始行 / 403,359 唯一 ID（可核验 run `1696df82…`）分开，注明二者不是同一轮且仅作量级提醒。
- 新增标准库只读审计 `research/tests/a_null_03_unknown_return/audit_full_scan_population.py` 与机器结果 `research/evidence/cpp/a_null_03_unknown_return_20261018/full_scan_population_audit_20261019.json`：run signature、scanner commit、manifest、compact summary/checksums 与 CSV 计数交叉核对通过。唯一重复 ID 的两条 CSV 行指向同一位置，但其 result JSON 只含一个 diagnostic；这解释 raw 行数与唯一 ID 面板差 1，不解释未绑定的 546,559。
- `npm run build`：通过；`node --test tests/auditRequests.test.js`：12/12 通过；`python -m unittest tests.test_null_research_selection`：2/2 通过。
- 2026-10-19 当前工作树定向复跑：A-NULL detector、signal controls、unsafe-memory、memory-safety 与两组 A-NULL 03 research tests 合计 67 项通过；这是本地开发回归，不替代 T 线独立复验。
- 预警变化不影响 detector 选择语义：普通 profile 不发送默认关闭的 NULL，只有显式 full-rules research 才包含它。研究模式中的未知返回仍为独立弱观察身份；CFG 与报告公共接口的阻塞条件未变化。

当前 unsafe-memory detector 为 0.5.0：已修正 format API 参数位、未知签名保留 partial/unknown、识别普通与 C++ raw string 常量格式，并在原扫描的 14 条条件 format 候选中抑制 8 条纯字面量表达式、保留 6 条含格式宏表达式；另外 source-hash replay 抑制了 4 条直接 raw-string 格式候选。11 个源码文件 hash 匹配，18/18 原观察重现；此项是开发侧语法边界证据，交由 T 线独立复验，不代表总体误报率。机器结果见 `research/evidence/cpp/a_unsafe_memory_review_20261018/literal_format_conditional_replay_20261019_v4.json`。表达式级 CSV census 覆盖 157 条 `printf/vprintf/syslog` 记录：14 条条件表达式、12 条当前识别的纯字面量格式（8 条条件 arms + 4 条 raw string）；其余记录未逐一 source replay，不外推逐文件结果。

新增的 829 文件 0.5.0 全量定点重放由 v8 工件绑定 detector 与共享 helper 两侧 source hash，且 baseline 模块从 pinned commit 隔离加载；8,504/8,504 基线行重现、829/829 输入 hash 匹配。当前 456 条候选（`fprintf` 405、`vfprintf` 51），825 个 complete、4 个 partial。v5/v6 的 baseline helper 未隔离，v7 固定了 baseline 但未记录 after helper hash，均保留作历史材料，不作为 canonical。与 0.3.0 相比多出的 239 条是字符串字面量前缀后接标识符/宏的表达式，不能沿用旧版按首字符抑制的边界，也不能把行为差异当成 TP/FP 标签。raw-string control 证明固定 raw 格式安静，raw-string 内标点不会扭曲共享实参切分；v8 这 829 个原候选文件计数仍为 456。共享 `split_call_arguments` 修复另在 235 个旧 unsafe-memory-call 候选文件重放：基线 662/662、当前 662、无 finding 差异，235/235 hash 匹配，230 个 complete、5 个 partial；该固定候选子集不能排除全库其他位置新增候选。长相邻字面量的线性扫描也避免正则回溯卡死。共享切分器涉及 bounds 与 integer-bounds，相关 27 项专项回归通过；0.5.0 条件 + raw-string source replay 为 18/18、11/11，8 条条件字面量和 4 条 raw literal 抑制、6 条宏/动态条件保留。机器结果见 `format_argument_positions_before_after_20261019_v8.json`、`unsafe_memory_call_argument_split_replay_20261019_v3.json` 和 `literal_format_conditional_replay_20261019_v4.json`。这些仍是开发侧证据，待 T 线独立复算。

456 条候选的 v8 表达式 census 中，122 条为调用/宏调用形状（其中 120 条外层调用标识符为 `_()`）、79 条为单标识符、239 条为字面量前缀加尾随 token、15 条其他复合式、1 条条件式。对 239 条字面量前缀源码逐项复算 hash 为 239/239；其中 177 条使用 `PRI*`、21 条使用 `TIFF_SSIZE_FORMAT`。当前只记录为来源形状，不据此收紧规则。下一步由开发线核实这些标准/项目宏及 gettext wrapper 的输入语义，提出有证据的分类策略和 controls；需要预处理或构建上下文时先明确 owner 接口依赖，不模拟宏展开结果。

120 条 `_()` 表达式另经只读源码审计：源码 hash 120/120 匹配；118 条 wrapper 参数是纯字面量序列，2 条含 `PROJECT_NAME`；110 条直接包含 gettext header，10 条无直接 include，所有文件都无同文件 `_` 定义。逐条材料见 `gettext_format_candidate_source_audit_20261019_v3.json`。这支持“本地化包装”来源形状，但不证明 `_` 的跨文件定义、catalog 来源/可信边界或实际可控性；开发线暂不调整告警语义。

候选源码自身的只读检查确认 18/239 直接包含 `<inttypes.h>`/`<cinttypes>`，14/239 在同一源码文件直接定义首个尾随宏 token。可见替换值部分为字符串字面量或别名，但尚未证明所有分支和 include 链；仓库范围的搜索也受 symlink/权限错误影响。开发线当前不应按 `PRI*`/项目宏名称直接过滤；等固定 compile context 后用预处理或 AST 确认有效扩展值，并先加 positive/fixed/macro-redefinition controls。

## 开发线任务树

```text
D0 固定 immutable base、源码/规则/profile、输入清单和 before 工件
├─ D1–D2 维护来源分级、NULL 默认关闭和显式研究模式的语义边界
├─ D3 完成 compile DB/Clang AST+CFG 接口契约；获可信构建输入后实现 A-owned consumer
├─ D4a 冻结原始观察/仓内根因/跨仓源码簇/人工结论的 schema 字段与未知状态
├─ D4b 加 validator、合法/非法 fixtures 和脱敏样例 manifest
├─ D4c 在 9,323 provisional frame 上做 schema-only 兼容演练，不改变观察行、不作准确率结论
└─ D4d 固定 hash 与 checkpoint，交测试线独立盲验
   D5 每轮持续维护 controls、性能记录、来源绑定和 pinned before/after
```

### 当前开发切片与完成门

**先执行 D4a–D4d**：该项不依赖 owner 或产品编译数据库，能与 T 线独立并行。四类计数不相加；无验证根因身份时计数为 `null` 并给出原因；跨仓相同源码须由精确源码身份和仓库身份复算；人工标签不得自动填充根因键。validator 必须证明原始观察行、位置和 partial/unknown 状态均保留，既有抽样/复核数据可读取。交付状态先标 `ready_for_review`，由 T 线验收后再更新。

D3 继续作为单独依赖项：owner 未提供可信 build-profile/provider 契约和匹配 compile DB 前，只整理消费接口与失败语义，不实现或宣称产品 AST/CFG 接入。当前仓库上游 `origin/main` 为 `56a5d2689a5abf21e13d35397d87c9b035954197`，A 隔离分支为 `4593a7c9b6977eb81172d01b46cc59daf46f5d45`（落后 12 个提交）；有 dirty 改动时不得 reset、checkout、stash、merge 或 rebase。先做只读路径/接口差异核对，公共改动交 owner。

2026-10-19 再次 `git fetch origin` 后 `origin/main` 仍为 `56a5d268…`。只读检查 HEAD 到上游的 12 个提交及 `origin/main` 的 `src/`、`tests/`，未发现 A-NULL compile DB/CFG provider 或消费契约；上游的 `indexing.py` 仍声明 `build_profile=none`，生产上下文提供轻量 AST/source facts。远端变更主要为 D 线扫描能力并涉及共享 `catalog.py`；当前工作树有大量 A 线 dirty 文件，故只记录上游，不把这些提交混入本轮 A 证据或 pinned 回归。

## 结构化 Vibe Coding 提示词

```text
角色：你负责 A-NULL 的 A-owned C/C++ NULL detector 与分析改进，只提交开发者回归和机器证据；抽样、真实案例标签和最终验收属于测试线。

持续目标：每轮基于固定 immutable base 完成一项有源码证据的检测改进；unknown/partial 诚实保留，交付专属正反 controls、来源绑定和 pinned before/after。当前优先任务是可信 compile DB/CFG 输入契约及 D4 四类计数 schema，不以降低告警数量为目标。

输入：共同基线、当前 dirty 状态、ownership、detector/rule 版本、有效源码/构建身份、既有 controls 和 pinned 工件。无匹配 compile DB 时不声称产品 CFG 已接入。每轮先记录 branch、HEAD 全 SHA、`origin/main`、ahead/behind、dirty paths；保护 dirty 文件，先只读审阅远端路径/接口变化，不能把远端 HEAD 冒充已验证 pinned base。

步骤：
1. 读取 A_CPP 约定、A-NULL method card、owner 接口申请和当前 checkpoint；保护现有工作树，固定本轮输入哈希与版本。
2. 复现具体语义缺陷并先记录 before；不要根据候选数猜测根因。
3. 仅在 A-owned detector 与专属测试内实现最小改动；共享 Runner/Catalog/UI/schema 改动先形成 owner 接口申请。
4. 覆盖 nullable 参数、显式来源、unknown-return、guard/sink、别名、宏/模板/跨函数及缺失/错误 build context；证据不完整时保留 obligations unknown/partial。
5. 增加 vulnerable/fixed/safe/unrelated/partial controls，并生成同源 pinned before/after、覆盖/耗时和失败说明。
6. D4 工作优先冻结字段级 schema、null/partial 语义、validator、正反 fixtures 和 schema-only 兼容产物；只改 schema/validator/fixtures/evidence，不改 detector、Runner、Catalog、API、UI。若要公共报告接线，先交 owner interface request。
7. 更新 method card 与 D checkpoint，冻结版本、命令、输入清单和变更范围，交测试线复验。

交付：代码与专属 controls、真实测试结果、rule/detector 版本、输入身份、机器可读 pinned 对照、coverage/性能/限制、接口申请（如需）和 checkpoint。

完成门：普通 profile 默认不启用 NULL；研究模式清楚标注弱观察/待复核及启用原因；来源证据分级清晰；无可信 CFG 时不伪造支配/安全结论；历史 controls 可复跑；测试线独立验收前标为待验收。

边界：不改历史报告、finding identity 或未经批准的公共合同；不覆盖 dirty worktree、不删除候选/证据、不 push/merge/改 PR。每轮写明 partial/unknown 和下一动作。
```

## 持续目标

持续按“固定基线—复现缺陷—最小 A-owned 改进—controls—pinned 证据—交测试线”推进。构建上下文、接口或证据缺失时切到可独立完成的计数草案/控制覆盖工作，并保留阻塞状态。
