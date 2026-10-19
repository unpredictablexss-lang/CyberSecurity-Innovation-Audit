# A-NULL-01 C/C++ NULL dereference method card v2

更新：2026-10-16。本文是 `ohscanner.cpp.null_dereference` 0.2.0 的当前方法卡；
`NULL_DEREFERENCE_METHOD_CARD.md` 的 v1 设计记录保留为历史研究资产。

## 身份和输出边界

- Detector：`ohscanner.cpp.null_dereference`，版本 `0.2.0`。
- Rule：`ohcpp-null-dereference-candidate-001`，rule version `1.2.0`，
  lineage `A-NULL-01:ohcpp-null-dereference-candidate`。
- 语言和范围：显式 C/C++ source unit，`per_file` bounded lexical slice；
  固定 Git 重跑使用 `light-ast` profile。
- 默认状态：`candidate/unassessed`。诊断只表示 source/sink/guard 的语法事实，
  不证明解引用失败、所有权、支配性、并发、攻击者控制、产品可达性或 CIA impact。

每个 finding 绑定 `file`、`source_sha256`、rule version、lineage、symbol identity 和
bounded AST fingerprint。Runner 的 schema v2 identity/source-binding 层继续绑定
repository、full commit、snapshot、profile、source blob OID 和 byte range；
缺任一来源字段时 identity 保持 unknown/unbound，不回填历史报告。

## 有界 source、sink、alias 模型

Source 角色包括参数指针、局部指针显式空值/重绑定、成员显式初始化或赋值、
`new (std::nothrow)` 分配结果可能为空，以及函数返回值未知 nullability。Sink 包括
`*p`、`p->field`、`p->method()`、`p[i]`、宏展开边界、间接调用参数和简单同函数
pointer/reference alias。

本轮补强了：

- `nullptr`/`NULL` 局部声明和已识别指针的空值赋值；
- `new (std::nothrow) T(...)` 的 `may_be_null` source；该形状不再被误分类为
  普通未知 return value 或非空局部重绑定；
- 成员字段默认初始化、构造初始化列表和成员空值赋值；
- `T *alias = p`、`T *&alias = p`、`auto &alias = p` 的同函数 alias；
- `if (!p)`、`p == nullptr`、`p != nullptr`、`p`、`else` 分支；
- 多语句错误分支的最终 `return`/`throw`/`break`/`continue`/
  `abort`/`exit`/`terminate`/`assert(false)` 终止；
- `p && p->x`、`p || p->x`、`p ? p->x : 0` 的窄短路安全路径；
- 空值后可见的非空重绑定（例如 `p = &local`）不再把旧 source 带到 sink。

这些是有界 lexical/dataflow facts，不是完整 CFG、类型系统或 alias proof。

## 固定组件重跑和根因聚合

家族 Harness `research/tests/a_null_02_controls/replay_fixed_component.py` 只读取
本地 pinned Git objects，不 fetch/checkout。候选索引
`benchmarks/historical/communication_dsoftbus_null_deref.json` 仅提供目标清单，
其历史 verdict、CVE 和 advisory 不作为检测真值或升级证据。

| snapshot | commit | tree | source blob | source SHA-256 | profile/coverage | result |
|---|---|---|---|---|---|---|
| vulnerable | `258662cd9840b55a31546a72d91027f6368cea84` | `366a4ced9400653c9628c0b677e4ae657c0e7bd8` | `a82b71fb5520b02278a4af695bbe918d14c1048e` | `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6` | `light-ast` / complete | 5 sites |
| fixed | `192f3e11d74beeaa3d879333471deb8a24a7e1c5` | `1d58ba0ef706a6f69dd372bd496c8058810882aa` | `13ddbe93a7f617784dec0f3761e09f66b5c3217c` | `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81` | `light-ast` / complete | 0 sites |

五处 source-to-sink 关系分别是 L70→L71、L81→L82、L96→L97、L107→L108、
L122→L123。每处均为 `clientProxy = new (std::nothrow) BusCenterClientProxy(...)`
后直接 `clientProxy->...`，无已识别同函数 alias、局部重绑定或前置 guard。固定
snapshot 在相同关系前增加 `if (clientProxy == nullptr)` 早返回 shape。

这五处按 `A-NULL-02-RC-NOTHROW-CLIENTPROXY-ALLOC` 聚合为一个独立根因组：
`independent_root_cause_count=1`、`candidate_site_count=5`、
`validated_vulnerability_count=0`。不得按告警行数报告五个漏洞。

## Review 标签

- `likely_false_positive`：fixed/safe/unrelated 或非指针控制反驳的 detector 输出。
- `plausible_unproven`：精确 source/sink 关系存在，但触发、入口、攻击者控制、
  reachability 或 CIA 未证明。
- `refuted`：候选关系在 pinned comparison source 中不存在，或本地修复 guard 已
  出现；只反驳局部关系，不证明产品安全。
- `insufficient_evidence`：coverage、宏/模板、跨函数 alias、构建上下文或证据义务
  不足，不能升级为更强结论。

本轮五个 vulnerable sites 为 `plausible_unproven`，五个 fixed counterparts 为
`refuted`；控件噪声为 `likely_false_positive=0`；产品升级门为
`insufficient_evidence`。

## Guard、错误路径和覆盖语义

- `complete`：bounded slice 被完整处理；语义义务仍可是 unknown。
- `partial`：parse 为 `partial`/`not_run`，或宏、模板、异常、析构、间接调用、
  alias/CFG/build fact 不完整。可以保留有效 candidate，但不能输出 safe/miss。
- `failed`：parse 或完整性失败。输出 failed，不输出安全或漏报结论。
- `not_analyzed`：不支持的语言、超出输入预算或未选择单元。输出 blocked，不输出
  C/C++ 安全或漏报结论。

单文件最大输入为 1 MiB，单次 detector run 最大总输入为 32 MiB。超限单元
明确记录 `input_limit_*` 并 fail-closed。任何 `partial`/`not_analyzed` 都使聚合
run 为 `blocked`；`completed` 只表示所有适用单元完成了这个窄 slice。

每个 finding 保留八个 A-NULL-01 `EvidenceObligation`：`guard_dominance`、
`cross_function_alias` 为 `unknown`，编译上下文、入口/权限、攻击者控制、敏感操作
可达性、触发条件和 CIA impact 为 `missing`。没有真实证据前不得 `confirmed` 或
`reportable`；满足门后才允许独立升级。

## 控制和误报边界

`research/tests/a_null_02_controls/` 的 19 个 self-authored controls 保持：
positive 6、fixed 5、safe 4、unrelated 4。新增 inline nothrow positive/fixed
回归覆盖 allocation source 与 guard repair。历史 `research/tests/a_null_01/`
18 fixture matrix 保持独立，不改写其 manifest、hash、结果或历史结论。

- positive：无 guard、显式局部空值、成员默认初始化、reference alias、错误路径
  fall-through、未知 return value、nothrow allocation；必须稳定保留 candidate。
- fixed：多语句 early return、else-only safe path、alias early return、局部非空重绑定、
  short-circuit、nothrow allocation guard；不得把修复后控制判为漏洞。
- safe/unrelated：地址-of local、guarded alias、reference-to-local、非指针成员和
  文本相似但没有 source/sink 的控制；不得因文本相似升级。
- partial/failed/not_analyzed、重复 identity 和最大输入控制必须 fail-closed；
  重复同 line/message identity 仍按 runner 契约确定性去重，不伪造 message。

有限 synthetic controls 不能计算 Precision/Recall，不支持 zero FP/FN。残余误报
来源包括未解析宏/模板实例化、跨函数 alias、异常/析构边界、隐式转换、复杂
控制流、成员跨函数状态和错误的 pointer declarator 解析；这些保留 unknown 或
partial，而不是 safe。

## 性能和可重复性

分析只遍历 bounded source slice，输入上限和性能回归由
`tests/detectors/test_cpp_null_dereference_signal_controls.py` 固定。相同
SourceUnit、context 和 detector 版本重复运行产生相同 DetectorRun、diagnostic
identity 和 source binding。固定组件 Harness 的 `--check` 对完整 replay JSON 做
确定性比较。性能测试只限制 wall time，不宣称产品吞吐量。

## Catalog 注册建议（未实施）

可审计建议保存在
`research/evidence/cpp/a_null_02_fixed_component_review_20261016/catalog_metadata_suggestion.json`。
公共 Catalog 负责人可另行审查并注册：

- `detector_id=ohscanner.cpp.null_dereference`，`version=0.2.0`；
- rule ID/version 如上，`candidate_cwe=CWE-476`，`kind=research_candidate`；
- `supported_languages=(c, cpp)`、`ast_scope=per_file`、`profile=light-ast`；
- `root_cause_group=A-NULL-02-RC-NOTHROW-CLIENTPROXY-ALLOC`，按根因组计数；
- 默认 severity/confidence `unassessed`，保留 complete/partial/failed/not_analyzed；
- 与 0.1.0 历史结果保持隔离，不重写旧 report、diagnostic ID、review 或 EvidenceObligation。

本变更不修改 `src/ohscanner/detectors/catalog.py`、公共 contracts、runner 或
catalog 注册。历史 CVE/advisory、fixed commit、AST/pattern 关系都不能替代真实
入口、触发、攻击者控制、可达敏感操作和 CIA 证据，因此不得升级
`confirmed/reportable`。
