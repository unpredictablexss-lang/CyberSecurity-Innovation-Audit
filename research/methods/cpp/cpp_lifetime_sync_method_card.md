# MethodCard: cpp.lifetime.unique-raw-alias-reset-v1

> 状态：Detector Contract v1 尚未冻结。本 detector 使用当前已实现的
> `src/ohscanner.contracts.Detector.detect(context, units) -> DetectorRun`
> 接口，版本仍标记 `0.1.0-proposed`，映射设计仍属 proposed design。
> `bounds/length/Parcel` 仅完成独立研究切片，未提升为正式 detector。
> 结果只含 syntax-level `candidate` 证据；不自报 confirmed、safe、
> `possible_hit/miss` 或漏洞结论。

## 1. 问题与精确适用范围

只处理一种所有权/生命周期形状：

1. 同一个已解析 C++ 函数内显式声明 `std::unique_ptr<T> owner`；
2. 通过 `T* alias = owner.get();` 建立 raw alias；
3. 之后执行 `owner.reset(...)`，旧对象不再由该 owner 保持；
4. 在 `alias = owner.get();` 重新绑定前，出现 `alias->...`、`(*alias)...`
   或 `*alias` 解引用；
5. 对 reset/use 分类是否处于同一个 `std::lock_guard`、`std::unique_lock`
   或 `std::scoped_lock` 词法作用域。

同步分类不会抑制候选。锁不延长已析构对象生命周期，也不证明锁序、条件
变量、回调、跨线程 alias 发布或析构顺序。本 detector 不同时处理 UAF
全形态、double-free、null deref、integer overflow、OOB 或并发竞争。

## 2. 接口与 required_facts

- `detector_id = ohscanner.cpp.lifetime`
- `version = 0.1.0-proposed`
- `supported_languages = ("cpp",)`
- `required_facts = ()`

`required_facts` 为空是因为下列输入已经是公共契约的必填字段，不应伪造为
`ScanContext.shared_facts` key：

- request repository/commit/profile/provenance/snapshot SHA-256；
- source repository-relative path；
- source text；
- source SHA-256；
- `parse_status` 和 `parse_issues`。

`lexical function block`、`ownership operation`、`raw alias`、`sync scope`
由 detector 对 `SourceUnit.text` 做有限语法切片计算，不要求 M2+ 公共 IR
字段。

## 3. Fixtures 与覆盖

全部为自建 synthetic development fixtures，不是公开 OpenHarmony 漏洞样本：

| 类别 | Fixture | 预期 |
|---|---|---:|
| vulnerable | `tests/detectors/fixtures/cpp_lifetime/vulnerable_unserialized.cpp` | 1 candidate |
| vulnerable + mutex | `tests/detectors/fixtures/cpp_lifetime/vulnerable_inside_mutex.cpp` | 1 candidate |
| fixed | `tests/detectors/fixtures/cpp_lifetime/fixed_alias_rebind.cpp` | 0 |
| safe control | `tests/detectors/fixtures/cpp_lifetime/safe_use_before_reset.cpp` | 0 |
| partial/unknown | `tests/detectors/fixtures/cpp_lifetime/partial_parse_macro_context.cpp` | 不分析 |
| failed | `tests/detectors/fixtures/cpp_lifetime/failed_parse_unbalanced.cpp` | 不分析 |

`manifest.json` 记录逐文件 SHA-256、parse 状态和解析问题。包含
partial/failed unit 时，即使 complete unit 已分析并产生候选，run 仍是
`blocked`；`ToolRunResult.parsing` 保留逐文件真实状态。

## 4. 算法

1. 保持偏移量地屏蔽注释和字符串/字符 literal；
2. 识别函数花括号范围、`unique_ptr` owner、raw alias、`reset()` 和 alias
   dereference；
3. 只在 owner/alias/reset/use 位于同一函数范围且顺序满足
   alias -> reset -> use 时生成候选；
4. 若 reset/use 间存在同 owner 的 `alias = owner.get()`，最终模式抑制候选；
5. 记录 `sync_scope=same_scoped_mutex_lock` 或
   `sync_scope=no_same_scoped_mutex_lock_observed`，但不改变候选是否产生；
6. 按 `(file,line,rule_id,message)` 折叠重复身份并稳定排序，避免共享
   Runner 拒绝重复 diagnostic identity。

## 5. 输出映射

使用现有 `src/ohscanner.runner.run_all`，不新增公共 schema：

- `DetectorFinding.file/line/column` -> `ToolDiagnostic` 位置；
- `evidence_type="syntax"` -> `ToolDiagnostic.evidence_type`；
- `rule_id` -> `ohcpp-lifetime-unique-raw-alias-reset-001`；
- `message` -> 解释 candidate shape、sync constraint 和非证明边界；
- `candidate_cwe="CWE-416"` 仅是初步候选类别；
- Runner 强制 `severity=confidence="unassessed"`；
- `DetectorRun.analyzed_files` -> `scope_files/scope_loc`；
- `SourceUnit.parse_status/parse_issues` -> `ToolRunResult.parsing`；
- `DetectorRun.limitations` -> `ToolRunResult.limitations`，Runner 再补充
  provenance、硬隔离缺失和非漏洞证明边界。

公共 schema 没有 candidate/review/validation status、constraints、
source hash sidecar；本轮不修改 schema。若未来公共化这些字段，应单独提交
contract-change proposal。

## 6. 状态语义

1. 执行：`completed/failed/blocked`，只表示 detector 调用结果；
2. 解析覆盖：`complete/partial/failed/not_run`，缺失分析保持 unknown；
3. benchmark 匹配：`possible_hit/miss/unknown/not_applicable`，本 detector
   不产生、不映射、不自报。

空 findings 不是 safe，也不是 benchmark `miss`；`completed` 不是安全结论。

## 7. 确定性、失败隔离与超时

- 输入 unit 按 path 去重排序；finding 按 file/line/column/rule/message 稳定
  排序；
- detector 自身折叠重复 finding identity；
- 共享 Runner 对每个 detector 独立捕获异常，crash 只生成该 detector 的
  `failed` ToolRunResult，后续 detector 继续执行；
- `LifetimeAnalysisOptions.timeout_check` 是 cooperative timeout，用于测试
  detector 自身返回 `failed` 后其它模块继续运行；
- 共享 Runner 尚无 hard timeout、独立进程、内存/文件沙箱或 kill/cancel。
  因此不宣称已实现硬超时或资源隔离。

## 8. 消融结果（2026-10-09 真实运行）

| 模式 | vulnerable | vulnerable+mutex | fixed | safe | partial | failed | 总 candidate |
|---|---:|---:|---:|---:|---:|---:|---:|
| base pattern | 1 | 1 | 1 | 0 | 0（unknown） | 0（failed parse） | 3 |
| + alias rebinding suppression | 1 | 1 | 0 | 0 | 0（unknown） | 0（failed parse） | 2 |
| + sync-scope classification | 1 | 1 | 0 | 0 | 0（unknown） | 0（failed parse） | 2 |

alias rebinding constraint 消除 fixed fixture 的结构误候选；sync
classification 不改变计数，只增加 `same_scoped_mutex_lock` 描述事实。
这只是开发 fixture 行为，不是准确率或泛化结论，不计算 Precision/Recall。

## 9. 已知限制与未验证命题

- 不计算完整类型、CFG、path dominance、数据流、exception/early-return；
- 不证明对象在所有可达路径上存活、析构时机、alias escape 或所有权转移；
- 不建模 lambda capture、宏展开、template/container wrapper、回调、条件
  变量、锁顺序或并发 alias publication；
- 不证明 candidate 可达、可触发、可利用或具有安全影响；
- 不证明任何真实 OpenHarmony 代码存在 UAF；
- 独立 holdout 尚未收集或运行，不能宣称泛化、误报率或漏报率。

## 10. 许可证与 provenance

代码、fixtures、方法和测试均为本分支自建；未复制第三方源码、规则、查询
或许可证材料。正式执行不启动 Semgrep、Cppcheck、Clang SA、CodeQL 或
Joern，也不生成 exploit/PoC、编译产物或数据库。
