# MethodCard: cpp.lifetime.unique-raw-alias-reset-v1

> 状态：Detector Contract v1 尚未冻结。本 detector 使用当前已实现的
> `src.ohscanner.contracts.Detector.detect(context, units) -> DetectorRun`，
> 版本为 `0.2.0-proposed`。所有 finding 都是 syntax-level
> `candidate/unassessed`；`completed` 仅表示所选 scope 被执行，不表示 safe。
> partial/failed/blocked/not_run 是 unknown 或覆盖不足，不是 miss。
> unsupported language 是 `not_applicable`，也不是 miss。

## 1. 精确检测语法形状

当前规则只组合以下事实：

1. 同一个已解析 C++ 函数内显式出现
   `std::unique_ptr<T> owner`；
2. 显式 raw alias 形式为 `T* alias = owner.get();`；
3. 同一个已解析 owner binding 后出现 `owner.reset(...)`；
4. reset 之后出现 `alias->...`、`(*alias)...` 或 `*alias`；
5. alias、owner、reset 和 use 位于同一函数，且命中声明位置加精确
   function/block scope 形成的稳定词法 binding identity；
6. 如果 reset 与 use 之间存在无控制流边界的直行
   `alias = owner.get();`，默认抑制 candidate；
7. 条件、循环、跳转、短路或嵌套块中的 rebinding 不作为安全证明，保持 candidate；
8. `std::lock_guard`、`std::unique_lock`、`std::scoped_lock` 仅记录
   `sync_scope`，不抑制 candidate。

当前 dereference 识别是正则语法切片，不是完整 C++ parser、CFG、数据流、
类型系统或生命周期分析。

## 2. 必要条件与判定边界

### 2.1 生成当前 candidate 的必要事实

所有下列事实都必须同时观察到；缺少任一事实时，不生成该规则 candidate：

- 显式 `std::unique_ptr<T>` owner declaration；
- 显式 `T* alias = owner.get()` raw alias declaration；
- 可解析到同一 owner binding 的 `owner.reset()`；
- reset 之后、相同 alias binding 下的显式 dereference；
- 同一函数和可建模词法 binding scope；
- finding 文件、行、列、rule id、evidence type 与 source SHA-256 完整绑定。

这些是规则 shape 的必要条件，不是漏洞成立的充分条件。规则不证明对象一定
析构、路径一定可达、alias 一定逃逸、调用者一定可控或存在安全影响。

### 2.2 只能保持 unknown 的情况

- `parse_status=partial/failed/not_run`；
- owner、alias 或 reset symbol 无法解析到规则所需 binding；
- reset 括号不平衡、函数/所有权语法不在可建模 block span；
- unsupported language、空 selected scope 或 no matching language；
- cooperative timeout、detector exception、异常输入；
- mixed complete/incomplete scope 中未完整分析的部分；
- 宏展开、模板、lambda capture、复杂 declarator、跨函数 transfer 等超出
  当前语法切片的情况。

这些情况不能写成 safe、miss、fixed 或 confirmed。`completed` 只覆盖实际
selected/analyzed files；empty findings 不是安全证明。

## 3. Pinned development fixtures

全部是本分支自建 synthetic development fixtures，不是 OpenHarmony 真实漏洞
样本，也不是独立 holdout。`manifest.json` 逐文件绑定 language、SHA-256、
parse status、parse issues、fixture category 和 expected observation。

| Evidence group | Fixture | Parse | 观察 |
|---|---|---|---|
| vulnerable | `vulnerable_unserialized.cpp` | complete | 1 candidate shape |
| vulnerable | `vulnerable_inside_mutex.cpp` | complete | 1 candidate shape |
| vulnerable | `vulnerable_conditional_rebind.cpp` | complete | 1 candidate shape |
| fixed | `fixed_alias_rebind.cpp` | complete | 当前规则无 finding |
| safe | `safe_use_before_reset.cpp` | complete | 当前规则无 finding |
| safe | `safe_shadowed_scope_bindings.cpp` | complete | 当前规则无 finding |
| unknown | `partial_parse_macro_context.cpp` | partial | unknown |
| unknown | `failed_parse_unbalanced.cpp` | failed | unknown |
| unknown | `not_run_parse_pending.cpp` | not_run | unknown |
| unknown | `missing_symbol_unresolved_alias.cpp` | complete | blocked/unknown |
| unknown | `incomplete_scope_unmodeled_owner.cpp` | complete | blocked/unknown |
| not_applicable | `unsupported_language_note.js` | complete | no matching language |

review evidence 必须按 `vulnerable/fixed/unrelated/safe/unknown/not_applicable`
分组运行；这些 evidence class 不得混成一个结果。safe fixture 即使
`completed` 且无 finding，也只能记录“该 selected scope 未观察到当前 shape”，
不能记录 safe verdict。

## 4. 覆盖与失败状态

- vulnerable development group：3 complete units，当前模式 3 candidate shapes；
- fixed development group：1 complete unit，当前模式 0 candidate shapes；
- safe development group：2 complete units，当前模式 0 candidate shapes；
- unknown group：5 units，覆盖 partial、failed、not_run、unresolved symbol、
  incomplete scope 各 1，run 保持 `blocked/unknown`；
- no matching language group：Runner 保持 `blocked`，limitation 为
  `not_applicable: no source with supported language.`；
- exception/invalid input 由 deterministic tests 隔离为该 detector 的
  `failed` 或显式拒绝，不转换为 miss；review sidecar 对越界 line/column 和
  非对象 metadata 显式拒绝。

这些是 fixture behavior 和覆盖状态，不是准确率结论；不计算 Precision/Recall。

## 5. 算法

1. 保持偏移量地屏蔽 comment/string/char literal；
2. 识别函数 brace span、`unique_ptr` owner、raw alias、窄显式 pointer /
   simple `auto name = expr` binding、`reset()` 和 alias dereference；
3. 按声明位置与精确 function/block scope 生成 owner、alias、pointer binding ID，
   owner/reset/rebind 通过该身份解析，而不是仅凭变量名拼接；
4. sibling/nested scope、不同函数中的同名 owner/alias 不跨 binding 拼接；
5. 只有无控制流边界的直行同 owner rebinding 才抑制 candidate；
6. 记录 sync scope，但不把锁解释为生命周期证明；
7. 缺失 symbol、unbalanced syntax 或不可建模 binding 使该 unit coverage
   incomplete，run 为 `blocked`，observation 保持 unknown；
8. 按 `(file,line,rule_id,message)` 折叠重复 identity 并稳定排序。

## 6. 输出与 source binding

公共映射保持不变：

- `DetectorFinding.file/line/column` -> `ToolDiagnostic` 位置；
- `rule_id = ohcpp-lifetime-unique-raw-alias-reset-001`；
- `evidence_type = syntax`；
- `candidate_cwe = CWE-416` 只作为初步类别；
- Runner 强制 `severity=confidence=unassessed`；
- `DetectorRun.status` 只描述执行/覆盖状态。

由于公共 `DetectorFinding`/`ToolDiagnostic` 当前没有 `source_sha256`，
本分支使用 `src/ohscanner/detectors/cpp/lifetime_review.py` 生成本地 review
sidecar。sidecar 为每个 finding 绑定真实 file、line、column、rule_id、
evidence_type、symbol 和 `SourceUnit.sha256`，并用 `finding_binding_id`
检测 stale/edited binding。该 workaround 不是公共 contract 实现；所需接口
变更见 `research/corpus/native/contract_change_proposal.md` 中的 2026-10-10
native replay CCR requests。

## 7. 已知误候选来源

- 条件或非直行 rebinding 被保守保留，因无 CFG 无法证明 stale path 不可达；
- 宏、模板、lambda capture、复杂 declarator、引用和 wrapper 类型可能混淆
  owner/alias binding；
- 最内层花括号只近似 lexical binding；
- 同名成员字段、参数、capture 或跨函数变量未完整建模；成员赋值
  `holder.alias = owner.get()` / `this->alias` 不会创建或重绑局部 alias，
  但成员存储本身仍披露为 unknown；
- exception、early return、callback、析构顺序未建模；lambda capture 和
  跨函数/传递 alias escape 会标记 incomplete/unknown，逃逸后的生命周期
  语义不作 safe 判断；
- sync scope 分类不证明并发语义。

以上来源可能使当前语法 shape 与真实生命周期语义不一致。

## 8. 已知漏报来源

- alias 来自函数参数、返回值、capture、成员字段或容器；
- `std::shared_ptr`、自定义 smart pointer、wrapper getter；
- 当前正则未覆盖的 dereference、subscript、conversion、callback use；
- 宏展开后的 reset/use、模板实例化、跨函数 owner move/destruction；
- 多 alias、多 owner、复杂 control-flow 或 exception path；
- parse failure、not_run、missing symbol、unsupported language 和 incomplete
  scope 中的未分析内容。

“无 finding”只表示当前窄规则在当前 source/parse scope 内未产生 shape。

## 9. 独立 holdout 与当前未验证项

`manifest.json` 中 12 个 fixtures 全部是 development/contract fixtures，另有
内联 deterministic 反例覆盖同名 binding、成员赋值、lambda/跨函数逃逸。独立
holdout 尚未
收集或执行，必须按 `root_cause_instance_id` 隔离，并在 detector code、fixture
manifest hash 和 method card 冻结后才可查看。holdout 需包含不同命名、wrapper、
idiom、宏/模板/跨函数 failure cases，并绑定真实 OpenHarmony repository、
完整 commit、file blob/source SHA-256、build/profile scope 和 source artifact。

当前已有一次真实固定源码的 vulnerable/fixed/safe 原生运行证据，但它验证的是
状态隔离和方法不兼容披露，不是该历史根因的当前规则命中。仍没有：product
build/runtime validation、independent labels、独立冻结 holdout run、
CFG/dominator、完整 C++ parse、hard timeout/process/memory sandbox。不得据此
写泛化、误报/漏报或安全结论。

## 10. 2026-10-10 native vulnerable/fixed/safe evidence

真实样本为 OpenHarmony `commonlibrary_c_utils` 的
`c_utils-singleton-uaf-2026-01`。历史根因是并发 `shared_ptr`
publication/destruction；safe control 是 static reference accessor。当前规则
适配范围仅为同函数 `std::unique_ptr` owner -> `owner.get()` raw alias ->
`owner.reset()` -> later dereference，因此三个 benchmark cell 都是明确
`not_applicable`，不是 miss。

| Role | Exact commit | Source SHA-256 | Execution | Failure | Result |
|---|---|---|---|---|---|
| vulnerable | `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` | `ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4` | `blocked` | `blocked`: unmodeled `shared_ptr.reset()` / rule-symbol binding | `not_applicable` |
| fixed | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `completed` | `none` | `not_applicable` |
| safe | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `completed` | `none` | `not_applicable` |

fixed 与 safe 共享提交和 source hash，但 analysis unit、scope、config hash、
run ID 和 evidence unit ID 独立，不能互代。fixed/safe 的 `completed` 只表示
所选 scope 被执行，不表示 safe。三条记录均为
`candidate/unassessed/draft` 语义下的研究证据，`result_evidence_count=0` 不作
安全证明。

逐运行命令、config/raw/stdout/stderr/normalized SHA-256、耗时、覆盖和失败
原因见 `cpp_lifetime_native_evidence_2026-10-10.md`。metadata 记录行数
212/214，而 raw bytes 的 splitlines/newline observation 为 211/213；保留为
`metadata_mismatch_preserved`，不改写或称为 raw-backed。

## 11. Candidate semantics and acceptance boundary

所有 detector finding 仍是 syntax-level `candidate/unassessed/draft`。
`completed` 只是 scoped execution，`possible_hit` 不是确认漏洞；本次 native
package 不输出 `possible_hit`。partial/failed/blocked/not_run 是 unknown，
不是 miss；`not_applicable` 仅用于上面明确证明的方法/analysis-unit 不兼容。
本轮不计算 Precision/Recall，不宣称零误报/漏报，不生成 PoC、不触发漏洞，
也不在 production `detect()` 中调用外部扫描器。

## 12. Provenance 与许可证

代码、fixtures、方法、CCR 和测试均为本分支自建；未复制第三方规则或查询。
native evidence 只按 exact commit 获取并哈希绑定 Apache-2.0 上游源码，源码
bytes 不提交，保留上游 header/notice 要求和 attribution。正式 detector 路径
不启动 Semgrep、Cppcheck、Clang SA、CodeQL、Joern，也不生成 exploit/PoC、
编译产物或数据库。
