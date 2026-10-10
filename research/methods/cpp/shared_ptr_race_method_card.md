# MethodCard: cpp.shared_ptr_race.non-atomic-shared-ptr-v1

> 状态：Detector Contract v1 尚未冻结。本 detector 使用当前已实现的
> `src.ohscanner.contracts.Detector.detect(context, units) -> DetectorRun`，
> 版本为 `0.1.0-proposed`。所有 finding 都是 syntax-level
> `candidate/unassessed`；`completed` 仅表示所选 scope 被执行，不表示 safe。
> `partial/failed/blocked/not_run` 是 unknown 或覆盖不足，不是 miss；
> unsupported language 是 `not_applicable`，也不是 miss。

## 1. 精确检测语法形状

当前规则只组合以下词法事实：

1. 类/结构体静态成员声明形如
   `std::shared_ptr<T> name;`（允许 `static` 前缀和简单初始化）；
2. 同一成员名在函数体内出现非原子读/写，例如
   `if (name == nullptr)`、`return name;`、`name.reset();`、
   `name = ...;`；
3. 该函数签名所在行的前缀包含该成员所属类名，避免把同文件的
   `DelayedRefSingleton<T>::instance_` 或 `Singleton<T>::instance_`
   误归到 `DelayedSingleton<T>::instance_`；
4. 如果同一成员在本单元中观察到 `atomic_load(&name)` /
   `atomic_store(&name, ...)`，并且一个非原子 occurrence 位于同一
   `std::lock_guard/unique_lock/scoped_lock` 词法 scope 内，则当前规则不生成
   candidate；
5. 同一成员的非原子 occurrence 不在任何可建模函数 span 中、且不在类体内或
   非 qualified 静态定义时，覆盖状态降为 `blocked/unknown`，不当作 safe。

这是正则语法切片，不是完整 C++ parser、CFG、数据流、锁语义、类型系统或
跨线程 interleaving 分析。`atomic_load/atomic_store` 与同 scope mutex 的启发式
不是同步证明。

## 2. 必要条件与判定边界

### 2.1 生成当前 candidate 的必要事实

- 显式 `std::shared_ptr<T>` 类/静态成员声明；
- 该成员在函数体中的非原子 occurrence；
- 该函数前缀包含成员所属类名；
- `file/line/column/rule_id/evidence_type/candidate_cwe/symbol` 和 `SourceUnit.sha256`
  完整绑定（源码 hash 通过 review sidecar 绑定）。

这些是规则 shape 的必要条件，不是漏洞成立的充分条件。规则不证明对象一定
析构、入口一定可达、调用者一定可控、锁一定保护/未保护、或存在安全影响。

### 2.2 只能保持 unknown 的情况

- `parse_status=partial/failed/not_run`；
- 成员名 occurrence 不在可建模函数 span，且不是类体内同名声明或 qualified
  static definition；
- unsupported language、空 selected scope 或 no matching language；
- detector exception、cooperative 或 runner 失败；
- mixed complete/incomplete scope 中未完整分析的部分；
- 宏展开、模板实例化、lambda、跨函数逃逸、复杂 declarator 等超出当前
  语法切片的情况。

这些情况不能写成 safe、miss、fixed 或 confirmed。`completed` 只覆盖实际
selected/analyzed files；empty findings 不是安全证明。

## 3. Pinned development fixtures

全部是本分支自建 synthetic development fixtures，不是 OpenHarmony 真实漏洞
样本，也不是独立 holdout。`manifest.json` 逐文件绑定 language、SHA-256、
parse status、parse issues、fixture category 和 expected observation。

| Evidence group | Fixture | Parse | 观察 |
|---|---|---|---|
| vulnerable | `vulnerable_non_atomic_shared_ptr.cpp` | complete | 非原子 shared_ptr candidate |
| fixed | `fixed_atomic_shared_ptr.cpp` | complete | 当前规则无 finding |
| safe | `safe_atomic_only.cpp` | complete | 当前规则无 finding |
| unrelated | `unrelated_plain_pointer.cpp` | complete | 当前规则无 finding |
| unknown | `unknown_partial_parse.cpp` | partial | unknown |
| unknown | `unknown_failed_parse.cpp` | failed | unknown |
| unknown | `unknown_not_run.cpp` | not_run | unknown |
| unknown | `unknown_incomplete_scope.cpp` | complete | blocked/unknown |
| not_applicable | `not_applicable_no_matching_language.js` | complete | no matching language |

review evidence 必须按 `vulnerable/fixed/unrelated/safe/unknown/not_applicable`
分组运行；这些 evidence class 不得混成一个结果。safe/unrelated/fixed fixture
即使 `completed` 且无 finding，也只能记录“该 selected scope 未观察到当前
shape”，不能记录 safe verdict。

## 4. 覆盖与失败状态

- vulnerable development group：1 complete unit，当前模式产生非原子
  shared_ptr candidate；
- fixed development group：1 complete unit，当前模式 0 candidate；
- safe development group：1 complete unit，当前模式 0 candidate；
- unrelated development group：1 complete unit，当前模式 0 candidate；
- unknown group：4 units，覆盖 partial、failed、not_run、incomplete scope，
  run 保持 `blocked/unknown`；
- no matching language group：Runner 保持 `blocked`，limitation 为
  `not_applicable: no source with supported language.`；
- exception/invalid input 由 deterministic tests 隔离为该 detector 的
  `failed` 或显式拒绝，不转换为 miss；review sidecar 对越界 line/column、
  stale source hash 和非对象 metadata 显式拒绝。

这些是 fixture behavior 和覆盖状态，不是准确率结论；不计算 Precision/Recall。

## 5. 算法

1. 保持偏移量地屏蔽 comment/string/char literal；
2. 识别函数 brace span、函数签名所在行前缀、类 brace span、锁声明 scope
   和成员声明；
3. 为每个 `shared_ptr` 成员记录所属类，按函数前缀过滤同名其他类成员；
4. 找到成员名在函数体内的非原子 occurrence，排除 `atomic_load/atomic_store`
   call 和声明行；
5. 若成员存在 atomic access 且当前 occurrence 处于同一词法锁 scope，则跳过，
   否则输出 syntax candidate；
6. 缺失 symbol、unbalanced syntax 或不可建模 span 使该 unit coverage
   incomplete，run 为 `blocked`，observation 保持 unknown；
7. 按 `(file,line,column,rule_id,message)` 折叠重复 identity 并稳定排序。

## 6. 输出与 source binding

公共映射保持不变：

- `DetectorFinding.file/line/column` -> `ToolDiagnostic` 位置；
- `rule_id = ohcpp-shared-ptr-race-candidate-001`；
- `evidence_type = syntax`；
- `candidate_cwe = CWE-362`：当前 candidate 的主根因类别是可能的 race condition；`CWE-416/use-after-free` 只是可能后果，不是已证明结果。
- Runner 强制 `severity=confidence=unassessed`；
- `DetectorRun.status` 只描述执行/覆盖状态。

由于公共 `DetectorFinding`/`ToolDiagnostic` 当前没有 `source_sha256`，
本分支使用 `src/ohscanner/detectors/cpp/shared_ptr_race_review.py` 生成本地
review sidecar。sidecar 为每个 finding 绑定真实 file、line、column、rule_id、
evidence_type、candidate_cwe、symbol 和 `SourceUnit.sha256`，并用 `finding_binding_id`
检测 stale/edited binding。该 workaround 不是公共 contract 实现。

### 6.1 CWE 语义边界

- 主 CWE 是 `CWE-362`（并发竞争条件的候选根因）；
- `CWE-416`（use-after-free）只记录为可能后果，不能当作已证明的 UAF、漏洞或影响；
- 当前 message 和 sidecar 明确不证明 UAF、guard dominance、concurrent interleaving、
  attacker control 或 security impact；
- finding 始终是 `candidate/unassessed` 的 `syntax` evidence；`completed` 只是 scope
  执行状态，不是 safe verdict；
- `partial/failed/not_run` 保持 unknown/non-miss，只有有证据的 incompatible analysis unit
  才是 `not_applicable`；
- 独立 holdout 状态为 `designed_not_executed`，未来只报告 raw observation/category counts，
  不计算或宣称正式 Precision/Recall、零误报或零漏报。

## 7. 已知误候选来源

- 同名 `instance_` 成员在不同类/模板中仍只靠函数前缀和类 span 近似区分，
  无完整 symbol/type resolution；
- 同一函数签名前缀包含所属类名不代表方法一定属于该类；返回类型、别名、
  macro、typedef 可能破坏归属；
- 锁 scope 只按最内层 brace span 近似，`defer_lock`/`try_to_lock`/`unlock`
  或跨函数 mutex 语义未建模；
- 存在 `atomic_load/atomic_store` 不证明所有非原子 occurrence 都被同一锁
  保护，也不证明同步正确；
- `std::atomic_load` / `std::atomic_store`、helper 函数或 typedef 中的原子
  访问若不在当前词法切片内，仍可能被误读为非原子 occurrence；
- 非原子 occurrence 在函数内但被 control flow/exception 分隔时仍保守保留；
- 宏展开、模板实例化、lambda capture、跨函数 return/参数 escape 未建模。

以上来源可能使当前语法 shape 与真实并发语义不一致。

## 8. 已知漏报来源

- `std::shared_ptr` 通过 typedef、template、member wrapper 或非简单声明出现；
- 成员名不是简单 identifier，或声明带复杂初始化、namespace qualifier；
- `atomic_*` 调用在宏、helper 或不同函数中，当前词法切片无法识别；
- 锁变量在函数前缀/返回类型中被改写、锁作用域跨函数、自定义锁类型；
- parse failure、not_run、missing symbol、unsupported language 和 incomplete
  scope 中的未分析内容；
- 非 atomic 访问隐藏在宏、跨函数、lambda、函数指针或容器中。

“无 finding”只表示当前窄规则在当前 source/parse scope 内未产生 shape。

## 9. 真实 OpenHarmony sample 与动态验证边界

真实样本为 `commonlibrary_c_utils` 的 `DelayedSingleton<T>`：

- vulnerable commit `bdfafdaafddb01ab7ae13354ce2ada9555d7935c`
- fixed commit `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7`

本分支在 WSL2 本地隔离环境用 clang 14 + ThreadSanitizer 构建了两个
200000-round 双线程 harness，`vulnerable` 版本观察到 data race 与
heap-use-after-free，`fixed` 版本未观察到 TSan 报告。完整命令、源码/二进制/
日志 hash、耗时、exit code 和 sanitizer 版本见
`research/experiments/cpp/shared_ptr_race_tsan_reproduction.md`。

动态证据只验证“该 harness 在该环境/commit 下是否触发”，不是 exploits 证明，
也不是全量安全结论。真实源码 bytes 不提交仓库，只按 exact commit 和 source
hash 绑定。当前 detector 不执行该 PoC，也不在 `detect()` 中运行 TSan。

同时提供 `research/experiments/cpp/shared_ptr_race_native_evidence.py`。该脚本
不再接受任意导出文件冒充 Git 来源，而是：

1. 校验本地 `origin` 为认可的公开代码托管地址且 owner/repository 精确匹配；
2. 从固定 commit 的本地 Git tree/blob 读取 exact source bytes；
3. 核对独立固定的 binding manifest 中的 commit/tree/blob/source SHA-256；
4. 生成 source-hash-bound 的 vulnerable/fixed detector evidence。

`research/experiments/cpp/prepare_shared_ptr_race_binding.py` 只生成 draft binding
manifest 和 hash；该 hash 必须由独立证据流程另行固定后才可视为可信标签绑定。
脚本不 fetch、不运行外部扫描器，也不把真实 source bytes 提交仓库。

```bash
python3 -m research.experiments.cpp.prepare_shared_ptr_race_binding \
  --repo-root /path/to/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --source-path base/include/singleton.h \
  --vulnerable-commit bdfafdaafddb01ab7ae13354ce2ada9555d7935c \
  --fixed-commit 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7 \
  --json-out /tmp/shared-ptr-binding.json \
  --sha256-out /tmp/shared-ptr-binding.sha256

python3 -m research.experiments.cpp.shared_ptr_race_native_evidence \
  --repo-root /path/to/commonlibrary_c_utils \
  --binding-manifest /tmp/shared-ptr-binding.json \
  --binding-sha256 "$(cat /tmp/shared-ptr-binding.sha256)" \
  --repository openharmony/commonlibrary_c_utils \
  --source-path base/include/singleton.h \
  --json-out outputs/reports/shared_ptr_race_native/evidence.json \
  --md-out outputs/reports/shared_ptr_race_native/evidence.md
```

对应回归事实：

| 验证层 | 结果 |
|---|---|
| synthetic fixture manifest | `verify_shared_ptr_race_fixtures.py` 通过，12 units |
| synthetic fixture full run | `shared_ptr_race_fixture_evidence.py` 确定性输出，Runner status `blocked` |
| real-source native evidence | vulnerable `completed` / 7 findings；fixed `completed` / 0 findings |
| M1 Git-object integration | 本地临时 Git repo 两个 commit，vulnerable/fixed 分离运行通过 |
| 完整测试 | 241 项通过（本轮最终复测） |

这些是当前 fixture/runner/evidence 回归事实，不是漏洞准确率或安全结论。

## 10. Provenance 与许可证

代码、fixtures、方法、CCR 和测试均为本分支自建；未复制第三方规则或查询。
真实 OpenHarmony 源码只在隔离临时目录按 exact commit 获取、哈希绑定，
Apache-2.0 upstream source bytes 不提交仓库，保留 upstream header/notice。
正式 detector 路径不启动 Semgrep、Cppcheck、Clang SA、CodeQL、Joern，也不
生成 exploit/PoC、编译产物或数据库。
