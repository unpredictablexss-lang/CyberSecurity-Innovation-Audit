# MethodCard: cpp.shared_ptr_race.non-atomic-shared-ptr-v1

> 状态：Detector Contract v1 尚未冻结。本 detector 使用当前已实现的
> `src.ohscanner.contracts.Detector.detect(context, units) -> DetectorRun`，
> 版本为 `0.2.0-proposed`。所有 finding 都是 syntax-level
> `candidate/unassessed`；`completed` 仅表示所选 scope 被执行，不表示 safe。
> `partial/failed/blocked/not_run` 是 unknown 或覆盖不足，不是 miss；
> unsupported language 是 `not_applicable`，也不是 miss。

## 1. 精确检测语法形状

当前规则只组合以下词法事实：

1. 类/结构体数据成员声明形如 `std::shared_ptr<T> name;`（允许 `static`
   前缀和简单初始化）。类外/global `shared_ptr` 不属于本规则，显式记录
   `not_applicable`，不再以 `class_name=None` 误绑定同名局部或成员；
2. 同一成员名只有在能绑定到同一 namespace + class owner 时才分析。绑定
   依据包括 inline member function、`Owner::Function`、`Owner::name` 和
   `this->name`；local declaration/shadowing 会遮蔽同名成员；
3. global、不同 class、不同 translation unit 的同名对象不会跨作用域绑定。
   经未解析对象表达式访问的同名成员保持 `unknown`，不当作 safe；
4. 纯 `atomic_load(&name)` / `atomic_store(&name, ...)` access set 不生成
   非原子 candidate；
5. mutex 只有在本 translation unit 中所有可归因的非原子访问都位于可靠
   RAII scope、且这些 scope 共享至少一个相同 mutex 时才抑制 candidate。
   `try_to_lock`、`defer_lock`、不同 mutex、单侧加锁、手工 lock API 和
   未解析锁身份不会抑制 candidate；
6. atomic 与 mutex 路径分开建模；混合路径不生成非原子 candidate 的前提仅是
   非原子访问集合满足上述共同锁条件，limitation 仍明确这不是完整并发证明；
7. 同一成员 occurrence 不在可建模函数 span 中且不能判定为声明/qualified
   definition 时，覆盖状态降为 `blocked/unknown`。

这是正则语法切片，不是完整 C++ parser、CFG、数据流、锁语义、类型系统或
跨线程 interleaving 分析。共同 lexical mutex、atomic API 和 owner binding
都只是窄范围抑制/归属证据，不是同步或安全证明。

## 2. 必要条件与判定边界

### 2.1 生成当前 candidate 的必要事实

- 显式 `std::shared_ptr<T>` class/static data member 声明；
- 该成员在函数体中的非原子 occurrence；
- occurrence 通过 namespace/class owner、qualified access 或 `this->`
  唯一绑定到该成员，且不被同名 local declaration shadow；
- `file/line/column/rule_id/evidence_type/candidate_cwe/symbol` 和 `SourceUnit.sha256`
  完整绑定（源码 hash 通过 review sidecar 绑定）。

这些是规则 shape 的必要条件，不是漏洞成立的充分条件。规则不证明对象一定
析构、入口一定可达、调用者一定可控、锁一定保护/未保护、或存在安全影响。

### 2.2 只能保持 unknown 的情况

- `parse_status=partial/failed/not_run`；
- 通过 unresolved object expression 访问同名成员；
- `try_to_lock`/`defer_lock` 等条件或延迟加锁状态；
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
| vulnerable | `vulnerable_one_sided_mutex.cpp` | complete | 未加锁一侧 candidate |
| vulnerable | `vulnerable_different_mutexes.cpp` | complete | 不同锁不互相抑制 |
| fixed | `fixed_atomic_shared_ptr.cpp` | complete | 当前规则无 finding |
| safe | `safe_atomic_only.cpp` / `safe_atomic_helper.cpp` | complete | atomic API path 无 finding |
| safe | `safe_same_mutex_shared_ptr.cpp` | complete | 共同 mutex 抑制 |
| safe | `safe_atomic_mutex_mixed.cpp` | complete | 无非原子 finding，保留 mixed limitation |
| unrelated | 2 个 plain-pointer/local fixtures | complete | 当前规则无 finding |
| unknown | partial / failed / not_run / incomplete scope | mixed | blocked/unknown |
| unknown | `unknown_try_to_lock_shared_ptr.cpp` | complete | conditional lock 不抑制且 coverage blocked |
| not_applicable | `not_applicable_global_shared_ptr.cpp` | complete | global 不属于 member rule |
| not_applicable | `not_applicable_no_matching_language.js` | complete | no matching language |

review evidence 必须按 `vulnerable/fixed/unrelated/safe/unknown/not_applicable`
分组运行；这些 evidence class 不得混成一个结果。safe/unrelated/fixed fixture
即使 `completed` 且无 finding，也只能记录“该 selected scope 未观察到当前
shape”，不能记录 safe verdict。

## 4. 覆盖与失败状态

- vulnerable development group：3 complete units，覆盖基础 shape、单侧 mutex
  和不同 mutex；
- fixed development group：1 complete unit，当前模式 0 candidate；
- safe development group：4 complete units，覆盖 pure atomic、共同 mutex 和
  mixed atomic/mutex narrow suppression；
- unrelated development group：2 complete units，当前模式 0 candidate；
- unknown group：6 units，覆盖 partial、failed、not_run、incomplete scope 和
  `try_to_lock`，run 保持 `blocked/unknown`；
- not_applicable group：2 units，分别覆盖 global shared_ptr rule mismatch 和
  no matching language；
- exception/invalid input 由 deterministic tests 隔离为该 detector 的
  `failed` 或显式拒绝，不转换为 miss；review sidecar 对越界 line/column、
  stale source hash 和非对象 metadata 显式拒绝。

这些是 fixture behavior 和覆盖状态，不是准确率结论；不计算 Precision/Recall。

## 5. 算法

1. 保持偏移量地屏蔽 comment/string/char literal；
2. 识别 namespace/class/function/block span、local shared_ptr binding、
   RAII lock declaration scope 和 class member declaration；
3. 为每个 shared_ptr member 绑定 namespace-qualified class owner，显式排除
   global declaration，并处理 qualified access、`this->` 和 local shadow；
4. 将成员 occurrence 分为 atomic / non-atomic，按 translation unit 聚合到
   同一 member identity；
5. pure atomic access set 不生成 candidate；否则仅当全部 non-atomic access
   共享可靠共同 mutex 时抑制；
6. 对未共同加锁集合优先报告 unprotected non-atomic access；若全部访问位于
   不同锁下，则报告全部 non-atomic accesses；conditional/deferred lock 使
   coverage 降为 `blocked/unknown`；
7. 未解析 object member access、缺失 symbol、unbalanced syntax 或不可建模
   span 使 coverage incomplete，不转换为 safe；
8. 按 `(file,line,column,rule_id,message)` 折叠重复 identity 并稳定排序。

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

- namespace/class/function owner 仍由 lexical span 和简单 qualifier 解析得到，
  alias、macro、typedef、继承和复杂 declarator 可能破坏归属；
- unresolved object member access 会被保留为 unknown，无法进一步区分具体
  instance、base class 或 wrapper object；
- 锁 scope 只按 RAII declaration 的最内层 brace span 和构造参数中的 mutex
  identifier 近似；手工 lock/unlock、condition variable、atomic flag、
  读写锁和跨函数 mutex 摘要未建模；
- 共同 lexical mutex 的抑制只覆盖本 translation unit 的可归因 non-atomic
  access，不证明所有线程、函数、别名或析构路径都遵守同一同步协议；
- pure atomic path 与 mixed atomic/mutex path 按窄规则分开处理；后者保留
  limitation，但不能当作完整 C++ memory model proof；
- control flow、early exit、exception、lambda capture、跨函数 return/escape
  不会改变 RAII scope 的近似边界，也不会提供 guard dominance proof；
- 简单 `Class<T>::method` owner qualifier 会规范化模板名，但模板参数语义、实例化、宏展开和真实 product build 未建模。

以上来源可能使当前语法 shape 与真实并发语义不一致。

## 8. 已知漏报来源

- global shared_ptr 是本规则明确 `not_applicable`，不会作为 member-race
  candidate；如需 global race 检测必须另设规则 ID、对象绑定和证据合同；
- `std::shared_ptr` 通过 typedef、template、member wrapper 或非简单声明出现；
- 成员名不是简单 identifier，或声明带复杂 declarator/initializer；
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
| synthetic fixture manifest | `verify_shared_ptr_race_fixtures.py` 通过，18 units |
| synthetic fixture full run | `shared_ptr_race_fixture_evidence.py` 确定性输出，Runner status `blocked` |
| real-source native evidence | draft-bound rerun：vulnerable `completed` / 2 findings；fixed `completed` / 0 findings；binding manifest 尚未独立 pin |
| M1 Git-object integration | 本地临时 Git repo 两个 commit，vulnerable/fixed 分离运行通过 |
| 完整测试 | 254 项通过（本轮最终复测） |

这些是当前 fixture/runner/evidence 回归事实，不是漏洞准确率或安全结论。

## 10. Provenance 与许可证

代码、fixtures、方法、CCR 和测试均为本分支自建；未复制第三方规则或查询。
真实 OpenHarmony 源码只在隔离临时目录按 exact commit 获取、哈希绑定，
Apache-2.0 upstream source bytes 不提交仓库，保留 upstream header/notice。
正式 detector 路径不启动 Semgrep、Cppcheck、Clang SA、CodeQL、Joern，也不
生成 exploit/PoC、编译产物或数据库。
