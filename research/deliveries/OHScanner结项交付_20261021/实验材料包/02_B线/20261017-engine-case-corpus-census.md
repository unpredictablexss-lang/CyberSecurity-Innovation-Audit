# 交付项 13：五种引擎用例在真实语料里的出现与触及

> 只读测量。仪器 `research/deliveries/ipc/engine_case_corpus_census.py`。
> 本文全部数字由该仪器一次运行产出，可用 §6 的命令复现。
> 任何数字都不是漏洞结论：形状是候选的必要条件而非候选，候选也不是漏洞。

## 0. 结论

交付项 12 的 §10 第 4 条留下的是这句：「**未做**在真实组件语料上复测本次新增夹具所
覆盖的五种模式」。这一步补上它，答案分三层，逐层比上一层弱：

1. **形状存在性**：五种模式里有三种在真实语料里大量存在，一种几乎不存在，一种完全
   不存在（§2）。S3（本地同名复核谓词）21 个文件、S5（能力导出调用）503 处 /
   132 文件，都是真实形状；S1 的 `const MessageParcel &` 全语料只有 6 处、集中在 4 个
   mock 副本头文件里，而且不是入口参数；S4 夹具那种「宏即类名」形状**一处都没有**。
2. **是否触及候选**：把 42 份已保存报告里的 179 条候选与形状文件集相交，只有 S1 的
   可变形式和 S5 命中了候选（114 条 / 81 条）。S3、S4、S1 的 const 形式在候选上
   **零触及**——形状真实存在，但没有影响到这一批候选（§3）。
3. **引擎的 case 级推理不落盘**：一跳成功/拒绝、非唯一拒绝、同名遮蔽这些句子由
   `IpcInterfaceDetector.detect(...)` 产出，**一条都没进已保存报告**；报告只带每条
   候选的溯源（状态/解析深度/来源绑定），不带为什么被采信或被拒绝（§4）。

因此本文加强的是「这些夹具不是对着空气写的」，**不是**任何一条候选的真实性。
夹具覆盖的形状在真实语料里存在，是夹具作为设计控制的前提被满足；零触及说明这些用例
在本轮 179 条候选上还没有付费，两者都不是候选升级的理由。

## 1. 方法

- 语料：`/home/audit/corpus-ipc-bline`（12 组件）、`corpus-ipc-shape`（12）、
  `corpus-ipc-widen`（8），共 32 个组件，`-I` 只读读取，不写任何产物。
- 报告：`/home/audit/wtmp/ipc-audit-all`（42 份）与 `ipc-audit-bline`（12 份），按
  `(repository, commit)` 去重后是 **42** 份（12 份重复文件被跳过，不再重复计数）。
- 作用域口径：整语料普查按**整段目录名**排除 `test/tests/unittest/fuzz/mock/samples/
  example/demo/benchmark/third_party/...`，用的是本车道已建立的
  `widen_shape_census.py` 里那份清单，两次普查因此可比。这是分段规则：`rdbmock/`
  不等于段名 `mock`，它和 `kvstoremock/` 都**存活**，§5 用已保存的计划回查了这一点，
  而不是靠清单推断。
- 工具链：按 `models.py` 的确切名单取被复核的调用者角色谓词（9 个），并记录读取到的
  `models.py` 的 sha256（`ad3d0498fcbc895dbc05f09f67e12dbb34b615c02026b570ab7f8b16003df124`），
  使名单有出处。
- 一句必须说的口径：语料读的是各组件的工作树，不是那次审计所钉 commit 的 blob。语料在
  审计后动过的组件，其形状会被记到较新的树上。
- 宏形状（S4）的表是先对**整语料**收集宏名、再扫正文的两遍法。单遍法下，一个在定义宏的
  头文件**之前**被遍历到的 `class Stub` 不会被数到，§2 的那个零就可能是遍历顺序的产物；
  改成两遍后 `Name::` 使用数由 4 升到 5，即顺序敏感确实存在，而「与夹具同形」仍是 0。

## 2. 五种模式 × 真实语料

`B_IPC.md` 验收第 2 条点名的五种模式，逐条给出语料侧的实测：

| # | 模式（验收第 2 条） | 夹具侧（交付项 12） | 语料侧实测 | 读法 |
|---|---|---|---|---|
| 1 | const 引用入口 | `auth02/entry_const_reference_positive.cpp` 与 `entry_reference_positive.cpp` 的不变量对 | `const MessageParcel &` **6** 处 / **4** 文件；可变形式 **14561** 处 / 917 文件 | 真实入口一律写作可变引用，const 形式不是入口形态 |
| 2 | 非唯一宿主方法 | `cap01/onehop_not_unique_positive.cpp` | 定义名 **51340** 个，其中同名多宿主 **12463** 个（驼峰无下划线 **12424**） | 「同名多定义」是语料的常态而非角落，代理结论，见下 |
| 3 | 一跳被拒的传播 | `cap01/onehop_ungated/credited/macro_*` 与 `onehop_not_unique_positive.cpp` 的拒绝句 | 导出调用点 **503** 处 / **132** 文件 | 只量到「该用例所谈的操作」存在，一跳结构本身未量 |
| 4 | 本地遮蔽的复核角色谓词 | `auth02/caller_role_shadowed_positive.cpp`（成员）与 `..._free_predicate_positive.cpp`（文件作用域） | 成员定义 **15**、文件作用域定义 **6**、声明 **16**，共 **21** 文件 | 真实存在且以成员形式为主；正文抽取口径见下 |
| 5 | 非零行号 | 全部正例钉住 `(rule, line, construct)` | 179 条候选里行号不是 `int ≥ 1` 的：**0** | 与 `contracts.py:125-126` 的口径一致 |

两条代理/口径说明，写在数字旁边而不是脚注里：

- 第 2 行的 **12463** 是代理值：它数的是「`类型 Owner::名(` 形状的异类定义名有 ≥2 个
  宿主」，其中也包含**静态数据成员的定义**——实测样本
  `const std::string DistributedWant::ACTION_HOME("action.system.home")`
  （`ability_dmsfwk/.../distributed_want.cpp:53`）就是这样被数进去的，它不是可调用名。
  因此仪器另报一列「驼峰且不含下划线」= **12424**，二者都只是「一跳被拒」的**必要条件**
  计数，不是拒绝次数。真正的拒绝次数要看引擎，而引擎的拒绝句不落盘（§4）。
- 第 4 行的成员/文件作用域拆分是**文本口径**：仪器把「写成 `Owner::名` 的定义」算成员，
  把「无限定符且不以 `;` 结尾」算文件作用域定义。在 `.cpp` 里写在类体内的成员函数没有
  限定符，会被算进文件作用域一列（实测样本
  `ability_ability_runtime/frameworks/native/ability/native/form_runtime/js_form_extension_context.cpp:101`
  的 `bool CheckCallerIsSystemApp() const`）。引擎内部是按符号表分的，文本分不出来。
  可辩护的是**不分列的总数（21 文件）**，拆列只作指示。

第 3 行的样本也一并说清：6 处 const 形式全部落在 `rdbmock/external_inner_kit/…` 与
`kvstoremock/external_inner_kit/…` 两份 mock 副本里，函数是
`PreSendRequest` / `PostSendRequest` / `WriteTransaction`（`api_cache_manager.h:38,40`、
`binder_invoker.h:180`），是 proxy/kit 侧的签名，**不是** `OnRemoteRequest` 这类入口。
也就是说：夹具钉的不变量（const 引用入口与引用入口读作同一个入口）在语料侧没有被行使，
因为语料里根本没有以 const 形式接收 parcel 的入口。

除验收点名的五种之外，交付项 12 还提交了两个由本车道自己发现的边界，其中
「宏即类名」的语料侧实测也在这里：

| 形状 | 语料侧实测 | 读法 |
|---|---|---|
| 对象宏作为类名（`class Stub` + `#define Stub <真名>`） | 对象宏 **4746** 个，其中展开为单个标识符的 **227** 个，被 `class/struct` 声明的 **6** 个，以 `Name::` 形式被使用的 **5** 个 / 10 文件，**与夹具同形的 0 个** | 语料里出现在类头位置的是 6 个可见性/导出属性宏（`ABILITY_EXPORT`/`API_EXPORT`/`BLUETOOTH_API`/`CJ_EXPORT`/`DLL_EXPORT`/`FFI_EXPORT`），它们的展开不止一个 token，不是重命名 |

结论按实说：夹具那种「宏重命名了类名」的形状，在这三个语料里一处都没有；本车道为它
提交的控制（`onehop_macro_renamed_stub_positive.cpp` 及同目录控制）保护的是一个语料里
不存在的形状。它仍然是有效控制（引擎确实会因此拒绝绑定分发处理器），但它不是**真实
代码里会遇到的**控制。

## 3. 触及候选：形状 × 179 条候选

42 份去重报告共 **179** 条候选；其中 **32** 个组件在本地有语料树，覆盖 **114** 条候选，
其余 10 个组件（65 条候选）没有本地树可交，不能参与本节。

| 形状文件集 | 命中的候选数 | 命中文件数 / 形状文件数 |
|---|---:|---:|
| S1 parcel 绑定（任一形式） | 114 | 33 / 917 |
| S1 parcel 绑定（const 形式） | **0** | 0 / 4 |
| S3 本地复核角色谓词 | **0** | 0 / 21 |
| S4 对象宏作类名 | **0** | 0 / 170 |
| S4 重命名宏作类名（与夹具同形） | **0** | 0 / 0 |
| S5 能力导出调用点 | 81 | 12 / 132 |

读法：

- 114 条候选与 S1 的形状文件集重合，不是「parcel 形状导致了候选」——可变引用是 IPC
  入口的写法，它出现在**几乎每个** stub 文件里，这条重合因此接近同义反复，它的用处是
  给出候选所在文件的分布（`ability_ability_runtime` 48、`bundlemanager_bundle_framework`
  29、`systemabilitymgr_samgr` 9）。
- 81 条候选在 12 个导出调用文件里，集中在同两个组件（`ability_ability_runtime` 43、
  `bundlemanager_bundle_framework` 26）。CAP-01 的用例在候选上是**有付费的**。
- S3 与 S4 是零触及，而它们的形状文件都在已保存的计划里（§5），所以这两个零不是
  「形状不在扫描范围」造成的，而是「这一批候选没有一个落在那两类文件上」。用交付项 4
  的说法：这是一个有分母的 0。

## 4. 报告侧：候选集怎么来的，以及引擎推理为什么不落盘

42 份报告、179 条候选的构成：

| 目录规则 | 候选数 |
|---|---:|
| `ipc.relay.descriptor-boundary`（AUTH-01） | 103 |
| `ipc.capability.export`（CAP-01） | 44 |
| `ipc.auth.missing`（AUTH-02） | 21 |
| `ipc.auth.guard-coverage`（AUTH-04） | 8 |
| `ipc.auth.object-owner`（AUTH-03 之一） | 2 |
| `ipc.parcel.copy-range`（DATA-01 之一） | 1 |
| `ipc.auth.caller-class` / `identity-domain` / `request-identity` / `service-identity` / `ipc.parcel.position-underflow` | **0** |

**11 条目录规则里 5 条在 42 个组件上是零。** 这与交付项 12 的关系要说清楚：那一轮把
AUTH-02/AUTH-04/CAP-01 的家族目录补齐，使六个族各自持有自己的负证据，靠的是**夹具**；
本节说明的是这些规则在**本轮语料**上的产出分布——AUTH-03 的分支规则与
DATA-01 的 `position-underflow` 在这批组件上一条都没产出。零候选不等于组件安全，
但也说明：为它们提交的夹具目前没有真实语料上的对应产出可以对齐。

候选的来源构成（`file_analysis_status` 与 `file_parse_status`）：

| 维度 | 计数 |
|---|---|
| `file_analysis_status` | `analyzed` 89 / `not_analyzed` **90** |
| `file_parse_status` | `complete` 89 / `partial` **90** |
| `passes` | 仅 `all-files` **90** / 两份 `all-files,complete-ast` 88 / 仅 `complete-ast` 1 |
| 有 blocked 分片的组件 | **42 / 42** |

**一半候选（90/179）来自 complete-ast 那一遍没有分析到的文件，且解析深度是 partial。**
报告本身把它们保留并逐条标注（这与 AGENTS「保留合法 partial 候选并独立于整体 blocked
状态」一致），本节只是把这个比例说清楚：本批次候选集的一半，其证据强度是
「all-files 一遍 + 部分 AST」，读这批候选时必须带上这个前提。另外 42 个组件**每一个**
都有 blocked 分片——即 `all-files` 那遍在两处都判为 blocked（见交付项 12 §8 记录的
`'partial' != 'blocked'` 断言分歧）。

**引擎的 case 级推理不落盘。** 对全部 54 份报告文件（含 12 份重复）逐字段搜索七个
case 标记（`one-hop`、`Cross-TU`、`not unique`、`credited`、`shadow`、`Dispatch handler`、
`caller-role`），命中 **0**；`limitations` 字段在每份报告里都是**同一组 10 条固定字符串**
（42×10，逐条相同），不是该次运行的推理。而同一批句子在进程内是存在的：本车道的
深度单测通过 `IpcInterfaceDetector().detect(...)` 的 `run.limitations` 读到它们（交付项
12 的 `EngineCaseCoverageTests` 就是靠这个断言两侧）。也就是说**一跳采信/拒绝、非唯一
拒绝、同名遮蔽这些句子，取决于驱动怎么读，而不在持久化产物里**。

这条不是本车道的修改对象：报告面属于 owner/共享面（`src/report/`），本车道只记录
现象与后果。后果是具体的：下游只拿 `report.json` 的读者，看不到「这条候选为什么被
采信」或「为什么这条一跳没被采信」，只能看到每候选的溯源字段。是否要把 case 级句子
写进报告，是共享面的决定。

## 5. 形状文件是否在已保存的计划里

上一节的零要成立，得先证明形状文件在扫描范围内。仪器直接回读每份报告的
`scope.shards[].paths`，与形状文件集逐条求交：

| 形状文件集 | 在已保存计划内 | 在计划里没被点名的 | 组件无已保存报告 |
|---|---:|---:|---:|
| S1 const 形式（4 文件） | **4** | 0 | 0 |
| S3 本地复核谓词（21 文件） | **21** | 0 | 0 |
| S4 对象宏作类名（170 文件） | **170** | 0 | 0 |
| S5 能力导出调用（132 文件） | **132** | 0 | 0 |

这同时回答了写作过程中出现的一个具体疑问：`rdbmock/`、`kvstoremock/` 这类目录名
**不**被生产段规则排除（规则要求整段等于 `mock`），实测这两个组件（
`distributeddatamgr_relational_store` 计划 921 / 审计 921、
`distributeddatamgr_kv_store` 计划 1446 / 审计 1446）的计划里确实点名了这 4 个文件。
所以 §2 第 1 行的 6 处 const 形式是**范围内**的实测，不是范围外顺带看到的。

## 6. 复现

```
cd /home/audit/ohscanner/worktrees/parallel-ipc-20261017
.venv-web/bin/python -I -u research/deliveries/ipc/engine_case_corpus_census.py
```

`-I` 与语料普查的既有约定一致（语料是不认识的第三方源码）。仪器只读、只打印，
不写任何产物，无参数即使用 §1 列出的三条语料与两处报告树；`--root` / `--reports`
可重复指定别的路径。上表所有数字来自同一次运行的 A/B/C/D 四节输出。

## 7. 未做与开放项

1. **by-value 返回那条边界仍未定**（交付项 12 §5）：本次没有给它任何语料侧证据。
2. **一跳结构本身没量**：§2 第 3 行量的是导出调用点（用例所谈的操作）存在；
   「这个调用点是不是经由一跳到达」需要入口索引，语料侧没有量。
3. **本车道当前修订里没有那份生产段排除清单**：已保存 42 份报告的作用域计划来自
   pinned 修订（`635b3e0` 的 `src/ohscanner/detectors/interface/audit.py:122`，
   `PRODUCTION_EXCLUDED_SEGMENTS`）。在本 worktree 的当前修订里，`src/` 下搜不到
   等价清单（`families/` 只有族适配），所以从当前修订驱动的一次运行会在别处推导作用域。
   这**不是**缺陷判断（批量 run 用的是 pinned 仓库，作用域面在并行会话的改动里可能已
   迁到共享面），是一条要点名的开放项，留给集成方/并行会话确认。
4. **语料读的是工作树**：与那次审计钉的 commit 可能不一致（§1）。
5. LLM/Agent 层准入边界未变：本文是只读测量，不构成 PoC 或漏洞升级。

## 8. 本次提交

仅本车道自己的路径：新增本文件与
`research/deliveries/ipc/engine_case_corpus_census.py`，并更新
`20261017-lane-delivery-record.md` 的文件清单与未验证项。未改任何检测器文件、
未改共享 manifest、未 push/PR/merge，候选/`validated_vulnerability` 一律不变（仍为 0）。
