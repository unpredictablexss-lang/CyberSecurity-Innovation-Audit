# 交付项 17：B 线新增四个家族（Parcel 边界/生命周期、身份流、敏感数据流）与 54 组件实测

> 本项回应 `/goal` 的最后一句："以你最后实际情况为准地达到 B 线功能目标"。
> 对应差距审查文档 §6 的 **B-0 / B-1 / B-2**。本项只改 `src/ohscanner/detectors/interface/**`
> 与 `tests/**`，不触碰 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、
> `src/evidence/`；没有 `git fetch`，没有写入任何语料克隆，没有删除负结果，没有为了降低
> 候选数加入白名单。

## 0. 一句话结论

检测器从 **0.8.1 / `oh-ipc-2026.10-v7`** 升到 **0.9.1 / `oh-ipc-2026.10-v10`**，新增
**5 条规则、4 个族**：`ipc.parcel.bounds`、`ipc.parcel.write-bounds`（DATA-02，CWE-20）、
`ipc.parcel.lifecycle`（DATA-03，CWE-416）、`ipc.auth.flow`（AUTH-05，CWE-863）、
`ipc.data.sensitive-flow`（DATA-04，CWE-200）。0.9.1 另外补三件事：**限定名跨文件**解析
（B-0 要求"避免仅 `f.file==fn.file` 导致静默"）、把"符号没有值"与"值有、但无审阅
账户归属"拆成两种候选陈述，以及为 B-2 的**跨服务代理链**保留身份变更点（`iface_cast<>`
句柄上的调用被记录为边界，并记录跨过去的是调用者身份还是服务自身身份）。在 54 个固定组件、31,225 个入选文件、24,151 个完整 AST 上实测：
**新增规则只有 `sensitive-flow` 发射 1 条候选，其余四条为 0**；四个零各有**插桩计数**
解释，不是"规则应该没问题"的推断。唯一的候选经固定源码复核后**保留为 candidate**：它命中
的是一个真实存在、值可解析、但策略里没有审阅账户归属的调用者 UID 守卫。

## 1. 改动面与版本

| 项 | 内容 |
|---|---|
| detector | `ohscanner.interface.ipc` **0.9.1** |
| model | `oh-ipc-2026.10-v10`（v9 之上新增 `forwarded` 身份事实与 `proxy` 句柄值） |
| 新增规则 | `ipc.parcel.bounds`、`ipc.parcel.write-bounds`、`ipc.parcel.lifecycle`、`ipc.auth.flow`、`ipc.data.sensitive-flow` |
| 新增族模块 | `families/data02.py`、`data03.py`、`auth05.py`、`data04.py` |
| 语义改动 | Parcel API 参数位置（`ReadRawData(dst,size)` 用第 2 参）、目的容量匹配、parcel view 失效、身份丢弃、敏感结果写入 reply；守卫陈述区分"无值"与"有值未审阅" |
| 解析改动 | `functions_by_file_name` 索引查找；`resolve` 增加**显式限定名**的跨文件解析（唯一匹配才接受） |
| 测试 | 615 通过 / 4 skipped；新增 24 条数据流语义测试、4 条跨文件解析测试、2 条 system-app 谓词测试、7 条跨服务边界测试、3 条入口覆盖记录测试 |

规则 ID 与差距文档的对应：`ohscanner.oh.parcel.bounds` → `ipc.parcel.bounds`（以及
`write-bounds` 为写入侧的独立 ID）、`ohscanner.oh.parcel.lifecycle` → `ipc.parcel.lifecycle`、
`ohscanner.oh.auth_flow` → `ipc.auth.flow`、`ohscanner.oh.sensitive_data_flow` →
`ipc.data.sensitive-flow`。**没有改 Catalog ID / 结果语义**；是否在 `main` 的 Catalog 里
登记这些 ID 属于 owner 的决定，本 lane 不单方面做。

## 2. 语料与口径

54 个干净组件，六个 audit 根（`perf-corpus` 10、`corpus-ipc-widen` 8、`corpus-ipc-shape` 12、
`corpus-ipc-bline` 12、`corpus-ipc-extra` 7、`corpus-ipc-batch3` 5），全部是 2026-10-17 的
`master` 快照，逐组件记录 `commit`（见 `candidates.json` 的 `components[].commit`）。
`applications_permission_manager` 只有 ArkTS/资源文件，没有 C/C++ 单元——它不是"0 候选"，
而是 **`0` 个适用单元**，单列在 `no_applicable_units`。

测量走 **直接固定树**（`bline_direct_measure.py`）：用 `git ls-tree -r -z` 枚举固定 commit，
`git cat-file blob` 读取，构造 `SourceUnit` 后交给检测器。原因：生产入口
`src/ohscanner/git_source.py:143` 的 M1 上限会拒绝大于 2000 文件/大字节的组件
（`ability_ability_runtime`、`window_window_manager` 等在 CLI 路径上直接失败）。直接树是
**测量路径，不是生产路径**，它没有 include 过滤，入选文件数与 CLI 略有差异。

两个 pass，与既有 pinned driver 一致：

| pass | 单元 | 状态 | 候选 |
|---|---|---:|---:|
| `all-files` | 完整 + 部分 AST | `blocked`（保留候选） | **337** |
| `complete-ast` | 仅完整 AST | `completed` | **183** |

`all-files` 是 `complete-ast` 的超集；两者不是相加关系。**154 条候选只出现在部分 AST 里**，
其中包含既有规则 `object-owner`（2）、`guard-coverage`（9）、`copy-range`（1）的全部发射。
因此"某个规则为 0"必须说明是哪个 pass。

**口径更正（必读）。** 0.9.0 定稿前的中间构建曾在同一语料上给出 `all-files` 265 /
`complete-ast` 141，并与更早的 CLI 表 264 相互校验；**提交后的 0.9.0 代码在同一批固定
commit、同样 31,225 个入选文件上给出 337 / 183**。差异来自两次测量之间对 relay/描述符
路径的修改，不是测量脚本或语料的差异（入选文件数、完整/部分 AST 数逐组件一致）。本表、
`candidates.json` 与下文所有数字都以**提交代码的实测**为准；265/141 那张表已被本表取代，
不再作为当前结论引用。

## 3. 逐规则实测

### 3.1 新增规则

| 规则 | CWE | complete-ast | all-files | 命中组件 | 控制（正/修/安全） |
|---|---|---:|---:|---:|---|
| `ipc.parcel.bounds` | CWE-20 | 0 | 0 | 0 | 1 / 1 / 1 |
| `ipc.parcel.write-bounds` | CWE-20 | 0 | 0 | 0 | 1 / 1 / 0 |
| `ipc.parcel.lifecycle` | CWE-416 | 0 | 0 | 0 | 1 / 1 / 1 |
| `ipc.auth.flow` | CWE-863 | 0 | 0 | 0 | 1 / 1 / 1 |
| `ipc.data.sensitive-flow` | CWE-200 | **1** | **1** | 1 | 1 / 1 / 1 |

控制由 `tests/fixtures/ipc/manifest.json` 登记，`family`/`variant`/`expected_rule` 三者由
`test_ipc_family_depth.ManifestContractTests` 强制一致（`positive ⟺ expected_rule 非空`）。

### 3.2 既有规则（同一语料、同一模型）

| 规则 | complete-ast | all-files | 命中组件（all-files） |
|---|---:|---:|---:|
| `ipc.relay.descriptor-boundary` | 143 | 238 | 18 |
| `ipc.auth.missing` | 16 | 27 | 9 |
| `ipc.auth.object-owner` | 0 | 2 | 1 |
| `ipc.auth.guard-coverage` | 0 | 9 | 3 |
| `ipc.capability.export` | 23 | 59 | 8 |
| `ipc.parcel.copy-range` | 0 | 1 | 1 |
| **`ipc.data.sensitive-flow`** | **1** | **1** | **1** |
| `caller-class` / `identity-domain` / `service-identity` / `request-identity` / `position-underflow` | 0 | 0 | 0 |

`complete-ast` 下仍在发射的规则是 4 条（AUTH-01、AUTH-02、CAP-01、DATA-04）；其余规则的
全部候选依赖部分 AST。

## 4. 四个零分别意味着什么（插桩，不是推断）

`bline_rule_probe.py` 包装分析器的决策点并计数；它不改变任何候选（每个包装都调用原方法）。
`bline_shape_census.py` 在同样的 54 个固定树上做文本上界普查。两者一起区分
"语料里没有这个形状"和"形状在，但入口路径没有走到"。

| 计数 | 值 | 含义 |
|---|---:|---|
| `index_sites` | 88 | 入口可达函数里被求值的下标站点 |
| `index_request` | **0** | 其中下标来自 request parcel 的站点 |
| `index_capacity_known` | **0** | 其中被索引缓冲区容量在源码中声明的站点 |
| `dest_sites` | **0** | 入口路径上到达的 `ReadRawData(dst,size)` 站点 |
| `invalidations` | **0** | parcel 上的失效调用（`Reuse`/`RewindRead`/`SetReadPosition`/`Seek`） |
| `views_invalidated` | **0** | 被失效操作命中的活动 view |
| `reset_actions` | **0** | `ResetCallingIdentity` 之后到达的建模敏感操作 |
| `reply_writes` | 3,305 | reply parcel 上的写入 |
| `disclosure_writes` | 6 | 写入的实参是披露类调用结果 |
| `actions` | 53 | 建模敏感调用 |
| `resolve_calls` | 25,221 | `resolve()` 调用次数（含新读到的跨文件函数体内部） |
| `resolve_cross_file` | 158 | 其中命中另一文件定义的次数 |
| `proxy_boundaries` | 10 | `iface_cast<>` 句柄上的调用（跨服务边界；全部在 `bundlemanager_bundle_framework`） |
| `proxy_boundaries_forwarded` | **0** | 其中显式转发调用者身份的边界 |

0.9.1 的探针数字相对 0.9.0 只在这几处变化：`resolve_calls`（新增计数）、
`index_sites` 87→88、`reply_writes` 3,265→3,305（`graphic_graphic_2d` +40），
以及新增的边界计数。`resolve_calls` 相对引入边界记录前的 25,384 少 163，正好是
`iface_cast` 调用数（110+10+34+9，分布在四个组件）：这些调用现在在 `value()` 里直接
返回 `proxy` 句柄，不再走普通 callee 解析。原因是被跨文件解析读到的函数体里还有站点，
属于**覆盖增加**；
所有 `**0**` 计数保持为 0，候选身份也逐条未变（见 `delta_v8_to_v9.json` 与
`probe_delta_v8_to_v9.json`）。边界计数为 10 且全部为 `service`：这批组件里
`iface_cast` 之后的跨服务调用没有一处显式转发调用者身份。

文本普查（54 个组件合计，**上界，不是可达性**）：

- `ReadRawData(` 163 处，`ReadBuffer(` 89 处，`ReadInt32(` 8,622 处；
  但入口可达函数里没有一处把 request 派生长度传给 `ReadRawData`，也没有一处用
  request 派生下标去索引一个容量已声明的局部缓冲区。**`bounds`/`write-bounds` 的零是
  "入口路径上没有该形状"，不是规则不能发射**——两者都有正/修复控制。
- `Reuse(` **0** 处；`RewindRead(` 32 处、`SetReadPosition(` 2 处、`Seek(` 152 处。
  后三者在这批组件里没有落在"先取 view、后失效、再读 view"的同一条入口路径上，
  所以 `views_invalidated` 为 0。**`lifecycle` 的零是覆盖/形状事实**；`Reuse` 在本版
  OpenHarmony 的接口头里也未出现，fixture 另有一条 `RewindRead` 的正控制，
  不依赖不存在的 API 才能证明规则会发射。
- `ResetCallingIdentity(` 313 处，`SetCallingIdentity(` 380 处；**裸调用
  `ResetCallingIdentity();`（返回值被丢弃）0 处**。这批组件全部是"保存—恢复"协议，
  因此 `auth.flow` 的两个前提（先有守卫、后丢弃身份）在语料里同时成立 0 次。
  **它的零是"形状不存在"**；规则对"丢弃返回身份 + 先前守卫 + 敏感操作"三条件同时成立的
  正控制仍然存在。

这些计数回答的是 B-0 的要求："保留规则在真实语料中是否实际执行的计数"。候选数为 0 时，
报告里的 `Entry/dispatch coverage:` 一行照常输出（分发器数、绑定 grade、事务解析、
`unresolved_dispatch`、条件绑定数），所以"没有入口"和"有入口但没有绑定/没有候选"
在报告层面可区分。

## 5. 唯一新增候选的源码复核（保留，不升格）

- 组件：`openharmony/security_access_token`@`17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- 位置：`interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp:104`
- 规则：`ipc.data.sensitive-flow`（DATA-04 / CWE-200）
- 路径：`TokenSyncCallbackStub::OnRemoteRequest` → switch `GET_REMOTE_HAP_TOKEN_INFO`
  → `GetRemoteHapTokenInfoInner` → 守卫 `if (!IsAccessTokenCalling())` →
  `result = this->GetRemoteHapTokenInfo(deviceID, tokenID)` → `reply.WriteInt32(result)`
- 守卫体（同文件 `:136-140`）：
  `int callingUid = IPCSkeleton::GetCallingUid(); return callingUid == ACCESSTOKEN_UID;`
  而 `static const int32_t ACCESSTOKEN_UID = 3020;` 在同文件 `:34`。

**判定：候选陈述成立，但它是扫描器的策略边界，不是已证明的未授权读取。** 守卫确实比较了
调用者 UID，且常量值是可读的：分析器用 `EntryIndex.define_constant` 把 `ACCESSTOKEN_UID`
解析到 `static const int32_t ACCESSTOKEN_UID = 3020;`（同文件 `:34`）。缺的不是常量初始化，
而是**审阅过的账户归属**：默认策略的 `service_account_roles` 为空，没有任何一条 reviewed
assignment 声明 3020 属于哪个服务账户、能授权哪些操作。**把"值读不到"和"值读到了但没有
审阅归属" 分开说出来**，是本轮修正的语义：两者都会保留候选，但对源码的陈述不同，前者是
可被复核为假的。候选消息现在写出后者：

> Guard seen, not accepted: the caller identity is compared against ACCESSTOKEN_UID (which
> these sources bind to 3020 at interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp:34),
> but no reviewed account assignment in this policy credits that value, so the comparison
> cannot be credited as authorization.

保留候选、不删除、不加白名单。**它不是漏洞**。注意 `tests/test_ipc_detector.py` 与
`tests/fixtures/ipc/manifest.json` 里已有一个**显式传入 reviewed policy** 的路径：在该路径
下这三处调用被 credit、候选不发射，并明说这是"只有 harness 显式提供策略时才成立"的控制，
默认策略下仍是正控制。同一个账户归属因此有两种可复现口径，本项没有把默认策略改成那种更宽松
的口径。同一组件的 6 次披露结果写入中只有这 1 次没有匹配守卫，另外 5 次路径上存在可识别的
权限判定。

## 6. 性能：同文件调用解析改为索引

在 `graphic_graphic_2d`（3,401 个入选文件）上，旧实现的 `resolve()` 与本地函数查找
每次调用都线性扫描全组件的 `self.functions`（该组件数万个函数），单个组件运行 **42 分钟
仍未完成**（同一进程 CPU 满载，faulthandler 栈顶在 `analysis.py:665` 的列表推导）。
加入 `functions_by_file_name` 索引后，同一组件 **83.9 秒**完成，逐规则结果与索引前一致
（当时该构建 83 条候选）。提交版本的同一组件是 all-files **120** / complete-ast **80**，
差异来自两次测量之间对 relay/描述符路径的修改，不是索引改动。54 个组件的最终整轮约
16 分钟。这个优化不改变语义：`resolve` 的同文件分支仍只接受"同文件 + 同 owner + 唯一
匹配"。

## 7. 测试、范围与证据

- `python -m unittest discover -s tests -t tests`：**615 tests，OK（skipped=4）**。
  新增 `tests/test_ipc_data_flow_rules.py`（24 条，钉住参数位置、目的容量匹配、
  view 失效归属、披露写回、身份丢弃/保存、未解析守卫不计数也不谎称无守卫、
  值可解析但无审阅归属时如实陈述、同名本地谓词按函数体解释）、
  `tests/test_ipc_cross_file_resolution.py`（4 条，钉住限定名跨文件解析的四个边界）与
  `tests/test_ipc_dispatch_coverage.py`（3 条，钉住覆盖记录每次都输出、含
  `unresolved_dispatch`、无基类子句的分发器不算 stub）。
- 14 个新 fixture 的正/修复/安全控制（`parcel_*`、`auth_flow_*`、`sensitive_flow_*`）。
- `scripts/check_change_scope.py --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc`：
  **`"violations": []`**。
- 机器可读证据：
  `research/evidence/interface/ipc/bline_rules_20261017/{candidates,probe,shape_census}.json`。
- 复现脚本：`research/deliveries/ipc/bline_{direct_measure,rule_probe,shape_census,aggregate}.py`。

## 8. 没做完、也不能声称的

1. **A 线的 `Bounds/Integer` 事实没有可联动对象**——当前主线没有可用的事实接口，
   `bounds` 只做本地的容量/下界匹配，不做符号执行或位向量溢出证明。
2. **账户归属没有默认审阅记录**：同文件 `static const` 与无参 `#define` 的值**可以**
   解析（`define_constant`），但默认 `service_account_roles` 为空——没有 reviewed
   assignment 时，解析出的值仍不能作为授权事实，候选按"值已解析、归属未审阅"保留。
   默认策略是否应内置某个服务账户的归属属于 owner 决定，本 lane 没有单方面放宽。
   带常量值但无审阅归属的跨文件 `#define` 同理。
3. **跨服务代理链只记录到"我们看见的边界"为止**：0.9.1 起，用 `iface_cast<IFoo>(...)`
   得到的句柄上的调用会被记为跨服务边界，并记录跨过去的是**调用者身份**还是**服务自身
   身份**（见 §10.4）；但接收者来自参数、字段或未建模工厂（`GetProxy`、`CreateProxy`
   之类）的调用**不**被声明为边界，任意深度的链、下游服务的守卫与它自己的授权判定都不读。
   `other->Guard()` 仍刻意不解析。身份变更点是**覆盖记录**，不产生候选，也不把入口守卫
   追认为下游授权。
4. **敏感 source 是一张命名表**（`DISCLOSURE_CALLS`），不是通用 taint；只覆盖
   "披露类结果 → reply"，不覆盖文件、日志、共享内存等 sink。
5. **ArkTS/ETS 与 JS/TS 前端没有实现**（B-3）。`applications_permission_manager`
   在本题语料中就是 0 个 C/C++ 单元；检测器对该组件给出 `blocked` + 无适用单元，
   而不是"扫描通过、无漏洞"。按差距文档 §6 的分工，这属于平台/Codex 建语言框架、
   B 做语义 review 的共享工作，本 lane 没有单方面实现。
6. **没有 PoC**：本项没有做任何动态验证或隔离复现；§5 候选也没有达到可复现条件。
   差距文档 §6 要求的"公开修复前/后真实漏洞对 + 伪造请求负例"仍未选定。
7. **部分 AST 的候选与完整 AST 的候选是两个视图**：124 条只在 `all-files` 中出现，
   不能说成 `completed` 覆盖下的结果。

## 9. 结论口径

337（`all-files`）/ 183（`complete-ast`）条全部是**未验证的静态候选**；
`validated_vulnerability` 与 `confirmed` 均为 0。某个组件为 0 不等于它安全；
一条候选不等于一个漏洞；54 个组件是 2026-10-17 的快照，不代表整个 OpenHarmony。
0.9.1 的跨文件解析在同一语料上使候选数**零变化**（337/183 → 337/183，逐组件逐规则
`changed: []`）；它增加的是被读到的函数体，不是新的判定。

## 10. 0.9.1：限定名跨文件解析，与守卫陈述的二值化

### 10.1 有界跨文件解析（B-0 的"避免仅 `f.file==fn.file` 导致静默"）

`resolve()` 原先只查 `(fn.file, 名字)`。一个写在别的翻译单元里的 `Class::Method()` 因此
读不到函数体：守卫没被读到，条目保持候选。0.9.1 只在调用点**自己已经写出限定名**时放宽：

- 只有带 `::` 的 callee 才可能解析到别的文件；未限定名仍是本文件（或入口索引已建模的一跳），
  **不做按末名搜索**；
- 限定符必须等于定义的 owner，或等于其末段（类内定义：调用写 `NS::Foo::Bar`，定义 owner 是
  `Foo`）；
- 必须**唯一命中**；重载集合、类内外两份定义都保持未解析，不挑一个；
- `other->Guard()` 这类接收者一律不解析——调用点没有说明那个对象是什么。

控制：`tests/test_ipc_cross_file_resolution.py` 四条，正例是"另一文件的限定名守卫被读到，
候选消失"，三条反例分别是"未限定名不借体"、"同名两份定义保持未解析"、"不同 owner 不取"。

**实测效果：零候选变化。** 54 组件、同一 commit 上，0.9.0（`1d47160`）与 0.9.1 的
逐组件逐规则比较为 `337/183 → 337/183`、`changed: []`；探针同时记录到放宽确实在工作
（`communication_ipc` 上 `resolve_calls=61`、`resolve_cross_file=8`）。也就是说，这次改动
增加的是覆盖（读到的函数体），不是判定：没有任何候选因此被 credit 或删除。

### 10.2 守卫陈述：区分"没有值"与"有值但没有审阅归属"

§5 那条候选的守卫比较 `GetCallingUid()` 与 `ACCESSTOKEN_UID`。旧消息写的是"本分析没有把
该符号解析成值"，但 `EntryIndex.define_constant` 实际上能把它解析到同文件 `:34` 的
`3020`——**旧消息对源码的陈述是可被复核为假的**。现在：

- 真的解析不到 → `auth_unknown`，消息写 `does not resolve that symbol to a value`；
- 解析到值、但策略里没有 reviewed account assignment → `auth_uncredited`，消息写
  `these sources bind to 3020 at <file>:<line>, but no reviewed account assignment in this
  policy credits that value`。

两种都**不**把比较计为授权，候选都保留；区别只在陈述是否与源码一致。控制：
`test_a_resolved_constant_without_a_reviewed_account_says_so` 断言消息出现 `bind to 3020`
与 `no reviewed account assignment`，且**不**出现 `does not resolve`；原有的
`test_the_candidate_keeps_the_comparison_it_could_not_read` 继续钉住真正无定义的情形。

### 10.3 证据与口径

本轮证据在 `research/evidence/interface/ipc/bline_rules_20261017_v10/`（与提交代码
同一份）：`candidates.json`（54 组件、0.9.1/v10 实测）、`probe.json`、
`probe_delta_v9_to_v10.json`（四点差异：`iface_cast` 早返回使 `resolve_calls` 少 163，
`bundlemanager_bundle_framework` 记到 10 次边界）、`delta_v9_to_v10.json`
（`337/183 → 337/183`、`changed: []`）、`shape_census.json`（纯文本普查，与检测器语义
无关，语料未变，沿用同一 54 个固定 commit 的结果）。

同目录族里保留两个较早的目录，便于复核而不是覆盖历史：`bline_rules_20261017_v9/`
是加入跨服务边界记录**之前**的 0.9.1 构建（候选相同，探针无边界计数、
`delta_v8_to_v9.json` 记录 0.9.0→0.9.1 的零变化）；`bline_rules_20261017/` 是 0.9.0
定稿前中间构建，其中的 141/265 已被 §2 的口径更正取代。三者都不回溯改写。

### 10.4 跨服务边界的身份变更点（B-2）

B-2 要求"跨服务代理链保留身份变更点"。0.9.1 的实现是有界的事实记录，不是链式追击：

- **句柄怎么认**：只认源码里写出来的 `iface_cast<IFoo>(remote)` 结果。这是这批源码里
  获得类型化代理的标准写法；接收者来自参数、成员字段或 `GetProxy` 一类未建模工厂时
  **不**声称边界。
- **边界上记什么**：`(file:line, 被调方法, 跨过去的身份)`。身份二选一：
  - `service` —— 默认。下游绑定器看到的是**本服务**的身份，不是本处理器入口时的调用者；
  - `caller` —— 只有路径显式执行了 `SetCallingIdentity(<调用者 token>)`，且其后没有
    `ResetCallingIdentity()`。把服务**自己**保存的身份 `SetCallingIdentity(saved)` 设回去
    不算：那是恢复自身，不是转发调用者。
- **它不做什么**：不产生候选、不把入口守卫追认为下游授权、不读下游服务的守卫，也不
  沿链继续（`proxy->A()` 的返回值再取 `B` 的情形没有建模）。记录进入
  `DetectorRun.limitations` 的 **Cross-service boundary coverage** 一行（边界数、其中
  携带调用者身份的数、作为服务执行的数），零边界也照常输出，所以"没走到"与"没找过"
  可区分。
- **控制**：`tests/test_ipc_proxy_chain.py` 七条——`iface_cast` 句柄上的调用是边界且记为
  service；转发调用者 token 记为 caller；转发后 `ResetCallingIdentity()` 回到 service；
  恢复自身保存身份不算转发；`Manager::GetInstance()` 这类**客户端 Kit** 调用不是边界；
  非 `iface_cast` 句柄不声称边界；入口守卫之后的跨服务调用仍只是覆盖、不产生候选。

## 11. B 线目标对照（差距审查 §6）

| 条目 | 状态 | 证据/位置 |
|---|---|---|
| B-0 六家族收口、版本与依赖 | 完成 | 交付项 16/17；`research/deliveries/ipc/20261017-v080-dependency-inventory.md` |
| B-0 入口建模（stub/handler、IDL dispatcher、callback、`unresolved_dispatch`） | 完成 | `entry_index.py`；报告 `Entry/dispatch coverage:` 行（分发器/绑定 grade/事务解析/未解析分发/条件绑定） |
| B-0 有界跨文件 helper/限定名 | 完成 | §10.1；`tests/test_ipc_cross_file_resolution.py`（4 条） |
| B-0 授权事实绑定实际调用者 | 完成 | `caller`/`self` 值事实、`caller_class`、审阅账户模型；`auth_unknown` 与 `auth_uncredited` 分开陈述（§10.2） |
| B-0 `IsSystemAppCalling`/`CheckSystemApp` 读函数体、不按名白名单 | 完成 | 同名本地定义优先按体解释、拒绝按名 credit；`tests/test_ipc_system_app_predicate.py` 成对控制 |
| B-0 客户端 Kit/`Manager::` 不当作 IPC 边界 | 完成 | §10.4 控制之一：`CameraManager::GetInstance().OpenCamera()` 不计边界 |
| B-0 Parcel API 语义 + 真实语料执行计数 | 完成 | §3、§4；插桩探针 `bline_rule_probe.py` |
| B-1 `parcel.bounds` / `parcel.lifecycle` 与 taint/guard/unknown | 完成 | DATA-01..03；正/修复/安全控制；`all-files` 与 `complete-ast` 双视图 |
| B-1 真实修复前/后漏洞对、隔离复现 | 完成一项（AUTH-01 族） | §12：CVE-2023-0036 vulnerable `e663b470` 稳定触发 3/3，fixed `5eaddcab` 拒绝；本地 Docker 镜像内 clang++/ASan/UBSan。Parcel 族（DATA-01..03）仍无对应的公开修复对，未作同类声明 |
| B-2 事实模型 + guard 支配 | 完成 | AUTH-02/03/04/05 与 DATA-04；成对样本（有 guard / guard 在错误分支 / guard 不支配 / 客户端调用受服务端保护）见 `tests/fixtures/ipc/` |
| B-2 跨服务代理链身份变更点 | 完成（有界） | §10.4；54 组件实测 10 次边界，0 次转发调用者 |
| B-2 敏感 source → 不可信可见输出 | 完成（有界） | DATA-04：披露类结果 → reply 写入；文件/日志/共享内存 sink 未建模（§8.4） |
| B-3 ArkTS/ETS + JS/TS 前端 | 完成首批（有界） | §13：`arkts_js.py`（complete/partial/unsupported 三态）+ 4 条规则 + `tests/test_ipc_arkts_js.py`（18 条）；真实语料 2045 文件全量解析、0 候选（`research/evidence/interface/ipc/b3_arkts_real_20261017/`）。Catalog 注册与 `requirements*.txt` 依赖仍属 owner；未解析 module.json5 |

"完成"指该条的实现与控制存在于本提交，并且有可复核的运行结果；它不指这些规则在真实组件里
找到了漏洞。

## 12. 真实修复对：AUTH-01 本地隔离复现（CVE-2023-0036）

差距审查 B-1 第 5 条要求"公开修复前/修复后真实漏洞 + 隔离伪造请求负例 + 无害对照，并尝试
在容器/仿真安全环境复现"。本提交在本地 Docker 验证镜像中重跑了已有的 AUTH-01 harness；
目标、两条修订与文件摘要全部由 manifest 固定，运行前逐文件校验 sha256。

**目标**：`openharmony/inputmethod_imf`，`PlatformCallbackStub::OnRemoteRequest`
（PR !228）。vulnerable `e663b47013d534a56165ab7467fbb3e14bf7172b`，
fixed `5eaddcab19bc4b22544f4bee1e8894fc2d6505dc`，依赖
`commonlibrary_c_utils b807d3dadb7dbb7639fe85b3a5f72da18d318da2`。

**环境**：镜像 `ohscanner-validation-local:20261016`
（`sha256:bfb8cbdda14a4654fccf5d61463d37c0ece1a2bd1af13520b21f7af0e539e712`），
Ubuntu clang 14.0.0，ASan+UBSan，无网络；宿主 WSL2 `6.18.54.1`。

**执行**（在容器内，`OHSCANNER_VALIDATION_CONTAINER=1` 由 `runner.py` 强制）：

```sh
docker run --rm --entrypoint sh -v 'C:\Users\16669\AppData\Local\Temp\ohpoc:/work' \
  -w /work/repo -e OHSCANNER_VALIDATION_CONTAINER=1 -e PYTHONPATH=/work/repo \
  ohscanner-validation-local:20261016 -c 'python3 /work/run_poc.py'
```

**结果**：

| 修订 | 状态 | `no_token`（攻击） | `correct_token`（对照） | `foreign_token`（攻击） |
|---|---|---|---|---|
| vulnerable `e663b470` | `stable_reproduced`（3/3） | trigger，`messages_sent=1 userId=4242` | no_trigger | no_trigger |
| fixed `5eaddcab` | `run_success` / `stable_rejected` | no_trigger，`ret=-74` | trigger（正常请求仍被服务） | no_trigger，`ret=-74` |

完整记录与编译命令见 `research/evidence/interface/ipc/auth01_dynamic_20261017/`
（`result.json` sha256 `20632c69…`，`result.md` sha256 `44047f51…`）。

**没有证明的事**：`validated_vulnerability` 仍为 0；reachability 状态是 `partial`——harness
直接调用 stub，真实 IPC 入口、调用者身份与权限状态仍是 EvidenceObligation。该样本属于
AUTH-01（relay/confused deputy），**不是** Parcel 族（DATA-01..03）的真实修复对；后者仍无
可用的公开修复前后组合，不能借这一条类推。

## 13. B-3 首批：ArkTS/ETS + JS/TS 前端与四条规则

`src/ohscanner/detectors/interface/arkts_js.py` 先交付可审计的语言前端，再在其上放窄规则。
前端三态是硬契约：

- `.js` → tree-sitter-javascript；`.ts`/`.ets` → tree-sitter-typescript。
- `complete`：AST 无 ERROR/MISSING；`partial`：有语法错误但仍恢复了调用/类结构；
  `unsupported`：语法包缺失（此时整个 run 是 `blocked`，不是"0 发现"）。
- **ArkTS 的 `struct` 与装饰器不在 TypeScript 语法内**，所以 `.ets` 通常报 `partial`；
  结果里的 limitation 明确写"component/decorator semantics are NOT claimed"。这满足
  "不可以看见 `.ets` 就声称有语义分析"。

首批规则（全部 candidate，`candidate_cwe` 只作机制分类）：

| 规则 | 触发 | 控制/抑制 |
|---|---|---|
| `ohscanner.oh.arkts.component_exposure` | 导出的 `UIAbility`/`ExtensionAbility` 生命周期方法把 `want.parameters` 派生值送进路径 API | 同函数/类内 `if (...startsWith/canonicalPath...)` 命中则不报；`module.json5` 未解析，finding 带 `manifest_export_state` 义务 |
| `ohscanner.oh.arkts.webview_bridge` | `registerJavaScriptProxy` / `javaScriptProxy` 注册 | 同函数内 URL/origin 比较则不报；带 `page_origin` 义务 |
| `ohscanner.js.path_taint` | `want.parameters` 派生值到达 `fileIo.*`/`fs.*` 路径 sink；含一层同文件函数声明调用（实参污染 → helper 形参 → sink） | 同函数（或 helper 内针对该形参）路径谓词则不报 |
| `ohscanner.js.dangerous_eval` | `eval(x)`、`new Function(x)` 且实参非字符串字面量 | 字面量实参不报 |

覆盖数字写进每次运行的 limitation（前端文件数/三态、调用点、bridge 注册与守卫数、路径 sink
与守卫数、ability 类数），与 IPC 检测器的计数口径一致。

**边界**：无 CFG；taint 最多跨一层同文件函数声明（不含方法/箭头函数），不解析 manifest、
不判定页面来源；守卫判定是"同函数 `if` 条件里出现被污染名字 + 路径谓词"的启发式，不是
支配证明。跨函数形态的候选带 "`sink <- helper`" 符号，调用点可达性仍是义务。`requirements*.txt` 与
`catalog.py` 属 owner 共享面，本提交没有改动它们：语法包只在本地 venv 安装，检测器也尚未
注册进 Catalog；接入前 CI 不会自动获得这两个依赖。

控制：`tests/test_ipc_arkts_js.py` 18 条，包含每个规则的正例与抑制例（含
`want.parameters?.x` 直接作实参的内联形态）、`partial` 三态报告，以及"非 Ability 类不产生
component_exposure 但路径规则仍触发"的分离控制。

真实文件上还有两个实现修正（提交 `dfb187a`）：

- `Node.start_point` 在真实 88 调用点的 `.ets` 文件上会让 tree-sitter 绑定段错误；行号改为
  从保存的字节偏移 `_line_starts()` + `bisect_right(start_byte)` 计算。
- 每次 parse 新建 `Parser`（Language 仍缓存）。复用一个 Parser 在上一棵树被回收后同样会崩。

**真实语料清点**：`research/evidence/interface/ipc/b3_arkts_real_20261017/` 对
`openharmony/applications_settings @ 5e8af0a2a104bc634f8d5e18ed03db202cd1ea02` 跑完整
前端：2045 个文件（ets 1343 complete / 552 partial，ts 122 / 2，js 26），112221 个调用点，
40 个导出的 Ability/Extension 类，30 个路径 sink，1 个 eval 站点，0 个 bridge 注册；
**0 条候选**。逐点核对解释了这个 0：唯一 eval 是字面量
`new Function('return this')()`；16 个 `want.parameters` 文件里被抽样的是
`bundleManager.getBundleInfoSync(want.parameters?.bundleName, ...)` 这类非文件 sink，
且在 `isParamsValid` 守卫之后；40 个 Ability 类没有一个把 `want.parameters` 送进文件 API。
这是覆盖结论，不是"该应用安全"。第二个独立检出
（`openharmony-security` 的 `vultraining`，`ceaf1b4f`，16 个文件 / 239 调用点 / 1 个
Ability 类 / 2 个路径 sink）同样是 0 候选，记录在 `b3_arkts_vultraining_20261017/`。
