# 交付项 17：B 线新增四个家族（Parcel 边界/生命周期、身份流、敏感数据流）与 54 组件实测

> 本项回应 `/goal` 的最后一句："以你最后实际情况为准地达到 B 线功能目标"。
> 对应差距审查文档 §6 的 **B-0 / B-1 / B-2**。本项只改 `src/ohscanner/detectors/interface/**`
> 与 `tests/**`，不触碰 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、
> `src/evidence/`；没有 `git fetch`，没有写入任何语料克隆，没有删除负结果，没有为了降低
> 候选数加入白名单。

## 0. 一句话结论

检测器从 **0.8.1 / `oh-ipc-2026.10-v7`** 升到 **0.9.0 / `oh-ipc-2026.10-v8`**，新增
**5 条规则、4 个族**：`ipc.parcel.bounds`、`ipc.parcel.write-bounds`（DATA-02，CWE-20）、
`ipc.parcel.lifecycle`（DATA-03，CWE-416）、`ipc.auth.flow`（AUTH-05，CWE-863）、
`ipc.data.sensitive-flow`（DATA-04，CWE-200）。在 54 个固定组件、31,225 个入选文件、
24,151 个完整 AST 上实测：**新增规则只有 `sensitive-flow` 发射 1 条候选，其余四条为 0**；
四个零各有**插桩计数**解释，不是"规则应该没问题"的推断。唯一的候选经固定源码复核后
**保留为 candidate**：它命中的是一个真实存在、但常量初始化未被建模的调用者 UID 守卫。

## 1. 改动面与版本

| 项 | 内容 |
|---|---|
| detector | `ohscanner.interface.ipc` **0.9.0** |
| model | `oh-ipc-2026.10-v8` |
| 新增规则 | `ipc.parcel.bounds`、`ipc.parcel.write-bounds`、`ipc.parcel.lifecycle`、`ipc.auth.flow`、`ipc.data.sensitive-flow` |
| 新增族模块 | `families/data02.py`、`data03.py`、`auth05.py`、`data04.py` |
| 语义改动 | Parcel API 参数位置（`ReadRawData(dst,size)` 用第 2 参）、目的容量匹配、parcel view 失效、身份丢弃、敏感结果写入 reply |
| 索引改动 | `functions_by_file_name`：同文件调用解析从全量扫描改为索引查找 |
| 测试 | 601 通过 / 4 skipped；新增 23 条数据流语义测试 + 3 条入口覆盖记录测试 |

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
| `all-files` | 完整 + 部分 AST | `blocked`（保留候选） | **265** |
| `complete-ast` | 仅完整 AST | `completed` | **141** |

`all-files` 是 `complete-ast` 的超集；两者不是相加关系。**124 条候选只出现在部分 AST 里**，
其中包含既有规则 `object-owner`（2）、`guard-coverage`（8）、`copy-range`（1）的全部发射。
因此"某个规则为 0"必须说明是哪个 pass。上一轮 CLI 表里的 264 条对应本表的 `all-files` 265
条——差的 1 条正是本次新增的 `data.sensitive-flow`，这也是两套测量互相校验的一个点。

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

| 规则 | complete-ast | all-files | 命中组件 |
|---|---:|---:|---:|
| `ipc.relay.descriptor-boundary` | 101 | 174 | 12 |
| `ipc.auth.missing` | 16 | 25 | 5 |
| `ipc.auth.object-owner` | 0 | 2 | 0 |
| `ipc.auth.guard-coverage` | 0 | 8 | 0 |
| `ipc.capability.export` | 23 | 55 | 4 |
| `ipc.parcel.copy-range` | 0 | 1 | 0 |
| `caller-class` / `identity-domain` / `service-identity` / `request-identity` / `position-underflow` | 0 | 0 | 0 |

`complete-ast` 下仍在发射的既有规则是 4 条（AUTH-01、AUTH-02、CAP-01、DATA-04）；其余
旧规则的全部候选依赖部分 AST，这是本表与上一轮 54 组件表的唯一口径差异。

## 4. 四个零分别意味着什么（插桩，不是推断）

`bline_rule_probe.py` 包装分析器的决策点并计数；它不改变任何候选（每个包装都调用原方法）。
`bline_shape_census.py` 在同样的 54 个固定树上做文本上界普查。两者一起区分
"语料里没有这个形状"和"形状在，但入口路径没有走到"。

| 计数 | 值 | 含义 |
|---|---:|---|
| `index_sites` | 87 | 入口可达函数里被求值的下标站点 |
| `index_request` | **0** | 其中下标来自 request parcel 的站点 |
| `index_capacity_known` | **0** | 其中被索引缓冲区容量在源码中声明的站点 |
| `dest_sites` | **0** | 入口路径上到达的 `ReadRawData(dst,size)` 站点 |
| `invalidations` | **0** | parcel 上的失效调用（`Reuse`/`RewindRead`/`SetReadPosition`/`Seek`） |
| `views_invalidated` | **0** | 被失效操作命中的活动 view |
| `reset_actions` | **0** | `ResetCallingIdentity` 之后到达的建模敏感操作 |
| `reply_writes` | 3,265 | reply parcel 上的写入 |
| `disclosure_writes` | 6 | 写入的实参是披露类调用结果 |
| `actions` | 53 | 建模敏感调用 |

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

**判定：候选陈述成立，但它是扫描器的知识边界，不是已证明的未授权读取。** 守卫确实比较了
调用者 UID；本分析没有建模"同文件 `static const` 初始化"，于是无法把它计入授权事实。
候选消息现在明确写出这一点：

> Guard seen, not accepted: the caller identity is compared against ACCESSTOKEN_UID on this
> path, but this analysis does not resolve that symbol to a value (a same-file constant
> initializer is not modelled here), so the comparison cannot be credited as authorization.

保留候选、不删除、不加白名单。**它不是漏洞**；若下一步把常量初始化纳入模型，它应当
自行消失，而不是被规则名单抑制。同一组件的 6 次披露结果写入中只有这 1 次没有匹配守卫，
另外 5 次路径上存在可识别的权限判定。

## 6. 性能：同文件调用解析改为索引

在 `graphic_graphic_2d`（3,411 个入选文件）上，旧实现的 `resolve()` 与本地函数查找
每次调用都线性扫描全组件的 `self.functions`（该组件数万个函数），单个组件运行 **42 分钟
仍未完成**（同一进程 CPU 满载，faulthandler 栈顶在 `analysis.py:665` 的列表推导）。
加入 `functions_by_file_name` 索引后，同一组件 **83.9 秒**完成，结果与索引前逐规则一致
（83 条候选，与 CLI 表相同）。54 个组件的最终整轮约 16 分钟。这个优化不改变语义：
`resolve` 仍只接受"同文件 + 同 owner + 唯一匹配"。

## 7. 测试、范围与证据

- `python -m unittest discover -s tests -t tests`：**601 tests，OK（skipped=4）**。
  新增 `tests/test_ipc_data_flow_rules.py`（23 条，钉住参数位置、目的容量匹配、
  view 失效归属、披露写回、身份丢弃/保存、未解析守卫不计数也不谎称无守卫、
  同名本地谓词按函数体解释）与 `tests/test_ipc_dispatch_coverage.py`（3 条，钉住
  覆盖记录每次都输出、含 `unresolved_dispatch`、无基类子句的分发器不算 stub）。
- 14 个新 fixture 的正/修复/安全控制（`parcel_*`、`auth_flow_*`、`sensitive_flow_*`）。
- `scripts/check_change_scope.py --base 6a41dc9b1aa030158e09be6241e2b14341f9256d --lane ipc`：
  **`"violations": []`**。
- 机器可读证据：
  `research/evidence/interface/ipc/bline_rules_20261017/{candidates,probe,shape_census}.json`。
- 复现脚本：`research/deliveries/ipc/bline_{direct_measure,rule_probe,shape_census,aggregate}.py`。

## 8. 没做完、也不能声称的

1. **A 线的 `Bounds/Integer` 事实没有可联动对象**——当前主线没有可用的事实接口，
   `bounds` 只做本地的容量/下界匹配，不做符号执行或位向量溢出证明。
2. **常量初始化未建模**：`static const`、跨文件 `#define` 的值不在值域里；这正是
   §5 那条候选保留的原因。下一步是把"同文件字面量初始化"纳入值传播，再重测候选差异。
3. **跨服务代理链没有保留身份变更点**：B-2 要求的 proxy chain 目前只有同文件一跳、
   同 owner 一跳与 `GetInstance()` 委托；任意跨进程/跨服务链仍是 unknown。
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

265（`all-files`）/ 141（`complete-ast`）条全部是**未验证的静态候选**；
`validated_vulnerability` 与 `confirmed` 均为 0。某个组件为 0 不等于它安全；
一条候选不等于一个漏洞；54 个组件是 2026-10-17 的快照，不代表整个 OpenHarmony。
