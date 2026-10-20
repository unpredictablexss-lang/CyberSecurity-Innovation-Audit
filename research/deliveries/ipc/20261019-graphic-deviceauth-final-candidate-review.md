# Graphic Standard 与 DeviceAuth 剩余七条候选复核

日期：2026-10-19
检测器：B 线 `ohscanner.interface.ipc 0.12.12` / model `oh-ipc-2026.10-v32`
固定源码来自八仓候选集；仅核对本报告列出的 6 条候选观察，原始 JSON/候选身份不改写。

## 结论摘要

| Candidate key | 固定仓库/提交 | 锚点 | 复核结论 |
|---|---|---|---|
| `1ba912309d6913e5` | `graphic_standard@a73af6bd3bac599b9359cba10ca7b5f82a02d5d9` | `GraphicDumperCommandStub::OnRemoteRequest:54` | `AUTH-02 source-local caller check not observed; product registration/ACL unknown. 保留 candidate/unassessed。` |
| `30aa8c14c1dc9eab` | 同上 | `GraphicDumperCommandStub::Dump:108` | 与上一条同一 stub 入口和同一诊断家族，根因候选应关联；不计成独立漏洞。操作可达性、调用者角色与数据敏感性未证。 |
| `0ca2bd768019b286` | 同上 | `VSyncConnectionStub::OnRemoteRequest:42` | 有接口描述符校验；FD 由已取得 VSync connection 的调用者获得，符合对象能力接口的预期形状。谁可取得/转交该对象及 FD 权限仍 unknown；不按单个 `WriteFileDescriptor` 确认漏洞。 |
| `2ef062a49a00b82a` | 同上 | `RSRenderServiceConnectionStub::OnRemoteRequest:48` | `CREATE_NODE_AND_SURFACE` 创建 surface 后返回 producer；该类入口没有统一 descriptor/caller guard，其他 transaction 有局部 token 校验。产品中 connection 对象的获取门、producer 权限与可达性未闭合，保留 candidate。 |
| `0c7942f0ce31085d` | 同上 | `RSRenderServiceConnectionStub::OnRemoteRequest:48` | 与上一条锚定同一个 dispatch 入口，但 AUTH-01 与 CAP-01 问的是不同事实：部分 case 存在局部 token 检查，不等于所有 case 都有共同边界校验；与 `2ef...` 关联为同一入口/对象路径，分别保留规则观察。 |
| `fcd84b315b3a206c` | 同上 | `RSRenderServiceStub::OnRemoteRequest:56` | `CREATE_CONNECTION` 在返还 connection 前校验 RenderService interface token、remote object 非空且为 proxy object。对象导出与构造关系有明确入口门；系统身份/产品调用策略仍在仓外，保留低置信候选/unknown，不当作 confirmed。 |
| `abd2b5258693ac3a` | `security_deviceauth@2cf21e46f43c63857c40a79b004eda14f79b04c2` | `StubDevAuthCb::OnRemoteRequest:66` | Stub 未自行比较 descriptor，按 callback transaction 解码 `callbackId`/`cbHook`，并调用 `ProcCbHook`。源码显示它是 SDK callback endpoint；谁持有/调用 callback handle、`cbHook` 如何跨 IPC 往返并被绑定至发起者，需 IPC adapter 与服务端调用点闭环。保留 unresolved external dependency/candidate，未证明任意远端可控指针调用。 |

> 本报告复核 **7 个候选 key**：graphic_standard 的 6 条新观察，以及 security_deviceauth 的 1 条观察。此前 graphic VSync fall-through 报告已覆盖另外 2 个观察；候选矩阵中的全部 8 条 graphic 观察现均有人工复核材料。
## 源码依据与边界

### Graphic Dumper

固定源码 `frameworks/dumper/src/ipc/graphic_dumper_command_stub.cpp` 中，`OnRemoteRequest:27-34` 先读取 interface token 并与 `GetDescriptor()` 比较，不匹配返回；随后 switch 将 GET/SET_CONFIG、DUMP、GET_LOG、ADD_INFO_LISTENER 分发到实现。`:52-57` 的 DUMP 调用 `Dump(v)`，实现 `:105-109` 进入 `GraphicDumperServer::Dump`。该入口没有 source-local 调用者 UID/permission 判断，但 interface token 只是接口类型校验，不是主体授权。

因此 AUTH-02 的“未发现本函数调用者鉴权”仍是准确观察；其安全意义取决于服务如何注册、谁能取得 remote object、底层操作是否另有角色/权限约束，以及 dump/config/log 是否暴露敏感内容。仅凭源码文件不能把它降为安全，也不能确认普通应用可达。

### VSync connection

固定源码 `rosen/modules/composer/vsync/src/vsync_connection_stub.cpp:22-28` 在所有 switch 分支前校验 `GetDescriptor()`；`:35-43` 的 `GET_RECEIVE_FD` 调用 `GetReceiveFd`，成功后将 FD 写入本次 reply。这个 Stub 是由 VSync connection object 提供的细粒度接口，单看 reply 写 FD 更像对象持有者取得该连接对应资源。仍需核验上游 `CreateVSyncConnection` 的取得策略和句柄分享能力；本轮不声称该 FD 对所有 app 安全。

### RenderService connection

固定源码 `rosen/modules/render_service/core/transaction/rs_render_service_connection_stub.cpp:25-30` 进入 switch 前没有统一 token guard。`CREATE_NODE_AND_SURFACE` (`:42-49`) 读取请求字段、调用 `CreateNodeAndSurface` 并回传 producer；其它部分 case（例如 `GET_DEFAULT_SCREEN_ID`，`:51-55`）自行校验 descriptor。`CREATE_VSYNC_CONNECTION` (`:419-429`) 的状态副作用先于落入下一个 case 的 token 校验，已在 [VSync fall-through 专项复核](20261019-graphic-standard-vsync-fallthrough-review.md) 单独关联；不要把该根因重复计算到本报告新候选。

父级 `RSRenderServiceStub::OnRemoteRequest:32-57` 对 `CREATE_CONNECTION` 校验 `RSIRenderService` descriptor、proxy object 属性，再返回新建 connection。它证明创建 connection 的本地协议门存在，但没有证明产品 ACL、普通 app 可达性或后续每个 connection transaction 的授权策略。因此：CAP-01 保留为待核查观察；AUTH-01 应表述为**逐 transaction descriptor 覆盖缺口**，不能声称整个对象完全无边界。

### DeviceAuth callback

固定源码 `frameworks/src/standard/ipc_callback_stub.cpp:55-73` 按 `DEV_AUTH_CALLBACK_REQUEST` 读取 callback ID 和 pointer-like `cbHook`，再调 `DoCallBack`；`:38-51` 检查 hook 非零、解码参数后传入 `ProcCbHook`。同提交 `frameworks/src/standard/ipc_adapt.cpp:1516-1517` 创建两个全局 `StubDevAuthCb`，`ipc_dev_auth_stub.cpp:115` 记录其尺寸；`ipc_callback_proxy.cpp:40` 写回 callback hook。现有材料证明这是一套回调适配机制，不证明外部不可信方能任意选择 hook。需要固定服务端对 callback object/parcel 的构造、调用进程身份和回调 ID/参数绑定，再判断是否存在不可信消息到函数指针调用的数据链。

## 固定源码摘要

| 候选源文件 | Git blob | SHA-256 |
|---|---|---|
| `graphic_standard/frameworks/dumper/src/ipc/graphic_dumper_command_stub.cpp` | `02623e1a94f726667aa01d305bf9b9fdc050fe70` | `20afc2aafaae3a78f50556188462497eaa62359cc7dd419b6a5698998b88e123` |
| `graphic_standard/rosen/modules/composer/vsync/src/vsync_connection_stub.cpp` | `e364dfc5f876863b49de3ba95ed1dec541fe1b9c` | `cc5f23a25a8722adba62434bf8d87b498cd20d174dc0204986ea6cf42d5ceb84` |
| `graphic_standard/rosen/modules/render_service/core/transaction/rs_render_service_connection_stub.cpp` | `ccc4b266f7e1bd50e834e654d004657114ef7f2e` | `4e21838ace1755c9dac5ce459f2cdcc1a6e4f3e8573235486a3c539e2584fb6b` |
| `graphic_standard/rosen/modules/render_service/core/transaction/rs_render_service_stub.cpp` | `d3791d10829dbffe54a4cdceeb53358f30b6e903` | `1469a7ef544fed05f2f471be7c78fe3faae0f0f74819775280a5001c1cafc34a` |
| `security_deviceauth/frameworks/src/standard/ipc_callback_stub.cpp` | `e42b3ce4d2a277d1e5eb88fe5f0bc9c301e35bf0` | `05661e3644f69c688442ab6e5880e60f800822bc73d7c63a92c33df6a7ce466c` |

Candidate source binding (commit/tree, file hash, line and parse status) remains in `20261019-eight-component-candidate-triage-v0.12.12/candidate_triage.csv`; raw reports and source snapshots remain unchanged.

## 状态与后续

已验证：固定源码存在上述 token/descriptor 检查位置、object/FD 回传调用和 callback hook 解码流程；候选锚点都标为 complete。complete 仅说明目标文件可解析。

未验证/unknown：Graphic Dumper、RenderService、DeviceAuth 的产品服务注册 ACL、签名/权限模型、调用者角色、实际设备可达性与安全影响；DeviceAuth callback object 的持有者与 hook provenance；VSync FD 的具体能力范围。

本轮所有观察保持 candidate/unassessed 或 unresolved external dependency，没有升级 confirmed，也没有修改扫描规则。此报告与旧候选 key 可形成逐条复核索引；不将同一 transaction 的多条 rule observation 等同多个根因。未运行完整组件构建、设备动态验证、PoC 或 Harness。
