# Graphic Standard VSync 分发路径复核

核对日期：2026-10-19

## 结论

八组件复测在完整解析锚点 RSRenderServiceConnectionStub::OnRemoteRequest:422 产生 CAP-01 与 AUTH-01 两条观察，按一个根因组复核，不计为两个漏洞。固定源码显示，服务端先创建并登记 VSync 连接，再因 switch case 缺少 break 落入 REQUEST_ROTATION 并校验 token。对应 proxy 正常请求只写名称；请求预期会在后续 token 校验失败，而连接对象已创建。普通应用可达性、重复请求能否造成产品级资源耗尽及影响仍未验证。因此保留为高优先级 candidate/unassessed，不标 confirmed，不关联 CVE。

## 固定来源

- 仓库 openharmony/graphic_standard
- commit a73af6bd3bac599b9359cba10ca7b5f82a02d5d9；tree d5446eefcd0dc9478a0da65c76fafc9f62f973ad
- 候选文件 rosen/modules/render_service/core/transaction/rs_render_service_connection_stub.cpp:422
- Git blob ccc4b266f7e1bd50e834e654d004657114ef7f2e；SHA-256 4e21838ace1755c9dac5ce459f2cdcc1a6e4f3e8573235486a3c539e2584fb6b
- 实现文件 rosen/modules/render_service/core/pipeline/rs_render_service_connection.cpp
- Git blob 74f57a8626e36fde90b158bf3d15e01f2cbd9012；SHA-256 b3b070b2aef3e0e7d005829e9919e3e9245ad146952246b5b9840efce55ccea1
- parse complete；八仓生产 CLI completed_with_limitations
- candidate key：CAP-01 7904746835031ecc；AUTH-01 fef124fb5c14180c

## 证据链

stub 的 CREATE_VSYNC_CONNECTION 在第 420 行读 name，第 421 行创建连接，第 422 行把对象写入 reply；case 没有 break/return，继续落入 REQUEST_ROTATION。后一分支第 425–429 行读取 interface token，并要求等于 RSIRenderServiceConnection::GetDescriptor()，否则返回 ERR_INVALID_STATE。

RSRenderServiceConnectionProxy::CreateVSyncConnection（proxy 文件第 104–120 行）只写 name，发送 CREATE_VSYNC_CONNECTION，并在 SendRequest 非 NO_ERROR 时返回空指针。故按此 proxy 请求布局，Parcel 在读完 name 后没有后续 token，校验预计失败。空 Parcel 上 ReadInterfaceToken 的具体行为依赖目标 IPC runtime，本报告未在目标设备或同版本 runtime 实测。

实现第 215–223 行创建 VSyncConnection、加入 appVSyncDistributor_ 并追加到 vsyncConnections_；CleanAll 第 93–100 行移除连接并清空 vector。若请求在创建后失败且同一 connection 仍存活，重复调用可能累积服务端对象；访问策略、配额、清理时机和资源影响仍需运行时确认。

两条候选抓到同一异常路径，但现有 CAP-01/AUTH-01 文案未表达“副作用先于后续拒绝”。人工根因数为 1，原始规则观察保留。邻近 CREATE_NODE_AND_SURFACE 也无本地 token check 但有 break，说明不能单凭缺少 per-case token 判漏洞；interface token 也不等价于 caller authorization。

## 下一步

在固定源码组件环境分别发送官方 proxy 和受控 Parcel，记录 IPC 返回码、reply、VSync Distributor 连接数及 CleanAll；检查 RenderService SA 访问策略。若证实可触发且对象被保留，优先修复 case 终止和失败回滚，再定义配额/caller policy。是否增加 token check 按接口契约决定。

可研究“switch fall-through 中副作用先于后续拒绝”规则，需该样本正例、修复版负例、合法 fall-through 负例和先检查后创建安全对照，且按根因独立拆分。本轮没有 detector 代码改动、产品构建、PoC/Harness、提交或推送。

## 后续源码对照：较新上游快照（2026-10-19）

为判断该观察是否仍存在于较新代码，本次只读核对 `openharmony/graphic_graphic_2d` 固定提交 `c19cedf62fefde6bf184aa815feeaf0346aa4d49`。这是与初始 `openharmony/graphic_standard@a73af6bd3bac599b9359cba10ca7b5f82a02d5d9` 不同时间的源码快照；以下是源码状态对照，不声称找到了精确修复提交，也不是漏洞披露记录。

- 较新 stub：[`rs_client_to_service_connection_stub.cpp`](https://github.com/openharmony/graphic_graphic_2d/blob/c19cedf62fefde6bf184aa815feeaf0346aa4d49/rosen/modules/render_service/main/render_server/transaction/zidl/rs_client_to_service_connection_stub.cpp)，blob `1eb2783a3172dde96f45dc33f438998794df9660`。`OnRemoteRequest` 在 `352-365` 先对 `descriptorCheckList` 中的 code 读取并校验接口 token；`CREATE_VSYNC_CONNECTION` 在该列表中（定义附近第 216 行）。该 case 位于 `1770-1813`，参数解析和连接创建后有独立 `break`（第 1812 行），不再顺序落入后续 case。
- 较新 proxy：[`rs_client_to_service_connection_proxy.cpp`](https://github.com/openharmony/graphic_graphic_2d/blob/c19cedf62fefde6bf184aa815feeaf0346aa4d49/rosen/modules/render_service_base/src/platform/ohos/transaction/zidl/rs_client_to_service_connection_proxy.cpp)，blob `b2c8a80f8cfebc1be3e4ac2c7f4e6583885f9fc7`。`CreateVSyncConnection` 在 `121` 写接口 token，随后写 name、remote token、id 和 windowNodeId（`128-145` 及后续参数写入），与较早 proxy 只写 name 的调用布局不同。
- 较新单测：[`rs_client_to_service_connection_stub_test.cpp`](https://github.com/openharmony/graphic_graphic_2d/blob/c19cedf62fefde6bf184aa815feeaf0346aa4d49/rosen/test/render_service/render_service/unittest/transaction/rs_client_to_service_connection_stub_test.cpp)，blob `319fbc50e3f17ac970d4645a1b9f4aeee44e722d`。第 `730` 行断言空/畸形 `CREATE_VSYNC_CONNECTION` 请求返回 `ERR_INVALID_DATA`；该断言覆盖输入校验，但没有断言失败请求后 VSync distributor/connection 集合未发生副作用。

**判定更新：**初始固定旧提交中的控制流异常仍是一个有源码依据的历史观察，候选只绑定旧 commit，保持 candidate/unassessed 且不关联 CVE。较新固定快照未呈现相同 fall-through 形态，并且调用协议已变化；可记录为“较新快照形态已不存在”，不能据此宣称旧观察由哪个补丁修复、旧版本问题曾可被普通应用利用，或资源影响已验证。此前建议的受控运行时验证仍未执行。

**对 B 检测能力的含义：**现有 CAP-01/AUTH-01 两条观察来自同一根因。规则捕获了接口边界形态，但没有把“有状态副作用发生在后续拒绝之前”表达成独立、可核验的语义事实。暂不新增规则；若后续要做，应先构造并验证四类控制：旧形态正例、显式 `break`/早退修复例、合法 fall-through 例、先校验再创建的安全例，并将同根因样本按根因整体留出，避免把这一个已分析样本当独立 holdout。

本次仅做 GitHub 固定源码读取和历史报告补充；未改检测器代码，未构建 OpenHarmony，未运行 PoC/Harness，未执行 Agent，未提交或推送。当前 B worktree 的完整单测数字不由本次源码读取更新。