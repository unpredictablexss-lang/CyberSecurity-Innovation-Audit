# CAP-01 render-session capability export：候选竞赛闭环

更新：2026-10-16（中国标准时间）。状态：`candidate/unknown`，`validated_vulnerability=0`。
本文件是证据闭环矩阵，不构成 confirmed/reportable 结论。

## 1. 候选选择与 RC-JSPROXY 阻塞

按要求先复核 RC-JSPROXY。它仍是本轮证据最强的 A 线候选，但产品级 Gate 仍为 `not_met`：

- 既有产品证据包 `outputs/reports/rc-jsproxy-product-evidence-20261015/` 仍缺完整产品 `.gn`、
  `foundation/distributeddatamgr/kv_store/BUILD.gn`、device/prebuilts、三 variant 产品构建产物、
  产品权限/身份/部署 trace、产品 CIA 测量和影响版本/分支闭合。
- 2026-10-16 重验过程先保留两次失败：attempt 1 因 current dirty shared_ptr Detector hash 与历史
  Harness manifest 不一致而在 variant generation 前失败；attempt 2 因 clang++ 经 symlink 调用而缺
  C++ runtime，在 native build 阶段失败。随后完成的 attempt 3 已达到
  `stable_reproduced_and_patch_revalidated`：组件模型 vulnerable race/close_get_entry 3/3 TSan 触发，
  mutex fixed control 与 atomic patch 3/3 clean，四类 controls 20/20。
  这些记录位于 `research/evidence/cpp/rc_jsproxy_patch_revalidation_20261016*`。
  但它仍不是产品构建、产品入口/权限 trace 或 CIA 验证，不能解除产品 Gate。
- 因产品源码、产品构建产物和真实权限/部署边界仍缺失，RC-JSPROXY 必须 fail-closed，继续
  `candidate/unknown`，不能用组件 Harness 的 TSan 结果升级。

因此转用社区扫描中入口和调用路径最清楚的安全边界候选：

- Diagnostic ID：`ohscanner.interface.ipc:eaf73b5d3dd8cbed`
- Rule：`ipc.capability.export`，Detector `ohscanner.interface.ipc 0.5.0`
- 选择点：`ScreenSessionManagerStub::OnRemoteRequest` 经固定 transaction code 和 attacker-controlled
  `screenId` 到达 `GetRenderSession(screenId)`，随后 `reply.WriteRemoteObject(renderSession)`。
  该路径比其他 CAP-01/AUTH-02 候选更直接地把远程入口、输入、敏感 capability handoff 和返回对象连起来。

## 2. 仓库与源码身份

- Repository：`openharmony/window_window_manager`
- Declared remote：`https://github.com/openharmony/window_window_manager.git`
- Full commit：`8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Full tree：`24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256：`b528cb54ffd2e4007bc3ae64b9cb06002bd7228fe8cc304cd1eeb9c457b836d9`
- Primary source：`window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp`
- Primary Git blob：`26df3196683976a9f175292fcbf54efef262eaa0`
- Primary source SHA-256：`404969d13de038e6deb4231dd68ba11af43e04f467c75e1866146a1df57de2ab`
- Observation：line 1778，byte range `[83689, 83741)`
- Detector/rule/profile/scope：`ohscanner.interface.ipc/0.5.0`、`ipc.capability.export`、
  rule version `unknown`、`light-ast`、1079 files / 472214 LOC。
- 当前 target checkout 为 detached `FETCH_HEAD` 且 working tree dirty；它不是 provenance。
  本包只读取并验证 pinned local Git objects。10 个 call-path/build/authorization 源文件的 blob、
  byte size、SHA-256 与 18 条 line-level quote relation 均已在
  `source-manifest.json` 中绑定并在 preflight 中重验。

commit 元数据：author/committer `openharmony_ci`，时间 `2026-10-08T11:45:03+08:00`，
subject `!20325 merge interceptMaximize into master`。本地对象是 shallow one-commit boundary，
`parents` 未保留；本地只有 detached `FETCH_HEAD`，没有可证明的 release tag 或 branch。

## 3. 真实入口、边界与攻击者控制

### 源码可见入口

1. `ScreenSessionManager : public SystemAbility, public ScreenSessionManagerStub`。
2. `ScreenSessionManager::GetScreenSessionMngSystemAbility()` 调用
   `SystemAbility::MakeAndRegisterAbility(&ScreenSessionManager::GetInstance())`。
3. client 通过 `SystemAbilityManagerClient::GetSystemAbility(DISPLAY_MANAGER_SERVICE_SA_ID)` 获取
   remote object，再 `iface_cast<IScreenSessionManager>`。
4. proxy 写入 interface token、`screenId` 和 `TRANS_ID_GET_RENDER_SESSION`，最后读取返回 remote object。
5. stub `OnRemoteRequest -> OnRemoteRequestInner` 校验 interface descriptor 后 dispatch。

### 权限/身份边界

- `OnRemoteRequestInner` 对该 transaction 的源码可见校验只有
  `data.ReadInterfaceToken() != GetDescriptor()`。
- `TRANS_ID_GET_RENDER_SESSION` 分支直接读取 `screenId`、查找对象并 `WriteRemoteObject`；
  分支内没有 `SessionPermission::IsSystemCalling()`、permission verify 或 caller/resource ownership check。
- 同一 translation unit 的 `ProcSetPrimaryDisplaySystemDpi` 使用
  `SessionPermission::IsSystemCalling()`；该 helper 读取 `IPCSkeleton::GetCallingTokenID()`，
  接受 native/shell token 或 system app token。
- 这证明“该分支未见本地 caller authorization”，不证明系统没有外层 SAMGR、SELinux、API restriction
  或 service-access policy。真实 permission grant/deny、UID/user/sandbox 和 caller identity 均为 `unknown`。

### 部署边界

源码显示它是 `DISPLAY_MANAGER_SERVICE_SA_ID` SystemAbility，且 BUILD.gn 依赖 `samgr_proxy`。
但产品 image、SA policy、SELinux domain、samgr 授权、导出面和设备 profile 未提供，
所以“未特权 app 能否取得该 proxy”仍是 `unknown`，不能把 source-visible remote API 写成实际 attacker reachability。

### 攻击者控制

条件性控制成立：若调用方已取得 `IScreenSessionManager` remote object，则 transaction code 和
`screenId` 由调用方构造；合法 descriptor 可由公开 client/proxy 代码写入。
`unprivileged/unrelated caller 可获得 proxy` 未被证明。

## 4. 从入口到敏感操作的可达路径

| Step | Pinned source | 观察 |
|---|---|---|
| 1 | `screen_session_manager.cpp:367-375` | 注册 `ScreenSessionManager` SystemAbility |
| 2 | `screen_session_manager_client.cpp:58-70` | 经 SystemAbilityManager 取得 remote object/proxy |
| 3 | `screen_session_manager_proxy.cpp:5558-5581` | 写 token、`screenId`、transaction code，读取 remote object |
| 4 | `screen_session_manager_stub.cpp:38-53` | `OnRemoteRequest -> OnRemoteRequestInner`，descriptor check |
| 5 | `display_manager_interface_code.h:20-211` | `TRANS_ID_GET_RENDER_SESSION` 是明确 transaction selector |
| 6 | `screen_session_manager_stub.cpp:1775-1778` | 读取 `screenId`，`GetRenderSession(screenId)`，`WriteRemoteObject` |
| 7 | `screen_session_manager.cpp:3186-3207` | 按 `screenId` 查 `ScreenSession` 并返回 render session |
| 8 | `screen_session.cpp:1007-1010` | 返回 `renderSession_` remote object |

静态 source path 已完整绑定。实际 product runtime call trace 尚未执行。

## 5. 触发条件、生命周期与前置

必须同时满足：

- target revision 的 ScreenSessionManager SystemAbility 已注册并可被调用方取得；
- 调用方能构造/持有合法 interface descriptor；
- caller 选择 `TRANS_ID_GET_RENDER_SESSION`；
- caller 提供一个存在且 `renderSession_ != nullptr` 的 `screenId`；
- binder request 在 screen session 生命周期内同步到达。

不需要并发竞态。主要生命周期窗口是 `ScreenSession` 存在且 `renderSession_` 尚未清空时的同步 binder 调用。
返回 remote object 的 ownership、跨进程 lifetime、后续能力集合和销毁时序均 `unknown`。

## 6. CIA 影响

- Confidentiality：`unknown`。源码只证明 remote object 被返回，不证明可读屏幕内容或跨用户数据。
- Integrity：`unknown`。未证明拿到 render session 的调用方能修改渲染、窗口或系统状态。
- Availability：`unknown`。未证明调用可导致资源耗尽、崩溃、卡死或拒绝服务。
- 已观察事实：capability handoff 在 pinned source 中可达；真实安全影响、稳定可利用性和跨模块影响均未建立。
- 任一 CIA 项缺证据即保持 unknown，不以 capability 名称臆造影响。

## 7. PoC、编译与验证状态

`poc/harness.cpp` 是 source-bound component model，不是产品构建：

- `vulnerable`：原分支模型，unprivileged caller 获得 render-session token。
- `fixed_control`：显式 token allowlist control，unprivileged caller 被拒绝。
- `patched`：使用最小补丁同语义的 `SessionPermission::IsSystemCalling()` guard。
- 四类控制：`unauthorized_export`、`authorized_export`、`wrong_descriptor`、`unknown_screen`。
- `poc/run_poc.py` 先重验 commit/tree/blob/source hash 和 18 条 quoted relations，再编译三 variant；
  compile flags 为 `-std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`；
  每个 variant/scenario 计划重复 3 次。
- runner 强制 `OHSCANNER_VALIDATION_CONTAINER=1` 且 `/.dockerenv` 存在。宿主机调用在任何 build/run 前退出，
  这不是把静态 subprocess 当 PoC sandbox。

当前环境没有 Docker CLI/daemon，且 WSL 不见 `/.dockerenv`。因此：

- vulnerable/fixed/patched native builds：`unexecuted`
- sanitizer run logs：`unexecuted`
- 3 次 stable replay：`unexecuted`
- product build/dynamic validation：`unexecuted`
- 仅保存 `validation/host-preflight.log`；不得把它写成 PoC runtime log。

一旦有本地 Docker Worker，按 `poc/README.md` 的 network-none、cap-drop、read-only、PID/memory/CPU
受限命令运行，保存 `validation-result.json`、stdout/stderr、compiler/image ID 和 repeat hashes。

## 8. 最小修复与三方验证

`patch/minimal.patch` 在 `GetRenderSession(screenId)` 之前加入：

```cpp
if (!SessionPermission::IsSystemCalling()) {
    TLOGE(WmsLogTag::DMS, "only support system calling.");
    break;
}
```

理由：复用同 translation unit 已存在的 caller-token/system-app policy，避免非系统调用者进入 capability
lookup/handoff，同时不引入新 permission API。补丁对 exact Git blob `git apply --check` 和 `git apply` 均通过；
patched source SHA-256 为
`2b379e4427071b3536583c9f0e16ccd90d7389953a534be87dae087ec74b9295`。

| Variant | 观察目标 | 当前执行状态 |
|---|---|---|
| vulnerable | unauthorized export=true，authorized=true | unexecuted |
| fixed_control | unauthorized=false，authorized=true | unexecuted |
| patched | unauthorized=false，authorized=true | unexecuted |

没有 native runtime logs 时不能声称三方验证通过。该补丁是 proposed local patch，不是 upstream fix。

## 9. CWE/CVE、模块、版本、分支

- Candidate CWE：`CWE-926`（Detector 的 capability-export 分类）。
- Candidate consequence：`CWE-668`（capability exposure）；这是 consequence candidate，不是已证明影响。
- CVE：`not_assigned`。本包未找到并验证公开 CVE assignment，不臆造编号。
- 受影响模块（source-bound）：`window_scene/screen_session_manager`、`window_scene/session/screen`、
  `window_scene/screen_session_manager_client`。
- 受影响版本：`unknown`；只绑定上述 commit snapshot，没有产品 image/tag/version manifest。
- 受影响分支：`unknown`；本地 repo 是 detached shallow `FETCH_HEAD`，没有可审计 branch/tag containment。
- 其他版本/分支：`unknown`，未做跨版本扫描，不外推。

## 10. Fail-closed 义务与下一步

保持 `candidate/unknown`、`validated_vulnerability=0`。升级前必须补：

1. 产品 repo/manifest/image 中实际包含该 blob 的 build artifact、模块路径和 hash；
2. 产品 SystemAbility/SAMGR/SELinux/API permission policy，含 grant/deny caller traces；
3. 本地隔离 Docker/Worker 中的真实组件或产品 runtime trace；
4. render session remote object 的实际 capability surface 与 CIA 测量；
5. vulnerable/fixed/patched 产品构建和三次稳定重放；
6. 产品 release tag/branch/version 影响矩阵；
7. 有公开 assignment 时核验 CVE，否则继续 `not_assigned`。

最终状态变化仍需项目负责人授权；本包不合并、不推送、不标 Draft Ready。