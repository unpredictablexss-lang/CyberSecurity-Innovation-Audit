# T45 独立验收：Safwk local ability manager IPC，CR-0244–CR-0246

- 验收 checkout：独立分支 `codex/t45-safwk-audit-20261027`，基线 `cb911db1e04189cc91008f7bc194290f7f5bd8e0`。
- A0 精确绑定：`openharmony/systemabilitymgr_safwk` commit `21c83c874a34e8d28e6a355a3b56e5167252ed27`，tree `e115202d315867371b3b7c885b4f017e10cb163f`；目标文件 `services/safwk/src/local_ability_manager_stub.cpp` blob `e08d0c62c1fa8bc296d601f2049d0c570cb6783c`，13,827 bytes，SHA-256 `e3992a67f44b497f120d96e73d3692bf3b62e158a7191babb9506d379cb84f16`。
- 当前 production CLI 0.12.12 / `oh-ipc-2026.10-v32` 精确扫描该文件：3 条诊断，解析 `partial`，detector 覆盖 `partial (0 complete / 1 partial)`。三条候选均与 A0 的位置和规则对应；目标文件的 partial 状态不允许据此判 PASS。

| A0 | 行 | A0 规则 | 当前 CLI finding | 源码观察 |
|---|---:|---|---|---|
| CR-0244 | 93 | `ipc.relay.descriptor-boundary` | `ohscanner.interface.ipc:02da7dacd4dae341`，同规则 | `OnRemoteRequest` 调用 `EnforceInterceToken`；失败立即返回 `ERR_PERMISSION_DENIED`。实现读取 interface token 并与 `LOCAL_ABILITY_MANAGER_INTERFACE_TOKEN` 比较。候选与可见 guard 需要 detector/model 复核，不证明跨接口访问。 |
| CR-0245 | 98 | `ipc.relay.descriptor-boundary` | `ohscanner.interface.ipc:07fce4eb18a5a3f6`，同规则 | dispatcher 在查 `memberFuncMap_` 和调用 handler 之前执行 `CheckPermission(code)`；权限失败立即拒绝。该行不是 descriptor 比较本身，而是调用者授权检查。 |
| CR-0246 | 131 | `ipc.auth.missing` | `ohscanner.interface.ipc:f041d0e6789ac565`，同规则 | `StartAbilityInner` 验证 SA ID、event string 后调用 `StartAbility`。此私有 handler 由头文件中的 `LocalStartAbility` trampoline 注册到 START transaction；可见上游 dispatcher 在所有 handler 前进行权限校验。 |

## 授权及调用上下文

`CheckPermission` 读取 `IPCSkeleton::GetCallingTokenID()`，对 `SYSTEM_ABILITY_EXT_TRANSACTION` 检查 `ohos.permission.ACCESS_EXT_SYSTEM_ABILITY`，对 `SERVICE_CONTROL_CMD_TRANSACTION` 检查 `ohos.permission.CONTROL_SVC_CMD`，其它 transaction（包括 START）检查 `ohos.permission.MANAGE_SYSTEM_ABILITY`，并仅在 `VerifyAccessToken` 返回 GRANTED 时继续。由此，CR-0246 的局部 handler 候选不等于 dispatcher 可达路径上缺少权限检查；CR-0245 也对应权限保护。权限定义/签发主体、产品实际启用配置、目标服务注册与外部 IPC peer 可达性仍需产品级证据。`StartAbility` 解析事件 JSON，设置 start reason 并异步启动目标 SA；实际目标及其影响依赖产品配置。

精确源码树的 `interfaces/innerkits/safwk/BUILD.gn` 将该文件纳入 `ohos_shared_library("system_ability_fwk")`，在 `is_standard_system` 条件下依赖 access-token 与 IPC 库。Safwk 单元测试 target `test/services/safwk/unittest/BUILD.gn` 同样编译该源文件；相关测试覆盖 `OnRemoteRequest`、`StartAbilityInner` 和 `CheckPermission`。本轮未构建/运行这些测试，且单测不替代产品授权配置或外部调用路径证据。

## 结论与 A0 保留

结论 `PARTIAL/BLOCK`：源码观察显示 dispatcher 有 descriptor token 和基于 transaction 的 access-token permission 检查，并且这些检查先于 handler 分派；当前扫描仍将相关位置报为 descriptor/auth 候选，属于需复核的 detector 与解析差异。文件解析 partial、产品权限授予与 peer reachability 未绑定、无可信修复版/对照，故不能作为通过或安全结论。CR-0244、CR-0245、CR-0246 均保持 A0 原状态 `not_testable / paused_pending_evidence`。未修改 detector、tests、fixtures、API 或队列。复核命令：`python research/evidence/cpp/verify_t45_safwk_ipc_audit_20261027.py`。
