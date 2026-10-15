# 下一步取证清单

以下是解除 `product_gate=not_met` 所需的最小证据，不代表当前已经满足。

1. **固定产品源码清单**：从完整 OpenHarmony checkout 导出 per-project pinned manifest，记录 repository、commit、tree、blob/source SHA-256、snapshot hash 和 manifest SHA-256；禁止 `revision=master` 作为产品范围。
2. **工具链清单**：记录 OpenHarmony SDK、GN/Ninja、hvigorw、Java、Python、prebuilts/build-tools、编译器、链接器和 build system 版本/路径/文件 hash，形成 `toolchain_manifest_sha256`。
3. **依赖闭包**：保存 GN target 解析、NAPI/ability/IPC/common-event/device/prebuilts 依赖图、resolved args、package/install graph 和 `build_manifest_sha256`。
4. **三种真实产品产物**：在同一 `rk3568/user` product profile 下构建 `vulnerable`、`fixed_control_mutex`、`patched_atomic_minimal`，分别记录 exact argv、build log hash、variant source hash、patch hash、artifact path、SHA-256、size、install/package path。不要填组件 Harness binary hash。
5. **产品入口链**：从部署包/module resolution 追到 `SingleKVStore.getResultSet`、`SingleKVStore.closeResultSet`、`KVStoreResultSet.getEntry`、`NapiQueue::AsyncWork` 的 runtime symbol 和产品 artifact hash；source-visible 必须另证 reachable。
6. **权限/身份/边界**：记录 permission name、grant_mode、deny/failure result、caller app identity、UID、user、sandbox、privilege、exported surface、跨应用/IPC/remote 入口和 attacker control。
7. **产品交错 trace**：每 variant 至少 3 次，记录 repeat、thread ID、JS/async-execute/complete queue、`GetInstance`/`SetInstance`/`CloseResultSet`/`getEntry` 源位置、overlap start/end event、产品 artifact hash、trace hash 和失败/超时原因。
8. **CIA 测量**：availability 记录产品进程/API 失败率或稳定无故障；integrity 记录 returned entry/state divergence 或 verified negative；confidentiality 记录 same-app/cross-app/device boundary 或 verified negative。所有测量要有命令、重复次数、分母和结果 hash。
9. **影响范围**：把 fixed commit/tree 绑定到产品 image/version/tag/branch manifest；模块、版本、分支每个 item 都要有 evidence hash。
10. **CWE/CVE**：保存 CWE-362 根因/trace 依据；做 bounded CVE/NVD/upstream 搜索并保存 query、范围、时间、结果，或由独立 reviewer 明确签署 no-assignment/unknown。
11. **修复重验**：真实产品源码上分别应用 fixed control 和 proposed atomic patch，使用相同 profile 重跑三 variant 三次；保存 patch apply、build、trace、CIA 和 artifact hash。
12. **Gate 重放和授权**：用 `src/ohscanner/poc/rc_jsproxy_product_gate.py` 重放，只有产品 build、entry/permission/identity/deployment、trace、CIA、scope、CWE/CVE 全部有证据且无 high/critical unknown 时才进入 `confirmed_reportable_review`；最终状态变化仍需项目负责人授权。
