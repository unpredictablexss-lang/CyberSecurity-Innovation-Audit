# RC-JSPROXY 产品证据取证清单（2026-10-15 下一轮）

用途：为 `A-EVID-02-NEXT` 采集真实产品证据。每项都必须保存 repository、full commit、tree、blob/source SHA-256、artifact/trace/result SHA-256、exact argv/environment、重复次数、失败/超时原因。组件 Harness binary hash 不得进入产品 artifact hash。缺证据保持 `unknown`，不填 `safe`、`miss` 或 `verified`。

## 1. 固定产品源码清单

- [ ] 从完整 OpenHarmony checkout 导出 per-project pinned manifest；每行包含 repository、path、full commit、tree、snapshot hash。
- [ ] 禁止 `revision=master`；保存 manifest 文件 SHA-256 和生成命令。
- [ ] 保留当前局部观察：manifest `077460ee7a284b4f45816764337fea99eb4057cb` 的 `default_small.xml` blob `802d516038203cb261d013f4ebcd04c925972708`、SHA-256 `37c6186ff503e4df93f134fffcbbd0f2a845552cf415270a58899f7351fad215`；它仍是 moving revision，不能当 pinned manifest。
- [ ] 失败时记录缺失项目、未解析 revision、snapshot/tree 不一致和命令退出码。

## 2. 工具链清单

- [ ] 采集 OpenHarmony SDK、GN、Ninja、hvigorw、Java、Python、prebuilts/build-tools、prebuilts/clang、compiler、linker 的 exact path、version、binary SHA-256。
- [ ] 保存 `toolchain_manifest_sha256`、生成命令、host/platform、环境变量和失败项。
- [ ] 当前只能观察 `build.sh` 声明 Node `14.21.1`、`toolchain.gni` 声明 clang `15.0.4`；实际 prebuilts 缺失，不能当工具链证明。

## 3. GN/Ninja/NAPI/device/prebuilts 依赖闭包

- [ ] 在完整 root 上执行 GN target 解析和 Ninja graph/package/install graph；保存 resolved args。
- [ ] 覆盖 NAPI、ability、IPC、common-event、device/board、prebuilts、mock fallback 和 package/install path。
- [ ] 保存 `build_manifest_sha256`。当前 `BUILD.gn`/`kv_store_deps.gni` 只有 source-visible declarations，不能替代 resolved closure。

## 4. 三种产品产物

- [ ] 在同一 `rk3568/user` profile 下分别构建 `vulnerable`、`fixed_control_mutex`、`patched_atomic_minimal`。
- [ ] 每个 variant 保存 exact argv、build log SHA-256、variant source SHA-256、patch SHA-256、artifact path、artifact SHA-256、size、install/package path。
- [ ] 产品 artifact identity 不得包含组件 Harness binary/output hash。
- [ ] 任何一个字段缺失，variant 状态保持 `unknown`。

## 5. 产品入口和 runtime symbol

- [ ] 从部署包/module resolution 追到 `SingleKVStore.getResultSet`、`SingleKVStore.closeResultSet`、`KVStoreResultSet.getEntry`、`NapiQueue::AsyncWork`。
- [ ] 保存产品 artifact hash、runtime symbol/versioned symbol、JS/NAPI call trace 和 source location。
- [ ] 把 source-visible 与 product reachable 分栏；不能用源码存在替代产品入口证明。

## 6. permission、UID、user、sandbox、exported surface

- [ ] 记录 permission name、grant_mode、grant/deny/failure result、caller app identity、UID、user、sandbox、privilege。
- [ ] 记录 exported surface、跨应用/IPC/remote 入口、设备/用户边界和 attacker control 条件。
- [ ] 测试 permission denied 和默认无权限路径；保存失败结果和日志 hash。

## 7. 产品级 CloseResultSet/getEntry 交错 trace

- [ ] 每个 variant 至少 3 次，记录 repeat、thread ID、JS/async-execute/complete queue、`GetInstance`/`SetInstance`/`CloseResultSet`/`getEntry` source location。
- [ ] 记录 overlap start/end event、产品 artifact SHA-256、trace SHA-256、timeout/failure reason。
- [ ] Harness TSan trace 只作为组件对照，不能填入产品 trace 字段。

## 8. availability / integrity / confidentiality 测量

- [ ] availability：产品 process/API failure、crash/no-crash、重复次数和分母。
- [ ] integrity：returned entry/state divergence 或 verified negative。
- [ ] confidentiality：same-app、cross-app、device boundary 或 verified negative。
- [ ] 三个维度都保存 exact command、repeat、denominator、result hash；没有测量就保持 unknown。

## 9. affected module / version / branch

- [ ] 把固定 kv_store commit/tree 与产品 image/version/tag/branch manifest 绑定。
- [ ] 每个 module/version/branch item 保存 evidence SHA-256。
- [ ] `vendor_hihope/rk3568/config.json` 的 `version=3.0`/`api_version=8` 仅可作 profile 观察，不能直接当 affected version。

## 10. CWE/CVE 检索记录

- [ ] 保存 CWE-362 根因和 trace 依据；UAF/DoS/泄露后果必须另有产品证据。
- [ ] 保存 bounded CVE/NVD/upstream query、时间、范围、结果 hash；0 命中不是无 CVE。
- [ ] 如果没有 assignment，保存独立 reviewer 的 no-assignment/unknown 签名；不要伪造 CVE。

## 11. 产品级修复重验

- [ ] 在真实产品源码分别应用 `fixed_control_mutex.patch` 与 `patched_atomic_minimal.patch`。
- [ ] 同 profile 重跑三 variant 各 3 次，保存 patch apply、build、trace、CIA、artifact hash。
- [ ] 组件级 clean 不等于产品修复通过。

## 12. 固定 Gate 重放和授权

- [ ] 新证据到达后继续使用 `src/ohscanner/poc/rc_jsproxy_product_gate.py`。
- [ ] 保存 Gate 输入 hash、exact argv、每次输出 `validation.json` hash、全部 failure/unknown。
- [ ] 只有 build、entry/permission/identity/deployment、trace、CIA、scope、CWE/CVE 全部有证据且无 high/critical unknown，才进入 `confirmed_reportable_review`；最终状态变化需项目负责人授权。
