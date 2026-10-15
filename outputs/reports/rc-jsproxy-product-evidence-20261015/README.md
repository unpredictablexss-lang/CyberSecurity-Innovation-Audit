# RC-JSPROXY 产品证据包

结论：`candidate/unknown`，`validated_vulnerability=0`，`confirmed/reportable=false`。

本目录是 A-EVID-02 的产品级证据闭环交付包。`inputs/product-evidence.template.json` 是唯一产品证据模板；`inputs/product-evidence.json` 是当前按该模板采集的产品证据实例。`src/ohscanner/poc/rc_jsproxy_product_gate.py` 是 fail-closed Gate，本次重放结果为 `component_validation=met`、`product_gate=not_met`，因此不升级候选状态。

## 目录

- `inputs/`：A 线证据、方法卡、PoC manifest、组件 Harness/PoC、产品证据模板和当前实例、产品构建 preflight、Gate 源码。
- `run-context.json`：checkout、目标仓库、执行环境、命令、重复次数、失败原因和运行日志 hash。
- `evidence-ledger.json`：逐项 source/evidence hash、执行环境、命令、重复次数、失败原因、结论和 promotion effect。
- `validation.json` / `validation.md`：Gate 生成的机器可读义务矩阵和人读限制说明。
- `logs/`：定向测试、Gate 重放、checkout、目标范围和 `git diff --check` 日志。
- `fixed_control_mutex.patch` / `patched_atomic_minimal.patch`：组件级安全控制和最小拟议补丁；不是产品修复。
- `limitations.md`：不能从当前证据推出的结论。
- `next-evidence-checklist.md`：项目负责人下一步取证清单。

## 证据边界

组件级 exact-header Harness 已在 WSL2 中以 ThreadSanitizer 重现 `CloseResultSet`/`getEntry` owner race，并完成 `vulnerable / fixed_control_mutex / patched_atomic_minimal` 各 3 次对照。它证明的是组件 Harness 的受控 race，不是 OpenHarmony 产品进程中的可达性、稳定崩溃、UAF、数据泄露、权限提升或可利用性。产品构建、产品入口/权限/身份/部署、产品交错 trace、CIA、影响版本/分支和 CVE 检索范围仍缺失或 unknown。

## 2026-10-15 A-EVID-02 attempt update

本轮已补齐部分 source/toolchain/dependency manifests、设备可用性、源码 patch apply、影响范围和逐项证据账本，但没有得到任何 rk3568/user 产品 artifact、产品 runtime trace 或 CIA 测量。固定 Gate 两次重放 SHA-256 均为 `229dfe6753206defbed7b98f018cee4f46eebaed034d1990ce45479369c38ede`，仍为 `product_gate=not_met`。详见 `limitations-next.md` 与 `attempt-evidence-ledger-20261015.json`。
