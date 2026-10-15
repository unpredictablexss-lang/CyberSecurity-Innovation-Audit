# RC-JSPROXY 下一轮取证限制（A-EVID-02-NEXT）

结论保持：`component_validation=met`、`product_gate=not_met`、`candidate/unknown`、`validated_vulnerability=0`。本轮只补齐逐项证据账本、固定 Gate 重放、限制和下一取证清单；没有升级 `confirmed/reportable`，没有修改历史报告、候选 ID 或 review。

## 本轮实际检查边界

- 审计 checkout：分支 `codex/full-runtime-performance-audit-20261014`，HEAD `0e94ceafab1b2d79547bdf71c86e26e8b42a6b48`，tree `cee6b4609e65f2954114b368761614d5f745d6a6`，remote `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`。原有 dirty worktree 和生成证据保持不变，未 push。
- 目标源码：`openharmony/distributeddatamgr_kv_store` commit `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`、tree `3b92c53fde616d5a3f9487b0c295670a42c63023`。关键文件 blob/source SHA-256 已逐项写入 `next-evidence-ledger.json`。
- 可用产品侧局部仓库：`build`、`manifest`、`vendor_hihope` 和独立 `distributeddatamgr_kv_store` checkout；均记录 commit/tree。它们不是完整 OpenHarmony 产品 checkout。
- 产品构建入口曾按 `rk3568/user` 尝试两次，均因 CRLF 入口脚本和完整源码树缺失而失败；本轮未重复构建失败实验，也未把组件 Harness 产物写成产品产物。

## 不能从当前证据推出的内容

1. **产品构建与产物**：没有完整 `.gn`、`foundation/distributeddatamgr/kv_store/BUILD.gn`、`device/board/hihope/rk3568`、`prebuilts/build-tools`、`prebuilts/python`、`prebuilts/clang`。没有 vulnerable / fixed_control_mutex / patched_atomic_minimal 的产品 path、SHA-256、size、install path。
2. **产品入口和权限**：源码可见 `getResultSet`、`closeResultSet`、`getEntry`、`NapiQueue::AsyncWork` 和 `GetInstance/SetInstance`，但没有产品部署包解析、runtime symbol、permission grant/deny、caller identity、UID、user、sandbox、privilege、exported surface 或 attacker control 证明。`source-visible` 不等于 `product reachable`。
3. **产品交错 trace**：组件 Harness 的 ThreadSanitizer 结果只证明其受控模型中的 race。它不是产品线程/队列 trace，不证明 UAF、DoS、泄露、内存破坏、稳定崩溃或可利用性。
4. **CIA**：availability、integrity、confidentiality 均无产品级分母、测量结果或 verified negative。当前不作泄露或完整性影响声明。
5. **影响范围**：模块已绑定固定源码对象；`vendor_hihope/rk3568/config.json` 的 `version=3.0`、`api_version=8` 只是局部 profile 观察，未与固定 kv_store commit 的产品 image/tag/branch manifest 闭合。affected version/branch 仍 unknown。
6. **CWE/CVE**：CWE-362 仍是基于源码 owner 读写和组件 TSan race的候选根因。CWE-416 不作为已证实后果。NVD 三个关键词查询为 0 结果，GitHub commit search 仅返回两个 `getEntry` 搜索命中；这些都不是 CVE assignment 或“无 CVE”证明。没有伪造 CVE ID。
7. **修复重验**：mutex control 和 atomic patch 有 patch/source hash 及组件级 clean 对照，但没有真实产品 patch apply、同 profile 三 variant 构建、产品 trace/CIA 重验。

## Gate 和后续新证据

固定 Gate 已重放两次，`validation.json` 两次 SHA-256 均为 `4785ecb9ad58b61694440065800ab4a352173519bf27ec0f0eae37e74f1840db`，结果始终为 `product_gate=not_met`。所有 high/critical unknown 均保留。

负责人若提供新的产品 checkout、构建产物或设备 trace，必须继续使用 `src/ohscanner/poc/rc_jsproxy_product_gate.py` 固定 Gate 重放，并保存每次命令、环境、重复次数、artifact/trace hash、失败/timeout/unknown。只有产品 build、entry/permission/identity/deployment、product trace、CIA、scope、CWE/CVE 全部有可审计证据且无 high/critical unknown，才进入 `confirmed_reportable_review`；最终状态变化仍需项目负责人授权。

## 2026-10-15 A-EVID-02 product collection attempt

结论仍为 `component_validation=met`、`product_gate=not_met`、`candidate/unknown`、`validated_vulnerability=0`；没有直接修改 `confirmed/reportable`。

本轮新增并绑定：

- 部分 pinned source manifest：`inputs/pinned-source-manifest.partial.json`，SHA-256 `288f2de3e43bd9f86ab4ddb5ae10731758255c97cb4c7d92b10f8d830cc44e63`。480 个声明项目中仅 6 个 checked-out、1 个 Git index 损坏、473 个缺失，不能称为完整 pinned manifest。
- 部分 toolchain manifest：`inputs/toolchain-manifest.partial.json`，SHA-256 `4c5756e9c1b91cc08c73e8e5b195b6b580eda95e5c7f3aafa2589e9cf6d4a5c4`。GN/Ninja/Python/Node 有 hash 绑定；clang/hvigor 不完整，且 WSL ext4 多次 recovery。
- 部分 GN 依赖闭包：`inputs/dependency-closure.partial.json`，SHA-256 `3d53dfa365315ed30ae6d4965d291db080341b6c3cc4838a435a4dd52b1a887c`。三次 `--build-only-gn` 均未进入 GN 图解析。
- 设备运行时：`inputs/device-runtime-availability.json`，SHA-256 `271a41dc8538218a3d544e4ca4b7bdffb3b7ac9e0df115bb808cc6830da0b108`。未发现 rk3568/OpenHarmony 设备，故产品 trace、permission/UID/user/sandbox、导出面和 CIA 均无法执行。
- 产品源码补丁 apply check：`inputs/product-source-patch-apply-check.json`，SHA-256 `06031e845d51f413443dd32523881e6b4f7e1283ebd2b6ecbfaec48142c65139`。这只证明两个 patch 能 apply 到 audited source，不是产品修复重验。
- 固定 Gate 重放两次，`validation.json` 两次均为 SHA-256 `229dfe6753206defbed7b98f018cee4f46eebaed034d1990ce45479369c38ede`，结果始终 `product_gate=not_met`。
- 定向测试 16/16 通过，日志 SHA-256 `68836a8450ce954cdb481e653164a2eeeebbc1e4cacd345e87eab2d621cb7664`。

本轮逐项证据账本：`attempt-evidence-ledger-20261015.json`，SHA-256 `e1156a56d478cfbd56329cc284ed7d42e8b0031d7b7f4fea6dd0057d0b7d5bbd`。

`validation.json` 中 `product_build_method.preflight=ready` 仅表示固定 Gate 的 8 个路径检查存在（`.gn`、build 入口、kv BUILD、rk3568 board/vendor、build-tools、python），不表示完整 OpenHarmony source/toolchain/GN dependency closure 已通过。实际三次 GN preflight 均失败，产品构建仍为 `preflight_ready_unexecuted`，因此不能把该 shallow preflight 解释为产品可构建。
