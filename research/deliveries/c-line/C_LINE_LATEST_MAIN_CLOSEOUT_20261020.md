# C 线最新 Mainline 快速收尾结果（2026-10-20）

## 结果

C 线已验收的 Ark Runtime 静态集成变更已接到本轮 fetch 的最新主线。合并没有冲突；上游 D 线状态与证据文件保持为 `origin/main` 中的原始 blobs。

| 项目 | 结果 |
|---|---|
| 最新主线 | `c380a474718e8ec4497aff55b18a1dd38bafa13f` |
| 集成代码提交 | `4e1268a980fd103326c7dbaa6ca2e78d2ba43e69` |
| 集成代码 tree | `0495b0db7d05f02e2ce4e48149f7571c8bdd8023` |
| 父提交 | `c380a474718e8ec4497aff55b18a1dd38bafa13f` + `764f7698f6babdcccb2cd68eba75ed1b0afefc9e` |
| 开发验证报告提交 | `c1f34e97326a61d68bc79282d782a3df37e128c9` |
| 独立测试报告提交 | `0b7ab8baf1e09e151dd88a0694da62cb49e1f906` |

## 开发与独立测试闭环

开发线在最新 main 集成代码上执行 Ark Runtime 212 项（209 passed、3 skipped），source-binding/Catalog/Parser/Runner 回归 59 项（58 passed、1 skipped），以及排除 Windows symlink 权限用例后的契约测试 19/19。独立测试线在隔离 checkout 对精确代码提交 `4e1268a980fd103326c7dbaa6ca2e78d2ba43e69` 重放：Ark Runtime 212 项通过、3 项跳过；source-binding、Runner、Catalog、契约、audit plan、known case、parser 和 detector regressions 共 97 项通过、1 项跳过；`git diff --check` 通过。测试线未发现生产代码或测试失败，因此没有额外代码反馈需要回传。

三项 Ark Runtime skip 的原因已记录：两个依赖的 pinned 历史 Ark Git store 未提供；一个仓库绑定 parser-owner 用例未配置 `OHSCANNER_ARK_REPO`。Windows 全契约测试中的 symlink 用例因 `WinError 1314` 被系统拒绝创建符号链接；可运行的其余契约测试通过。这些状态保留为 skip/环境限制。

## 结论边界与后续触发条件

集成保持 Ark Runtime `0.6.3` / model `0.8.14`、显式选择、默认关闭和精确 source-bound 限制。Float32Array 与条件性 `TypedArray.set` 仍为源码候选。产品运行时和 Ark VM 执行 `not_run`；产品适用性、入口与影响 `unknown`；没有计算正式 Precision/Recall，也没有确认产品漏洞。

本轮 C 线代码集成/独立回归达到 `CLOSEOUT_READY_WITH_LIMITATIONS`。后续只在出现具体 source/preprocessor 配置、可用 runtime 构建、可复现测试缺陷或其他新证据时，按开发→独立测试反馈循环开启相应切片；unknown/not_run 按现有状态保留，不反复重审相同证据。

## 复验报告

- 开发与最新主线集成：[C_LINE_MAINLINE_INTEGRATION_20261020.md](../../../../c-mainline-dev-closeout-20261020/research/deliveries/c-line/C_LINE_MAINLINE_INTEGRATION_20261020.md)
- 精确 SHA 独立复验：[C_LINE_MAINLINE_TEST_20261020.md](../../../../c-mainline-test-closeout-20261020/research/deliveries/c-line/C_LINE_MAINLINE_TEST_20261020.md)

## 收尾追加：TypedArray.set 运行时尝试

针对上节的源码级 view-boundary candidate，开发线在 Ark Runtime `a65a2853ccae13da167d9aa4720ab8b11ec16656` 上尝试了隔离 host-tools 构建。构建使用只读源码绑定、私有 ext4 OverlayFS 输出/HOME/prebuilts；官方预编译包的哈希已核验。HB 停在 `[LOAD] Checking all build args...`，工作进程等待 Kali/WSL 9p 源码读取，未启动 GN、Ninja 或 clang。为控制收尾范围，进程组经显式 TERM 停止，返回码 1 属于人工停止，不是自然构建失败。

开发报告：[C_LINE_ARK_RUNTIME_BUILD_ATTEMPT_20261020.md](../../../../c-runtime-dev-closeout-20261020/research/deliveries/c-line/stage_20261020/C_LINE_ARK_RUNTIME_BUILD_ATTEMPT_20261020.md)；独立验收补充：[typedarray_set_offset_runtime_acceptance_addendum_20261020.md](typedarray_set_offset_runtime_acceptance_addendum_20261020.md)。测试线核对了精确源码身份及隔离输出；没有 `ark_js_vm` 或 `es2abc`。候选 witness、offset 0 控制和 offset 4097 拒绝控制均为 `not_run`。源码算术候选仍是：写入 2048 字节落在非零 byteOffset 目标 view 之前，但仍在 backing ArrayBuffer 内。运行时行为、backing-store OOB、产品适用性和安全影响均未确认，分别保持 `not_run` / `unknown`；不报告漏洞确认或准确率指标。

本轮以可交付源码结论、独立算术复核及明确记录的运行时构建阻塞收尾。任务树状态仍为 `CLOSEOUT_READY_SOURCE_CANDIDATE_RUNTIME_NOT_RUN`；只有出现新的可用构建条件或其他具体证据时再开下一切片。

## 2026-10-21：最新 Ark 源码差异复核

Gitee `openharmony/arkcompiler_ets_runtime` 的 `HEAD` 与 `master` 现为 `d1a58d59166777e16574ceed64c15f0b2f44a76c`（tree `2cd854aa7d9f987de89d31a6a512e735779e75b6`），相较此前固定的 `a65a2853ccae13da167d9aa4720ab8b11ec16656` 有新源码变化。开发与独立测试线分别绑定相关源码的 Git blob 和 SHA-256，并比较 offset 转换、uint64 长度和、byte index 缩窄及最终写入路径。测试线要求补齐两个转换 helper 的对象身份并纠正 `Set` 行号；开发已修正，测试复核通过。

两线结论一致：非零 `byteOffset` view-boundary candidate 在 d1a58 中仍有源码支持。该结论只指向目标 TypedArray view 边界；本 witness 的写区间仍位于 backing ArrayBuffer 内。没有 Ark Runtime 执行或产品影响证据，backing-store OOB 未建立，runtime 保持 `not_run`，产品影响保持 `unknown`。详见开发报告 [C_LINE_ARK_SOURCE_DELTA_D1A58D5_20261020.md](../../../../c-runtime-dev-closeout-20261020/research/deliveries/c-line/stage_20261020/C_LINE_ARK_SOURCE_DELTA_D1A58D5_20261020.md) 与独立复核 [typedarray_set_offset_source_delta_independent_20261021.md](typedarray_set_offset_source_delta_independent_20261021.md)。
