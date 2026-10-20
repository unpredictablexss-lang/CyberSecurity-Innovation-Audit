# C 线 Ark Runtime 构建尝试记录（2026-10-20）

## 绑定身份与问题

- OHScanner scanner 基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`。
- Ark Runtime 仓库：`openharmony/arkcompiler_ets_runtime`，HEAD `a65a2853ccae13da167d9aa4720ab8b11ec16656`，tree `8781f036a3e7e04d8e0b34970d5f623b42875016`。
- 候选：`ecmascript/builtins/builtins_typedarray.cpp` 中普通 array-like `TypedArray.set` 的 offset 转换/写入边界；scanner 同 SHA 源码分析记录在 `C_LINE_ARK_STAGE_DELIVERY_20261020.md`。
- 本次目的：构建实际 Ark host 目标并运行边界 witness。没有运行成功的 Runtime 或前端，本报告不把源码推演称作 Runtime 证据。

## 隔离和工具链

- WSL2 Kali x86_64。完整 OH 源树位于 Windows D:，通过只读 bind mount 暴露给 staging；`findmnt` 确认 staging 根为只读 9p。staging 的 `prebuilts` 通过 OverlayFS 挂载，upper/work、`out`、HOME 与日志均在 WSL ext4 `/tmp/c-runtime-ark-overlay-20261020/`。
- `build.sh` 私有初始化实际报告 Node.js `v14.21.1`、ohpm `5.0.8`，ohpm 初始化成功；提示 Node 14 低于推荐的 Node 18。GN/Ninja/clang 均未启动。
- 首轮默认目标触发了可选 `ohos-sdk` 构建，长时间停在 `[LOAD] Checking all build args...`，没有进入 GN/Ninja。该进程组已停止，日志和输出保留于 `/tmp/c-runtime-ark-overlay-20261020/build.log` 与 `/tmp/c-runtime-ark-overlay-20261020/out/`。
- 依根任务要求改用 `--no-prebuilt-sdk=true` 重试。精确命令：

```sh
bash ./build.sh --product-name rk3568 \
  --build-target ark_js_host_linux_tools_packages \
  --no-prebuilt-sdk=true
```

- 工作目录为只读 staging 源根 `/mnt/d/openHarmonyScanner/tmp/c-runtime-ark-build-20261020/root`；单独 out 为 `/tmp/c-runtime-ark-overlay-20261020/out-nosdk`，HOME 为 `/tmp/c-runtime-ark-overlay-20261020/home-nosdk`，日志为 `/tmp/c-runtime-ark-overlay-20261020/build-nosdk.log`。
- 构建脚本将 `--prebuilt-sdk=true` 附加在传给 HB 的参数末尾，但显式 `--no-prebuilt-sdk=true` 仍同时存在。HB 写入私有 hb args 与 rk3568 preloader 文件后，约 3 分钟仍停在 `[LOAD] Checking all build args...`。Python HB worker 多数处于对 D: 9p 源树元数据读取的 D 状态；没有 GN、Ninja、clang 进程，out 约 204 KiB，仅含参数和 preloader 信息。
- 为控制挂起时间，向本次确认的进程组 414 发送 TERM；进程已退出。日志和 out 均保留，没有清理或覆盖。
- 结果：构建未进入编译阶段；无 Ark Runtime 二进制或可运行测试工件。`ark_js_host_linux_tools_packages` 未完成。这个 blocker 是 Kali/WSL 9p 上 HB 参数加载停滞，不能解释为源码构建失败或测试通过。

## witness 与当前结论

计划中的动态 witness：8192 字节 backing buffer，sibling view `[0,4096)` 初始化 `0x11`，target view `[4096,8192)` 初始化 `0x22`，Proxy array-like length 4096 且数值属性返回 `0x5a`；调用 `target.set(source, 18446744073709549568)`。controls 为 offset 0 的正常写入及 offset 4097 的范围错误。

按已有源码路径的算术推演，候选会在 target view 之前开始写：目标 view 的 backing 起点为 4096，窄化后的起始偏移推演为 -2048，绝对 backing 起点为 2048。预期被改写的 sibling 索引为 `[2048,4096)`；该区间仍在 8192 字节 backing buffer 内，属于 sibling view 可观察范围。这是**源代码层级预测**，三个问题目前均无动态观察证据：

- 是否真的在 target view 边界之前发生写入：未运行，unknown。
- 写入是否越过 backing-buffer 边界：源码推演认为不会；Runtime 结果未运行，unknown。
- 相邻 sibling view 是否观察到写入：源码推演预期可观察；Runtime 结果未运行，unknown。

offset 0 与 4097 controls、官方 `typedarrayset` 模块测试、真实修复版本对照均为 `not_run`。本轮没有提出产品影响、漏洞确认或修复结论。

## 环境准备旁注

一次预置依赖盘点误启动了官方宽范围 `prebuilts_config.py` 下载器，随后已停止；其缓存中的 9 个官方归档均按对应 SHA-256 校验，且未删除或重置。共享 `openharmony/prebuilts` 与 `/root/.prebuilts_cache` 的新增内容和校验信息已单独完整发送给任务负责人；后续构建只使用只读 source bind 与私有 overlay。Hvigor 归档及构建准备文件放在私有 `/tmp`，没有改 Ark 生产源码。

## 可复现证据位置

- 首轮日志：`/tmp/c-runtime-ark-overlay-20261020/build.log`
- 无 SDK 重试日志：`/tmp/c-runtime-ark-overlay-20261020/build-nosdk.log`
- 两轮隔离输出：`/tmp/c-runtime-ark-overlay-20261020/out/`、`/tmp/c-runtime-ark-overlay-20261020/out-nosdk/`
- 部分完整仓库复制曾因耗时停止；部分目录保留于 `D:\openHarmonyScanner\tmp\c-runtime-ark-build-20261020\private\prebuilts`，未清理。
