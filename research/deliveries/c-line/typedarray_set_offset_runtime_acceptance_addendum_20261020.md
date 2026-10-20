# TypedArray.set 运行时独立验收补充：未取得执行产物

日期：2026-10-20（Asia/Shanghai）  
OHScanner 固定基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`（tree `764f7698f6babdcccb2cd68eba75ed1b0afefc9e`）  
Ark Runtime 固定源码：`a65a2853ccae13da167d9aa4720ab8b11ec16656`

## 来源与隔离构建尝试

独立复核时重新读取了 Ark checkout HEAD，并对 `ecmascript/builtins/builtins_typedarray.cpp` 重算 SHA-256：`14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c`，与 pinned blob 对应的既有哈希一致。

开发线使用只读 bind 的 OpenHarmony 源树、私有 prebuilts overlay、独立 `/tmp` HOME 和 `out` 路径尝试构建，避免改动共享源树/输出。runtime 不在可执行状态时，我没有在来源不明或其他版本二进制上运行测试。

最后一次 Ark host 目标尝试命令：

```sh
bash ./build.sh --product-name rk3568 --build-target ark_js_host_linux_tools_packages --no-prebuilt-sdk=true
```

记录位置：

- 构建日志：`/tmp/c-runtime-ark-overlay-20261020/build-nosdk.log`
- 隔离输出：`/tmp/c-runtime-ark-overlay-20261020/out-nosdk`
- 工作区 staging：`D:\openHarmonyScanner\tmp\c-runtime-ark-build-20261020\root`（WSL 内 `/mnt/d/openHarmonyScanner/tmp/c-runtime-ark-build-20261020/root`）

该命令日志包含 ohpm 初始化成功及为 `rk3568` 生成的 preloader 元数据，最后可见行停在 `[LOAD] Checking all build args...`。随后核查时没有正在运行的 hb/build.sh/ninja 构建进程；隔离输出下没有 `ark_js_vm`、`es2abc` 或 `ark_js_host*` 可执行文件。进程终止时的退出码没有被捕获，故不推断具体失败诊断。`--no-prebuilt-sdk=true` 绕过了共享旧日志所示 SDK bootstrap，但未产生可运行 Ark runtime。

工具链来源：开发线报告下载并校验了官方 Node 14.21.1 和 Hvigor 5.0.3.906；Linux Python 3.12.10 来自 OpenHarmony prebuilts。仍缺少的具体终端原因无法从最后日志行确定；可证的阻塞是构建未到生成 host runtime 的阶段，且没有可执行产物。

## 独立验收状态

以下用例均未运行（`not_run`）：

1. 8192-byte backing buffer、前后相邻的 sibling/target 4096-byte Uint8Array views、Proxy array-like 长度 4096 及大 offset 候选。
2. `offset = 0` in-view 正控制。
3. `offset = 4097` RangeError 拒绝控制。

没有记录 runtime stdout/stderr、退出码或最终字节，因为没有经过源码身份核验的 `ark_js_vm` / 前端可执行文件。之前独立报告中的源码算术只证明静态候选的整数计算，不是 Python 模拟或 Ark VM 实测。

最终分类：转换路径 `reachable`（源码级）；目标 view 前置写 `candidate`（静态源码候选）；三项 runtime 验收 `not_run`；产品影响及构建配置 `unknown`。本报告不将构建缺产物记作 PoC 测试失败或通过。
