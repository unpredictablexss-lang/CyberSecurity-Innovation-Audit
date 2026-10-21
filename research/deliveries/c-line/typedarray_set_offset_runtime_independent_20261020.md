# TypedArray.set 超大 offset 独立复核（源码与运行环境）

日期：2026-10-20（Asia/Shanghai）  
独立测试分支：`codex/c-runtime-test-closeout-20261020`  
OHScanner 代码基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`  
基线 tree：`764f7698f6babdcccb2cd68eba75ed1b0afefc9e`  
Ark Runtime 源码：`a65a2853ccae13da167d9aa4720ab8b11ec16656`

## 独立源码复核

独立按调用点和整数表达式复核了 developer correction 中的算例。固定源代码在 `BuiltinsTypedArray::Set` 的 array-like 分支先将 offset 变为 `uint64_t`，再计算长度和；其后基于目标 view 的 `targetByteOffset` 计算并窄化 `targetByteIndex`，再以 32 位 `limit` 控制逐元素写入。

取 `x = 18446744073709549568 = 2^64 - 2048`、`srcLen = 4096`、`targetLength = 4096`、`targetByteOffset = 4096`、元素大小 1：

- `srcLen + x` 按 `uint64_t` 回绕为 2048，故 `2048 > 4096` 为假。
- `(x + targetByteOffset) mod 2^32 = 2048`，得到窄化后的写入起点。
- `limit = 2048 + 4096 = 6144`，所以循环范围是 `[2048, 6144)`，共 4096 次。
- 目标 view 位于 backing buffer `[4096,8192)`；候选中 `[2048,4096)` 的 2048 次写入位于 view 之前，但仍在 8192-byte backing buffer 内。

该结论是对固定源码及整数算术的独立复核。它不是 Ark VM 执行结果，也不证明产品采用该源码或构建配置。按父任务提供的 PoC 形状，长度为 4096 的 Proxy array-like 对象可逐个提供源值；我未在任何运行时执行它。

## 构建及运行路径核查

固定 checkout `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime` 的 `.git/HEAD` 由 WSL Git 读取为 `a65a2853ccae13da167d9aa4720ab8b11ec16656`。官方仓内 `test/jsperftest/README.md` 给出的 x86_64 构建命令为：

```sh
./build.sh --product-name rk3568 --build-target ark_js_host_linux_tools_packages --build-target ets_frontend_build
```

仓内 `test/run_ts_test262.py` 使用 `ark_js_vm` 运行 `.abc` 文件。当前 runtime checkout 的 `out/` 中无 `ark_js_vm`、`ark_js_host*` 或 `es2abc`。随后对整个 `D:\openHarmonyScanner` 做文件名搜索（排除 `.git`）也未找到上述执行文件；搜索记录了两个含尾随点目录的 Windows 路径错误，未发现的结论限于可访问文件路径。

观测到的工具链状态：WSL Linux 有 Python `3.14.7`，没有 `node`（`node: command not found`）；Windows 主机可解析 `node.exe`，但版本为 `22.14.0`，不是项目要求的 Node 14.21.1。先前共享构建尝试记录缺少 Linux Python 预置及 Hvigor；本独立任务没有启动构建，也没有修改共享源码、构建输出或工具链。

因此 Ark Runtime PoC、in-view 正控制、越界拒绝控制均为 **not_run**。这不是失败或通过。Python/JS host 上的算术模拟即使执行，也只能核对数学，不可作为 Ark Runtime 证据；本报告不将其计为 runtime 测试。

## 运行时测试假设（待可执行二进制）

若得到可验证来自上述源码 commit 的隔离 host runtime 与前端，运行含三种独立场景的 JS/ABC：

1. 候选：8192-byte backing；兄弟 view `[0,4096)` 初始化 `0x11`；目标 view `[4096,8192)` 初始化 `0x22`；Proxy 源 `length=4096`，索引值 `0x5a`；offset `18446744073709549568`。预期若候选执行，兄弟 view 后半与目标 view 前半变为 `0x5a`。
2. 正控制：普通 in-view offset `0`，验证 array-like 路径和读写样本正常。
3. 拒绝控制：target 长度 4096、源长度 1、offset 4097，验证 range-error 行为。

以上是待测试假设，不代表观察结果。记录每个命令退出码、runtime/frontend SHA 和 stdout/stderr；若构建产物来自其他源码版本，不将其用于此固定源码结论。

## 结论状态

- 超大 offset 经固定源码转换路径：`reachable`（源码级）。
- 目标 view 前置写：`candidate`（经独立源码算术复核）。
- backing ArrayBuffer 边界越界：此算例不支持。
- Ark Runtime PoC / 正控制 / RangeError 控制：`not_run`（无可用二进制；本轮未构建）。
- 产品配置、入口及影响：`unknown`。
