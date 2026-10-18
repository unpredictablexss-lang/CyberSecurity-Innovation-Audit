# C1 Ark Runtime 产品构建 profile 取证（2026-10-18）

状态：**blocked**。这轮确认了固定源码与产品/板级 pin，但没有产品构建实际命令和依赖记录，不能提供可复现的编译/预处理 profile。

## 对象身份与一致性

当前 manifest 文件为 `D:/openHarmonyScanner/openharmony-manifest-current-20261018.xml`，117,629 bytes，SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`。其项目条目绑定：

| 项目 | commit | tree | 输入 blob / SHA-256 |
|---|---|---|---|
| arkcompiler_ets_runtime | `a65a2853ccae13da167d9aa4720ab8b11ec16656` | `8781f036a3e7e04d8e0b34970d5f623b42875016` | 目标 `.cpp` blob `68fb3b0adc4f9062889a861be51b7be90362e37a` / `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| vendor_hihope | `b40eabbe69943126c65df1f9ff28057f56e93e46` | `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb` | `rk3568/config.json` blob `fc7fed801d07f19f05a752878e738d8d40f1bc01` / `46dc640a6ca988687245de967f4e2ec3aebd20ed3423472c48b89bc845c28408` |
| device_board_hihope | `5d368fb765920c2b1cad41eb86164563461a7074` | `992544086dffa1a73ea444f7a22eeed25b149107` | `rk3568/config.gni` blob `12776e4d60dea146dd31c91ca93f84b3e41f6920` / `ca368f4a9db0302b4cd6c656c30e0c196070591251ac8777079861c0fd7d45b4` |

`vendor/hihope/rk3568/config.json` 标识 `product_name=rk3568`、`device_build_path=device/board/hihope/rk3568`、`type=standard`；manifest 指向的 vendor 与 board commit 对应这些输入 blob。Ark Runtime 精确 commit/tree、目标路径 blob 与 SHA-256 均从本地 Git object database 只读核实。因此候选配置与**源码 snapshot pin 一致**。该结论只证明配置候选和对象绑定，不证明曾用它完成产品构建。

## 本次取证工作区

OHScanner Git 工作区为 `CyberSecurity-Innovation-Audit`，branch `codex/a-line-scanner-regression-20261018`，HEAD `f8e3a0ad7463f216db4be7502bd8a19eec545908`（tree `8a77f63c93903b3b34aa3bd0a8ff1d04e57a0d60`），`origin/main` 本地 ref 为 `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`，origin URL 为 `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`。该工作区原有大量脏文件；本轮只新增本目录与本专属交付文件，没有把它误认为 OpenHarmony 源码仓库，也没有修改共享状态文档。当前 branch/worktree 是 A 线历史分支，C1 输出只按用户指定路径隔离，不能据此声称已有独立 C1 Git branch。

## 已观察与未知

直接观察：`config.json` 的 `target_cpu=arm`，板级 `config.gni` 声明 `armv8-a`、`cortex-a55`、`clang`；目标 `BUILD.gn` 有 `libark_jsruntime` 构建声明。来源和字节级索引在 [`profile_manifest.json`](../../experiments/ark_runtime/c1_profile_20261018/profile_manifest.json)。本地源码 `BUILD.gn` 的 SHA-256 为 `8e5f0d4d829578200b75175ea81e8ef2c8370fe4c331ab6a3b255cad95988a89`，但没有在本轮记录中证明其 blob 身份，不能把它当作固定 commit 的内容证据。

缺失：与该产品 build 对应的 compile database / Ninja command、`args.gn`、完整 argv、实际 clang 二进制和版本、target triple、宏、ordered include paths、生成头文件、depfile 闭包及各依赖哈希，以及这些构建输出对应本 manifest 的 provenance。故实际 compiler/preprocessor profile、宏和 include 顺序、生成输入闭包均为 **unknown**；没有执行构建或预处理，也没有编造宏表。未找到匹配的 `compile_commands.json`、GN `args.gn` 或产品 `out` 记录。目标只读源文件当前精确 blob 可用，但本地构建产物不足。

## 采集、复核与重放

以下命令只读取已有对象/文件，不 fetch、不切换 checkout、不启动 GN/Ninja、不编译。Windows 下若 Git object store 的 reparse point 不可读，可在已配置的 WSL 环境执行等价 Git 只读命令；此轮通过 WSL 对象库查询核对 commit/tree/blob。每次要验证 manifest pins 与当前本地对象：

```bash
set -eu
ROOT=/mnt/d/openHarmonyScanner/openharmony
git -C "$ROOT/.repo/projects/arkcompiler/ets_runtime.git" show -s --format='%H %T' a65a2853ccae13da167d9aa4720ab8b11ec16656
git -C "$ROOT/.repo/projects/arkcompiler/ets_runtime.git" rev-parse a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp
git -C "$ROOT/.repo/projects/vendor/hihope.git" rev-parse b40eabbe69943126c65df1f9ff28057f56e93e46:rk3568/config.json
git -C "$ROOT/.repo/projects/device/board/hihope.git" rev-parse 5d368fb765920c2b1cad41eb86164563461a7074:rk3568/config.gni
python research/experiments/ark_runtime/c1_profile_20261018/profile_check.py
```

profile check 对 JSON 做 key-sorted、紧凑 UTF-8 canonicalization 并打印 SHA-256；重复采集且输入未变时摘要一致。它也逐字节核对当前 manifest、产品/板级配置、目标源文件及 BUILD.gn；缺失或 SHA-256 不符退出码 4。输入 profile 字段、source pins 或证据索引变化会改变摘要。可以将已审阅摘要传入 `--expected-digest <sha256>`；不匹配退出码 3。当前 profile 缺字段/非 ready，退出码 2，故**重放被 fail closed**。profile check 是证据完整性闸门，不执行编译/预处理。只有取得同一 build 的原始命令和闭包后，才能在隔离只读副本上调用已记录的 compiler 命令做最小预处理重放；本轮没有该命令，不提供猜测命令。

## 最小 blocker / 证据请求

向构建环境提供者请求同一 manifest build 的：

1. `out/rk3568/compile_commands.json`（或 Ninja `-t commands` 导出中精确匹配该源文件的原始命令）、同目录 `args.gn` 与 build log 元数据；
2. clang executable 路径、版本输出、SHA-256、工具链包/commit 标识和 target triple；
3. 对应 compile edge 的 depfile、生成头文件及完整依赖闭包，带路径、对象身份、字节数和 SHA-256；
4. 上述输出与 manifest 文件/pins、product `rk3568`、板级配置及 runtime commit 的绑定凭据。

未收到前维持 `blocked/unknown`。profile 不作为源码语义正确性、覆盖完整性或漏洞验证证据。

## 可交给 C2 / C4 的字段

可传递：runtime repo/commit/tree、target path/blob/SHA-256、manifest 文件 SHA-256、product/board 名称、vendor/board commit/tree/config blob、目前仅为直接观察的 CPU/board/toolchain 声明、profile SHA-256、状态及缺口列表。compiler/version、实际 target triple、原始 argv、宏、include 顺序、生成输入与 dependency closure 当前均为 null，不可用于声称产品 profile 已复现；C2/C4 收到完整构建证据后应按同一 schema 补入并重新生成摘要。
