# C1 Ark Runtime 产品构建 profile 取证（2026-10-18）

状态：**partial / blocked**。2026-10-19 已从固定 HiHope 配置生成产品 GN 与编译命令，并在隔离环境成功编译固定 Ark Runtime ARM32 目标对象、保存 512 项依赖闭包。尚未完成产品镜像与运行时复核，故 C1 证据仍不满足 detector admission。

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

直接观察：`config.json` 的 `target_cpu=arm`，板级 `config.gni` 声明 `armv8-a`、`cortex-a55`、`clang`；目标 `BUILD.gn` 有 `libark_jsruntime` 构建声明。来源和字节级索引在 `profile_manifest.json`（文件引用：../../experiments/ark_runtime/c1_profile_20261018/profile_manifest.json）。C1 sink-binding manifest 现已将根 `BUILD.gn` 绑定到 commit blob `b3c8effde42ae810e825437b7cfcaabf1a3fdbdf` / SHA-256 `8e5f0d4d829578200b75175ea81e8ef2c8370fe4c331ab6a3b255cad95988a89`，并验证工作树字节匹配；这证明固定 GN 文本身份，不证明其条件在 HiHope build 中如何求值。

本次补查发现 `openharmony/out` 目录存在，但只有 `ohos_config.json`、空的 `dfx/` 和三份 `hb_args` schema/default 文件，没有 `out/rk3568/`、Ninja 图或产品编译产物。`ohos_config.json` 的已解析记录将 vendor product 指向 `vendor/hihope/rk3568`，并记载 `target_cpu=arm`，但 `device_path` 为 `device/board/rockchip/rk3568`，与固定 manifest 的 `device_build_path=device/board/hihope/rk3568` 不一致。`setargs.json` 的产品默认值为 `rk3568@hihope`；`buildargs.json` 的参数默认值包括 `target_cpu=arm`、`build_type=release` 和 `compiler=clang`。这些默认值描述框架 schema，不证明本次 build 调用实际使用了它们；`ohos_config` 也无法绑定到固定 HiHope manifest 候选，因为设备路径不匹配。四个相关文件的字节数、SHA-256、证据类别及声明范围已记入 `profile_manifest.json` 的 `observed_output_state`，并加入输入漂移检查。因此这个 `out` 状态仍不能绑定到本次 hihope 产品候选。

截至 2026-10-18 的基线记录缺少 build 输出。2026-10-19 GN/目标编译复核现已提供匹配本 manifest 的 `args.gn`、compile database、实际 clang、ARM32 产品命令、宏/有序 include 路径、生成的 musl 头文件和逐项 SHA-256 的 Ninja 依赖闭包。精确范围及 artifact 哈希见下方 2026-10-19 章节与实验 JSON。仍未知的是完整产品镜像、可启动产品 VM、真实 species 行为和安全影响；release `ohos_build_type` 也仍显示 debug。

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

profile check 对 JSON 做 key-sorted、紧凑 UTF-8 canonicalization 并打印 SHA-256；重复采集且输入未变时摘要一致。它也逐字节核对当前 manifest、产品/板级配置、目标源文件、BUILD.gn 和新增记录的 `out` 状态文件；缺失或 SHA-256 不符退出码 4。输入 profile 字段、source pins 或证据索引变化会改变摘要。可以将已审阅摘要传入 `--expected-digest <sha256>`；不匹配退出码 3。当前 profile 缺字段/非 ready，退出码 2，故**重放被 fail closed**。profile check 是证据完整性闸门，不执行编译/预处理。只有取得同一 build 的原始命令和闭包后，才能在隔离只读副本上调用已记录的 compiler 命令做最小预处理重放；本轮没有该命令，不提供猜测命令。

## 最小 blocker / 证据请求

上述构建身份和单对象依赖闭包已通过 2026-10-19 隔离构建补齐；Ninja 消费后的 `.d` 已由 `.ninja_deps` 的 `VALID` 记录复核。剩余 blocker 是完整产品镜像、VM/runtime 目标身份和实际 species 行为。profile 仍不作为源码语义正确性、覆盖完整性或漏洞验证证据。

## 2026-10-19 构建工具可用性补查

在 Ubuntu 24.04 中用 `/tmp/c1-hb-venv` 建立了临时 HB Python 环境；安装 `prompt_toolkit==1.0.18`、`kconfiglib`、PyYAML、requests 和 setuptools，并通过 `PYTHONPATH` 使用仓库自带的 Jinja/MarkupSafe。环境位于 `/tmp`，未改动 OpenHarmony 产品源码、`out` 配置或 admission 文件。

HB 主程序可启动并输出 `hb help` 的构建选项。此次以非交互方式运行 `hb set --all` 仍进入产品选择提示，最终因没有 TTY 而失败，故没有产生已选择产品或写入配置。`hb tool --ls` 在加载工具阶段失败，原因是仓库缺少 `prebuilts/build-tools/linux-x86/bin/gn`；工具输出建议执行 `build/prebuilts_download.sh`，本轮未执行下载脚本。另发现 Python 3.12 环境原先缺少 `distutils`；临时 venv 安装 setuptools 后 HB 可启动。

这轮只证明 HB CLI 的 Python 启动路径可用，并确认 GN 预置工具缺失；没有运行构建、下载 prebuilts、选择或写入产品配置，也没有得到 compile command、`args.gn`、Ninja 图或 Ark VM。产品 profile 仍为 **blocked/unknown**，原有 fail-closed 准入结论不变。后续如获得明确可复现的构建环境，可通过 `hb build --product-name rk3568@hihope` 显式指定产品；在目标配置/输出隔离方式确认前，不以交互式 `hb set` 结果作为证据。

## 可交给 C2 / C4 的字段

可传递：runtime repo/commit/tree、target path/blob/SHA-256、manifest SHA-256、HiHope product/board pin、ARM32 产品编译命令/哈希、clang 身份、宏/有序 include 路径、512 项依赖闭包及对象哈希。这些字段证明固定构建中的单一目标对象可编译；仍不能代替完整产品镜像、VM/runtime 行为、C2/C4 detector 回放或漏洞影响证明。

## 2026-10-19 隔离 GN 产品配置与目标编译边

### 固定输入与配置解析

使用同一 resolved manifest（SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`）生成只读源码归档，并在隔离 Docker 容器内运行 HB。归档清单列出 525 个项目；完整归档状态仍是 **failed**，原因是未解析 linkfile `vendor/ohemu/common/qemu-run`。与本次 C1 直接相关的 runtime 目标、runtime `BUILD.gn`、HiHope 产品配置和 HiHope board `config.gni` 都逐字节匹配已固定 blob/SHA-256。逐项信息及归档清单摘要见 `profile.json`（文件引用：../../experiments/ark_runtime/c1_product_gn_20261019/profile.json）。

HB 使用显式产品 `rk3568@hihope`，`--build-only-gn` 和 `--export-compile-commands`；容器网络关闭，源码、prebuilt 与工具链以只读挂载提供，只有新建的隔离输出目录可写。GN 阶段成功，生成 `build.ninja` 和 compile database。生成的 `build_config.json` 将产品绑定到 `vendor/hihope/rk3568`，并明确写入 `device_build_path=device/board/hihope/rk3568`、`target_cpu=arm` 和 HiHope toolchain label。这里 `device_company=rockchip` 是产品配置中的 SoC/company 字段，故 `ohos_config.json`/`args.gn` 的 `device_path=device/board/rockchip/rk3568` 并不能单独说明 HiHope build path 错误；先前记录的路径疑点由本次实际解析出的 `device_build_path` 澄清。

首次 GN 生成未传 `--build-type`；实际 `args.gn` 为 `ohos_build_type="debug"`、`runtime_mode="release"`。随后单独输出目录重跑并显式传入 `--build-type release`，HB 报告 GN 成功，但生成的 `args.gn` 仍是 `ohos_build_type="debug"`、`runtime_mode="release"`；没有 compile database 或编译产物，故该选项没有建立 release 编译 profile。两次运行的输出路径和文件哈希都记在 profile JSON。compile database 对目标 `.cpp` 有 5 条不同编译边，包含 host、Windows 及产品编译变体。产品命令使用 `PANDA_TARGET_OHOS`、`PANDA_TARGET_ARM32_ABI_SOFT=1`、`PANDA_TARGET_ARM32`，并包含 `NDEBUG`；有序 include 路径、宏集合、逐条命令 SHA-256 和原始 argv 均保存在 profile JSON。工具身份为 GN `2026 (47b40ef4)` / SHA-256 `aa76f11ec5ab820695fdd0973d644d205305b1a23fabcc43e230871f502230a7`、Ninja `1.13.2` / SHA-256 `2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b`、OHOS clang 15.0.4 / SHA-256 `2b28a71dbd71e1bc7f2b9b793f4add7499bee5d533e2d581df2bd0f716e7011c`。

### 编译边验证结果

生成物哈希也固定在 JSON：`build.ninja` 为 62,847,983 bytes，compile database 为 4,103,004,071 bytes。Ninja dry-run 在读取整图时被另一组件的重复输出规则阻断：`toolchain.ninja:463: multiple rules generate obj/applications/standard/contacts_data/Contacts_DataAbility.stamp`。随后按 compile database 中精确的产品 ARM32 命令直接尝试目标源编译，编译器因缺少生成的 `obj/third_party/musl/usr/include/arm-linux-ohos/features.h` 失败；没有生成目标 object 或 depfile。此尝试不补造 sysroot 头文件，也不把 host 编译变体当成产品编译结果。

本节记录当时的中间状态：GN 和目标 compile edge 已生成，但 Ninja 整图重复输出、缺生成 sysroot 头和专用预置仍使目标编译未完成。下方“隔离目标依赖编译续跑”记录了这些环境阻塞的处理及之后目标对象成功编译。release profile、产品 image/Ark VM 和真实 TypedArray species 行为仍未完成；研究适配器/public Runner admission 保持 **blocked**、`execution_enabled=false`。

### 2026-10-19 隔离目标依赖编译续跑

在隔离输出目录中使用 `ninja -w dupbuild=warn -j8` 请求精确产品对象 `obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set/builtins_typedarray_stub_builder.o`。Ninja 已进入目标的依赖构建；为保持固定源码归档只读，构建所需 notice/license 写入通过逐文件只读覆盖副本处理，所有已覆盖文件均逐字节匹配源文件。`xz` 与其 `liblzma` 运行库也以只读挂载提供，来源为 Ubuntu 主机工具，身份摘要记在 `profile.json`。

首轮目标依赖编译先后遇到缺少 Ruby、IDL 工具要求输入文件可写、Ark 专用 LLVM 预置未物化等环境问题。通过独立 Ruby 工具层、逐文件字节一致的 license/notice 与 IDL 可写覆盖、以及从固定 `build/prebuilts_config.json` 指定的 Huawei Cloud URL 获取并校验 SHA-256 sidecar 的 `ark_js_prebuilts_20230713.tar.gz`，已逐项补齐隔离环境依赖。固定源码归档仍只读。

随后同一 HiHope `product_ohos_arm32` 编译边成功生成 `builtins_typedarray_stub_builder.o`（5,555,996 bytes，SHA-256 `865a1639c3f73f24f7235400228d0bd341930aa903231cd2c4ff21de25f220d5`）。其编译数据库命令哈希为 `c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88`；Ninja `.ninja_deps` 记录了 **512** 个 `VALID` 依赖，均有可解析路径和 SHA-256，闭包清单 SHA-256 为 `042b92b0bfe1db0424124b87f534c78039877e6141cfb8794d8f3b991a70d2af`。生成对象引用的源 `.cpp` SHA-256 与固定 Git blob 完全一致。日志、Ninja 原始依赖输出、闭包和逐文件 overlay 哈希已随 `profile.json` 保存于本实验目录。

随后从同一产品 ARM32 compile argv 派生 `-E -dM` 和 Clang filtered AST 检查。宏表 SHA-256 为 `8324be27ad6b466787312ca034c9a32e54b2b4beb3410bd132cb7ac6045befba`：`NDEBUG=1`，`PANDA_TARGET_OHOS=1`、`PANDA_TARGET_ARM32_ABI_SOFT=1`、`PANDA_TARGET_ARM32=1`、`PANDA_TARGET_32=1`；`ENABLE_ASM_ASSERT`、`ARK_ASAN_ON`、`__aarch64__` 未定义。`ENABLE_ASM_ASSERT` 是 undefined 而非显式定义为 0；按固定 `stub_builder.h` 的 `#elif defined(ENABLE_ASM_ASSERT)`，本构建选择无 ASM_ASSERT 的分支。该宏证据只绑定当前 a65 产品 profile，不向历史 parent/fix 版本外推。

Clang AST 输出绑定同一产品 compile command：`Filter` 定义位于目标 `.cpp:1436`，精确类型为 `void (GateRef, GateRef, GateRef, Variable *, Label *, Label *)`；`NewTypedArray` 选中的声明为 `GateRef (GateRef, GateRef, GateRef, GateRef)`；`StoreTypedArrayElement` 为五个 `GateRef` 参数。AST 显示 `newArrayType = GetObjectType(LoadHClass(glue, newArray))` 在 `HasPendingException` 检查通过后的分支读取，并传给 `StoreTypedArrayElement`。完整 filtered AST、原始宏表及逐文件 SHA-256 已保存于实验目录的 `clang_*_ast.txt` 和 `target_preprocessor_macros.txt`，相关派生命令哈希在 `profile.json`。这复核当前产品构建的宏、类型与调用绑定，不复核历史分析模型的编译假设，也不代替运行时行为。

### C1 artifact verification

`python research/experiments/ark_runtime/c1_product_gn_20261019/verify_profile_artifacts.py` performs a read-only consistency check over the archived evidence: runtime commit/tree/target Git blob, the separate C1 sink-binding manifest's target and creator rows, the exact ARM32 command digest, built object digest, all 34 byte-identical overlays, the 512-row dependency closure, macro dump, and the three filtered Clang AST dumps and resolved signatures. It returned `verified_scoped_artifacts_profile_remains_partial`. This verifies the archived one-object evidence remains internally bound; it deliberately leaves the product profile `partial`, and does not admit the detector or claim a full image/runtime result.

这补足了固定产品配置下的**单一 Ark Runtime 目标对象编译证据**，不等于完整产品镜像、release profile、VM 运行或真实 TypedArray species 行为；也没有入口/攻击者控制或安全影响证据。源归档仍有无关的 `vendor/ohemu/common/qemu-run` linkfile 缺失，完整 Ninja 图包含重复输出警告。本研究适配器/public Runner admission 继续 **blocked**、`execution_enabled=false`，不据对象编译结果上调产品漏洞结论。

### 2026-10-19 ARM32 VM 与 TypedArray species 行为复核

同一构建输出中成功生成 ARM32 `ark_js_vm` 和同一源码归档的 host `es2abc`，并用 QEMU ARM user-mode 与 C1 musl/sysroot 执行 `.abc`。最小 `assert_true(true); test_end();` 在 `--test-assert=true` 下返回 0；固定源码注册的完成钩子名称是 `test_end`。species 候选和四项隔离控制再以 `--asm-interpreter=false --test-assert=true` 重跑，输出与初次运行一致。此前使用 `testEnd` 的运行触发完成守卫，属于 harness 名称错误，已从行为结论中排除。

独立 species 探针显示：C1 VM 可直接读取 `DefaultDerived[Symbol.species]` 与自定义 `CustomDerived[Symbol.species]`，但对这两个 `Int8Array` 子类调用 `filter()` 都返回 `Int8Array`；Node v22.14 返回各自的子类构造器结果。实例上显式覆盖 `source.constructor[Symbol.species]` 时，C1 VM 则选择 `Uint16Species`/`Uint16Array` 并按目标类型转换值。宽控制脚本在第二项跨类型子类断言处中止；随后隔离运行的 Number/BigInt 拒绝、构造异常与回调顺序、回调中改写 constructor、Set/CopyWithin/With 不读 species 四项均通过。宽脚本内尚未隔离复核的其余项仍为 partial。

当前 a65 source archive 中 `ecmascript/base/typed_array_helper.cpp` 的 SHA-256 是 `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d`；`TypedArraySpeciesCreate` 在约 949 行具备 protector/prototype/own-constructor 条件快路径。观察与该路径绕过 subclass `@@species` 一致，但尚未证明具体分支状态或安全后果。机器记录、各 JS/ABC 哈希、运行日志和证据限制见 `runtime_behavior/README.md`（文件引用：../../experiments/ark_runtime/c1_product_gn_20261019/runtime_behavior/README.md）。

当前 C1 VM 与 Node 的类型行为差异按 **candidate** 记录；历史 parent/fix 运行时对照、完整产品镜像/设备执行、入口可达性、攻击者控制和具体安全影响仍 **partial/unknown**。不能据此作漏洞结论或提升 Runner 准入；profile 仍为 **partial**，准入继续 **C / blocked / execution_enabled=false**。
