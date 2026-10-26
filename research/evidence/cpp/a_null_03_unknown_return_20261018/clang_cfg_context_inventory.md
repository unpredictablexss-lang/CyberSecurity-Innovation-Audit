# Clang CFG 上下文盘点（2026-10-18）

## 已验证

- 本机 WSL 提供 `Debian clang version 21.1.8`。
- 对本地控制文件执行 Clang 的 `debug.DumpCFG` 可输出函数 entry/exit、基本块、条件和 successor。例如 `fixed_error_path_multistatement.cpp` 输出 null 检查 block 后分向错误返回块与解引用块。这只证明 Clang 能生成该固定控制文件的 CFG。
- 在扫描使用的五个 OpenHarmony 组件目录中查找 `compile_commands.json`，没有找到：`foundation/communication/dsoftbus`、`foundation/distributeddatamgr/kv_store`、`base/security/access_token`、`base/update/updateservice`、`foundation/window/window_manager`。
- 现有 `prepare_git_context` 报告 `build_profile=none`，而 `ScanContext.shared_facts` 只提供轻量语法摘要、源码 blob OID、语法事实及覆盖信息；没有编译数据库或构建参数传入 NULL detector。

## 结论与边界

这些组件本轮没有可用的真实编译数据库，因此 `compile_context` 保持 missing、`guard_dominance` 保持 unknown。不得把本地 Clang 对合成 fixture 的结果外推为组件 build CFG 证据。

## 后续核查与 0.4.0 行为

续查五个组件以及 OpenHarmony `out` 目录仍没有 `compile_commands.json`。当前 WSL 可调用 `/usr/bin/clang`；主扫描环境的 `gn`、`ninja` 不在 PATH，Python `clang.cindex` 不可导入，因此不能从扫描用构建直接导出数据库或使用 libclang。检测器 0.6.0 将无编译上下文的 guard relation 保留为 `unknown`：疑似保护的 sink 不作完整负向结论，疑似未保护的 sink 可保留候选但文件标为 `partial`。不发布词法 `dominating` 或 `not_dominating` 结论。主线 25 项 controls 的 pinned before/after coverage 与 finding 数见 `macro_object_continuation_before_after_20261019.json`；其 after source hash 为当前 0.6.0 detector SHA-256 `3569bdce12236a37973f7e311ad3c738ca7e05276504fdf57a0de1b77cbf09a5`。`pinned_before_after_latest_20261019.json` 是旧 0.4.0 工件，不应作为当前版本证据引用。

## 2026-10-19 隔离构建树续查

- 另一份 OpenHarmony 5.0.2 隔离树在 `D:\openHarmonyScanner\outputs\ark-runtime-isolated-validation-20261018\openharmony-5.0.2`，其中有 GN/Ninja 预编译工具和 `out/rk3568/args.gn`，但没有 `out/rk3568/build.ninja` 或 `compile_commands.json`。
- 该树不是完整 source checkout：`foundation/communication/dsoftbus` 和 `base/security/access_token` 源目录不存在；GN 初始化在 `drivers/interface/camera/sequenceable/map_data/BUILD.gn:32` 因缺少 `graphic_surface` 组件失败。日志见 `out/rk3568/error.log` 与 `out/rk3568/build.log`。
- 因此不能把该树的产品参数或任何将来生成的编译命令绑定到锁定的 5 个组件扫描源码。补齐并核对精确 source commit/tree、成功生成 Ninja 图和 compile database 后，才可将对应文件纳入 Clang-backed controls；当前实现仍 fail closed 为 `unknown/partial`。

## 锁定扫描源码身份交叉核验

核验时不能把 full-scan 工件目录名后缀当作源码 commit。权威身份来自各项目的 `request.json`、`run_meta.json`，并与 `D:\openHarmonyScanner\openharmony` 各组件 Git `HEAD`、tree 和工作树状态逐项对照。五个相关组件当前 checkout 均与扫描输入精确匹配且工作树 clean：

| 组件 | 扫描与当前 checkout commit | Git tree |
|---|---|---|
| communication/dsoftbus | `7743b679f6c3599e21bea4e4b1564422668e3643` | `d386e20f8074e037f330a5df11e99fc66ed155d0` |
| distributeddatamgr/kv_store | `64e48eb1d97b45f44125761f16811f78be609a4a` | `f8c90f1ed61a0899fb03a0410ea4842ef50e1300` |
| security/access_token | `c53a55c371d88c46b0785cc4adb444876e6a9628` | `4942df10e6ed926dab1106e5752cf294305240d6` |
| update/update_service | `f97649a3a427059f42aa9df802dfeb979379bc65` | `a8f0bcf98cbbca3365bcb7410eacabf5041356e6` |
| window/window_manager | `cabdfac822a4c69a6ecae8f1a875a927d19f57fa` | `8298eb0898035d1ade23ae62239bcfa05ba815a8` |

这消除了源码身份阻塞，但仍没有对应构建上下文：该 checkout 没有产品 `out/rk3568/build.ninja`、没有 `compile_commands.json`，也没有 GN/Ninja 预编译二进制；扫描运行自身记录 `build_profile=none`。另一个 5.0.2 验证树中的 GN 产品配置与源码环境不完整，不能直接冒充这五个组件的扫描构建参数。下一步应在精确源码/产品配置下生成并校验 compile database；在此之前仍不声称 CFG 支配关系已证明。

本轮用隔离 Python 3.10 环境恢复了 HB 命令依赖，并试读了产品设置；`hb set --product-name rk3568@hihope` 只生成了 `out/ohos_config.json` 和 `out/hb_args` scratch 配置，没有生成 Ninja 图。HB 输出把 `device_path` 指向不存在的 `device/board/rockchip/rk3568`，而当前产品 `config.json` 的 `device_build_path` 是 `device/board/hihope/rk3568`。由于生成参数仍不一致且源码 checkout 没有 GN/Ninja，本轮没有执行构建或把该配置用作分析证据。

## 2026-10-19 Clang Static Analyzer controls

以 Debian Clang 21.1.8 的 `core.NullDereference` checker 对 6 个固定 controls 作了无 compile database 的最小 C++17 实验。错误分支落入解引用报告 1 条诊断（line 10）；多语句错误早返回、短路和别名早返回 controls 均为 0 条。未加调用方时，未保护参数与未知外部返回也都是 0 条；仅给参数函数补一个同 TU 的合成 `nullptr` 调用后才报告 1 条，改为非空调用则为 0 条。这说明 analyzer 结果受实际 caller/模型上下文影响；它是方法控制证据，不是产品编译/可达性证据，也没有接入 detector。

带每个输入 SHA、命令和限制的结果文件：`clang_static_analyzer_controls_20261019.json`。

仍需开发：为 pinned source 引入受校验的 compile-database 输入、Clang AST/CFG 生成与缓存键；绑定 compiler/version/defines/includes/语言模式和源码哈希；将 CFG source/sink/guard binding 结果交给 detector；仅在可证明对应关系时更新 domination，否则保持 unknown。还需用早返回、短路、别名重绑、错误路径、同名 decoy、宏/模板、跨函数控制建立 Clang-backed controls，并确保构建上下文缺失/漂移/Clang 不可用时 fail closed。

## 可复核命令

```text
wsl.exe clang --version
wsl.exe bash -lc 'clang++ -Xclang -analyze -Xclang -analyzer-checker=debug.DumpCFG -fsyntax-only /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-a-null/research/tests/a_null_02_controls/fixtures/fixed_error_path_multistatement.cpp'
```

上述 CFG 输出是探索性环境检查，尚未接入生产扫描器或作为漏洞判定证据。
