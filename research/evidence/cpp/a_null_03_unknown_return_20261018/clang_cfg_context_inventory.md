# Clang CFG 上下文盘点（2026-10-18）

## 已验证

- 本机 WSL 提供 `Debian clang version 21.1.8`。
- 对本地控制文件执行 Clang 的 `debug.DumpCFG` 可输出函数 entry/exit、基本块、条件和 successor。例如 `fixed_error_path_multistatement.cpp` 输出 null 检查 block 后分向错误返回块与解引用块。这只证明 Clang 能生成该固定控制文件的 CFG。
- 在扫描使用的五个 OpenHarmony 组件目录中查找 `compile_commands.json`，没有找到：`foundation/communication/dsoftbus`、`foundation/distributeddatamgr/kv_store`、`base/security/access_token`、`base/update/updateservice`、`foundation/window/window_manager`。
- 现有 `prepare_git_context` 报告 `build_profile=none`，而 `ScanContext.shared_facts` 只提供轻量语法摘要、源码 blob OID、语法事实及覆盖信息；没有编译数据库或构建参数传入 NULL detector。

## 结论与边界

这些组件本轮没有可用的真实编译数据库，因此 `compile_context` 保持 missing、`guard_dominance` 保持 unknown。不得把本地 Clang 对合成 fixture 的结果外推为组件 build CFG 证据。

## 后续核查与 0.4.0 行为

续查五个组件以及 OpenHarmony `out` 目录仍没有 `compile_commands.json`。当前 WSL 可调用 `/usr/bin/clang`；`gn`、`ninja` 不在 PATH，Python `clang.cindex` 不可导入，因此本轮环境不能从实际 OpenHarmony 构建导出数据库或使用 libclang。检测器 0.4.0 已将所有依赖 guard 关系的词法路径保留为 `unknown`：疑似保护的 sink 会让文件进入 `partial`，疑似未保护的 sink 可保留候选但同样让文件进入 `partial`。不再发布词法 `dominating` 或 `not_dominating` 结论。Pinned 前后 coverage 数和 finding 数见 `pinned_before_after.json`。

仍需开发：为 pinned source 引入受校验的 compile-database 输入、Clang AST/CFG 生成与缓存键；绑定 compiler/version/defines/includes/语言模式和源码哈希；将 CFG source/sink/guard binding 结果交给 detector；仅在可证明对应关系时更新 domination，否则保持 unknown。还需用早返回、短路、别名重绑、错误路径、同名 decoy、宏/模板、跨函数控制建立 Clang-backed controls，并确保构建上下文缺失/漂移/Clang 不可用时 fail closed。

## 可复核命令

```text
wsl.exe clang --version
wsl.exe bash -lc 'clang++ -Xclang -analyze -Xclang -analyzer-checker=debug.DumpCFG -fsyntax-only /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-a-null/research/tests/a_null_02_controls/fixtures/fixed_error_path_multistatement.cpp'
```

上述 CFG 输出是探索性环境检查，尚未接入生产扫描器或作为漏洞判定证据。
