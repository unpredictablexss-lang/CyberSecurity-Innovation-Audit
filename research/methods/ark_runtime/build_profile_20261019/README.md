# Ark parent/fix build/preprocess profile

日期：2026-10-19（Asia/Shanghai）。工作只发生在 `E:\网安\CyberSecurity-Innovation-Audit-c12-product-admission-20261019`。本轮未执行 fetch、checkout、commit、push、merge、reset，也未运行目标构建、预处理器或动态 PoC。

## 状态

`BLOCKED / NOT_ADMITTED`。

`ark_parent_fix_build_profile_manifest.v1.json` 从本地 pinned Git blob `ark-runtime-coverage-ledger-20261019.json` 可复算出 16 个 Ark parent/fix 开发案例；其中 6 个案例具备完整的 commit/tree/blob/source-sha 记录，但 0 个具备完整产品 build/preprocess profile。这里的“完整记录”只表示身份字段完整，不表示已在本地 official Ark Git store 中验证源对象。

当前 `OHSCANNER_ARK_OFFICIAL_GIT` 未绑定；产品 `args.gn`、GN target、compile database、实际 include closure、产品编译器/链接器/sysroot、预处理 TU、宏展开日志、产品 manifest、二进制/版本/分支映射均缺失。因此所有案例保持 `build_profile.status=BLOCKED`、`preprocess_profile.status=BLOCKED`。

## 身份绑定

- OHScanner HEAD/tree、source audit commit/tree/blob/SHA、ledger blob、Detector、parser source、parser module、config/profile 和 host toolchain 均写入 manifest。
- host Python/Git/Clang/CMake/Ninja/GN probe 只是环境观测，不是 Ark 产品 toolchain。
- source audit blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea` 的 SHA-256 与既有导入验证一致。
- 缺少 official Ark Git store 时，不把 ledger 中记录的 commit/tree/blob 当作已经本地复核的源对象。

## 可复算命令

```powershell
$python = "C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$root = "E:\网安\CyberSecurity-Innovation-Audit-c12-product-admission-20261019"
& $python "$root\research\methods\ark_runtime\build_profile_20261019\build_profile_manifest.py" --repo-root $root
& $python "$root\research\methods\ark_runtime\build_profile_20261019\build_profile_manifest.py" --repo-root $root --verify-only
```

当前验证结果为 `verified_blocked_manifest`，manifest/recomputed payload SHA-256 为 `a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214`。

## 解除阻塞的最小补救

1. 由数据保管人提供只读 official Ark Git object store，并核对每个 parent/fix commit、tree、blob、source SHA。
2. 锁定具体产品 manifest、版本、分支、GN target、`args.gn`、compile database、工具链与 sysroot。
3. 对目标 TU 保存完整 include closure、预处理输出、宏展开日志和哈希。
4. 将 profile 与 Detector/rule version、scope、config hash、parser binary identity 绑定。
5. 只有产品构建、入口/权限、触发、CIA 影响、PoC 和修复产品重验全部闭环后，才重新评估准入。