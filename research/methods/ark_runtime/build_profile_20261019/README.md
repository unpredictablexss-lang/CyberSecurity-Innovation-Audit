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
$python = "C:\Program Files\Python310\python.exe"
$root = "E:\网安\CyberSecurity-Innovation-Audit-c12-product-admission-20261019"
& $python "$root\research\methods\ark_runtime\build_profile_20261019\build_profile_manifest.py" --repo-root $root
& $python "$root\research\methods\ark_runtime\build_profile_20261019\build_profile_manifest.py" --verify-integrity-only
& $python "$root\research\methods\ark_runtime\build_profile_20261019\build_profile_manifest.py" --repo-root $root --reproduce-environment
```

`--verify-integrity-only` 是可移植的只读自摘要检查：它从保存的 manifest 移除 `payload_sha256` 字段，按 canonical JSON 重算并比较摘要，同时要求记录保持 `BLOCKED` / `NOT_ADMITTED`。成功只说明内容与文件内声明的摘要一致；摘要不是签名，不能证明内容来源、来源对象真实存在、事实正确或产品 profile 完整。它不访问 repo/host，也不会覆盖 verification 文件。

`--reproduce-environment` 独立重算当前 checkout/host 的 fingerprint（HEAD/tree、detector/parser/config/source-audit 与 host toolchain），与历史 manifest 记录比较并输出 changed paths。checkout 路径、源码状态、Python/parser 模块与 Git 工具变化都会报告 `environment_drift`；漂移不等于历史记录损坏。`--verify-only` 仅为该模式的弃用别名。重放结果只写入显式指定的 `--verification-output`。两种检查均不能验证产品 build/preprocess。历史 manifest 的记录摘要为 `a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214`；新模式不会重生成或改写该历史文件。

运行本目录的 focused self-tests：

```powershell
& $python -m unittest discover -s "$root\research\methods\ark_runtime\build_profile_20261019\selftest" -p "test_*.py"
```

## 逐文件来源证据（不等于 PC-1 完成）

`source_identity_evidence.v1.json` 为清单中 6 个已登记完整案例的 26 个 parent/fixed 文件保存逐文件证据：固定 commit/path 的 raw URL、预期与实测 Git blob SHA-1、SHA-256、实测字节数和逐项匹配状态。12 个文件原始登记长度缺失，记录明确标为 `not_recorded`，长度不作对比。它由 `source_identity_evidence.py` 从 pinned commit 的 GitHub raw 文件重放生成；不保存上游源文件正文。

```powershell
python research/methods/ark_runtime/build_profile_20261019/source_identity_evidence.py --fetch
python research/methods/ark_runtime/build_profile_20261019/source_identity_evidence.py --verify-only
```

也可在网络隔离环境把源字节放在 `<evidence-dir>/<commit>/<path>` 后，以 `--evidence-dir <evidence-dir>` 离线重算。`--verify-only` 仅检查记录结构、文件集、预期身份、实测哈希字段、逐项检查状态和记录摘要；要独立重放原始字节，应重新运行 `--fetch` 或提供离线字节。

这 26 个文件字节匹配不能证明 Git commit/tree 对象、parent/fix ancestry 或依赖闭包；记录中的 12 个 parent/fix tree SHA 明确为 `NOT_VERIFIED`。它也不是产品 source identity 到 shipped binary 的关联。16 个 G12-PC-1 案例的 build/preprocess profile 仍为 0/16 完整，PC-1 状态维持 `IN_PROGRESS_BLOCKED`，不得由此结论关闭。

仍需产品 owner/数据保管人提供：只读 official Ark Git object store；精确产品 manifest、版本/分支和 GN target；对应 parent/fix 的 `args.gn`、compile database/实际 compile action、编译器/链接器/sysroot 与生成输入；精确 TU 的完整 include closure、预处理输出及宏日志；以及目标源码到 shipped binary/version/branch 的可审计映射。缺任一项继续标为 blocked。

## 解除阻塞的最小补救

1. 由数据保管人提供只读 official Ark Git object store，并核对每个 parent/fix commit、tree、blob、source SHA。
2. 锁定具体产品 manifest、版本、分支、GN target、`args.gn`、compile database、工具链与 sysroot。
3. 对目标 TU 保存完整 include closure、预处理输出、宏展开日志和哈希。
4. 将 profile 与 Detector/rule version、scope、config hash、parser binary identity 绑定。
5. 只有产品构建、入口/权限、触发、CIA 影响、PoC 和修复产品重验全部闭环后，才重新评估准入。
