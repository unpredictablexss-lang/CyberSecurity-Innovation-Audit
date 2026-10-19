# Ark parent/fix build/preprocess profile

历史基线日期：2026-10-19（Asia/Shanghai），原工作发生在 `E:\网安\CyberSecurity-Innovation-Audit-c12-product-admission-20261019`。C D2 后续工作在独立 worktree 进行，没有改写上述历史 manifest 或 raw-source 记录，也未运行目标构建、预处理器或动态 PoC。

## 状态

`BLOCKED / NOT_ADMITTED`。

`ark_parent_fix_build_profile_manifest.v1.json` 从本地 pinned Git blob `ark-runtime-coverage-ledger-20261019.json` 记录 16 个 Ark parent/fix 开发案例；其中 6 个案例有完整的 commit/tree/blob/source-SHA 字段，0 个有完整产品 build/preprocess profile。2026-10-20 后续 D2 对这 6 案的 12 个 commit/tree 对、26 个登记文件和 parent→fixed ancestry 增加了独立 object-store 检查记录，见下文 `official_git_object_evidence.v1.json`。这仍不证明对象库获取/保管链或服务器真实性。

产品 `args.gn`、GN target、compile database、实际 include closure、产品编译器/链接器/sysroot、预处理 TU、宏展开日志、产品 manifest、二进制/版本/分支映射均缺失。因此所有 16 案保持 `build_profile.status=BLOCKED`、`preprocess_profile.status=BLOCKED`。

## 身份绑定

- OHScanner HEAD/tree、source audit commit/tree/blob/SHA、ledger blob、Detector、parser source、parser module、config/profile 和 host toolchain 均写入 manifest。
- host Python/Git/Clang/CMake/Ninja/GN probe 只是环境观测，不是 Ark 产品 toolchain。
- source audit blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea` 的 SHA-256 与既有导入验证一致。
- manifest 中的 historical source identity 字段本身不是对象验证；本地 object-store 核验结果独立保存在 D2 evidence record，并保留获取/保管链限制。

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

raw-source record 自身不能证明 Git commit/tree 对象、parent/fix ancestry 或依赖闭包；其中记录的 12 个 parent/fix tree SHA 在该 record 内仍标 `NOT_VERIFIED`。另见下一节独立的 object-store evidence record。raw source / Git object 均不是产品 source identity 到 shipped binary 的关联。16 个 G12-PC-1 案例的 build/preprocess profile 仍为 0/16 完整，PC-1 状态维持 `IN_PROGRESS_BLOCKED`，不得由来源核验结论关闭。

## 本地 bare Git object-store 核验（不等于 source authenticity 或 PC-1 完成）

`official_git_object_evidence.py` 先 pin profile manifest 的 payload SHA-256 `a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214`、schema、required identity fields、16 案集和精确的 6 个 `recorded_complete` case ID；被替换或仅保持 6/26/12 数量但身份不同的 manifest 会 fail closed。随后对这些固定案例执行只读检查：commit/tree 类型与 OID、commit 指向的 tree、每条登记 path 对应的 blob OID、blob SHA-256/字节数（仅对有登记长度者比对），以及 parent 是否为 fixed commit 的祖先。它要求 bare store 的唯一 `origin` fetch/push URL 都精确指向官方 Gitee Ark Runtime 仓库；不会 fetch、checkout 或写 object store。store path 可通过 `--git-dir` 给出，或用 `OHSCANNER_ARK_OFFICIAL_GIT` 提供。

```powershell
& $python "$root\research\methods\ark_runtime\build_profile_20261019\official_git_object_evidence.py" --git-dir "D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git"
```

输出的 `official_git_object_evidence.v1.json` 记录 pinned manifest identity、store path、声明的 remote、时间、逐 commit/tree/blob/hash/ancestry 结果和摘要。官方 remote 配置与对象哈希/祖先关系一致，只能证明这些内容与本地 object store 的声明相符；获取过程、保管链和服务器真实性没有独立签名/API 证明，字段为 `NOT_INDEPENDENTLY_VERIFIED`。因此不得称作 source authenticity 或 source provenance 的独立认证。

本证据仅覆盖 6 案、12 个 commit/tree 对和 26 个文件；其余 10 案未验证。12 个文件缺少登记 byte length，明确为 `not_recorded`，只可校验 Git blob OID 与 SHA-256。产品 build/preprocess profile 仍为 0/16 完整，PC-1 继续 `IN_PROGRESS_BLOCKED`。

focused self-tests（含合成 bare store，不把其作为产品或上游证据）：

```powershell
& $python -m unittest discover -s "$root\research\methods\ark_runtime\build_profile_20261019\selftest" -p "test_*.py"
```

仍需产品 owner/数据保管人提供：只读 official Ark Git object store；精确产品 manifest、版本/分支和 GN target；对应 parent/fix 的 `args.gn`、compile database/实际 compile action、编译器/链接器/sysroot 与生成输入；精确 TU 的完整 include closure、预处理输出及宏日志；以及目标源码到 shipped binary/version/branch 的可审计映射。缺任一项继续标为 blocked。

## 解除阻塞的最小补救

1. 由数据保管人提供只读 official Ark Git object store，并核对每个 parent/fix commit、tree、blob、source SHA。
2. 锁定具体产品 manifest、版本、分支、GN target、`args.gn`、compile database、工具链与 sysroot。
3. 对目标 TU 保存完整 include closure、预处理输出、宏展开日志和哈希。
4. 将 profile 与 Detector/rule version、scope、config hash、parser binary identity 绑定。
5. 只有产品构建、入口/权限、触发、CIA 影响、PoC 和修复产品重验全部闭环后，才重新评估准入。

## 剩余 source-anchored case 补充核验（2026-10-20）

`supplemental_source_identity_evidence.py` 不改写带历史摘要的 profile manifest。它固定检查 manifest payload SHA-256 `a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214`，对 7 个仍有 commit 锚点、但不在前述六案对象证据中的 case，从同一配置的本地 bare Gitee object store 重算 commit→tree、指定路径的 blob OID/raw SHA-256/字节数以及 parent→fixed ancestry。路径只取 case `scan_scope` 或已有 parent/fixed 文件路径的并集。没有登记 expected raw SHA/length 时保留 `NOT_RECORDED`，不得把重算值解释为独立期望值。

```powershell
python research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py --git-dir "D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git" --write
python research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py --git-dir "D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git" --verify-only
python research/methods/ark_runtime/build_profile_20261019/supplemental_source_identity_evidence.py --self-test
python -m unittest research.methods.ark_runtime.build_profile_20261019.selftest.test_supplemental_source_identity_evidence
```

结果保存在 `supplemental_source_identity_evidence.v1.json`。命令会分别打印 anchored/unanchored case 数、`MATCH`、`NOT_RECORDED`、`MISMATCH` 计数、missing-side path 和 blocked expected path 数；`NOT_RECORDED` 单独计数，不计为 `MATCH`。任一 `MISMATCH` 或 expected path 无法读取都会非零退出。合成负例检查证明正确值、错误值和缺记录值分别得到 `MATCH`、`MISMATCH`、`NOT_RECORDED`，并验证缺侧路径计数。三案仍为 `UNKNOWN`：`ARK-ARRAY-CALLBACK-ABRUPT-COMPLETION-HISTORY-VARIANT` 没有 parent/fixed commit 和 scope（虽然描述提到两个历史 commit，但没有绑定关系）；`ARK-TYPEDARRAY-CONSTRUCTOR-LENGTH-NARROWING-I7W51D` 与 `ARK-DATAVIEW-INDEX-WIDTH-AND-BOUNDS-IB8BCA` 没有 commit/tree/path。不得根据类似描述补猜身份。local object identity、commit ancestry 和 raw SHA 都不证明获取/保管链、服务器真实性或目标产品构建纳入。全部 16 个产品 profile 仍 `BLOCKED`，PC-1 仍 `IN_PROGRESS_BLOCKED`。
