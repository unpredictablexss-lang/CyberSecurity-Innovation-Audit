# C1 product profile recheck — 2026-10-18

## Decision

**Status: source and selected product configuration authenticated; effective product profile still blocked.** The user selected `hihope/rk3568` from the current manifest. The manifest binds `vendor/hihope` to `b40eabbe69943126c65df1f9ff28057f56e93e46` and `device/board/hihope` to `5d368fb765920c2b1cad41eb86164563461a7074`. WSL Git confirms the corresponding product and board config blobs; their raw SHA-256 values are recorded below and in the C4 exact-snapshot inventory. The product config declares `target_cpu="arm"` and `device_build_path="device/board/hihope/rk3568"`; this identifies the selected configuration, but does not prove it was used to generate a successful compile action. No successful product compile action, exact evaluated `args.gn`, or compile database is available, so the effective product profile is not established. A separate OpenHarmony 5.0.2 rk3568 build directory remains invalid evidence for this target: its target source bytes differ and GN generation fails before Ark Runtime compilation.

No compiler command, macro set, include closure, generated-header set, or product configuration is inferred from these partial observations. This record does not upgrade the C4 inventory digest into a compile cache key.

## Exact target evidence observed

Target: `openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, path `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`.

| Observation | Value | Interpretation |
|---|---|---|
| Local source path | `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime\ecmascript\compiler\builtins\builtins_typedarray_stub_builder.cpp` | Present in the shared OpenHarmony workspace |
| Local source size | 150,610 bytes | Matches the bound target source record |
| Local source SHA-256 | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` | Matches the C3 bound source digest |
| Exact Git identity | WSL Git reads the `.repo` object store through the repo-tool symlink; HEAD is `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree is `8781f036a3e7e04d8e0b34970d5f623b42875016` | Commit, tree and target blob are verified from local Git objects |
| Target listing | Exact `ecmascript/compiler/BUILD.gn` blob `e6f28ab0562deea4a0ece18851e1ea927b806c1d` lists the source under `libark_jsoptimizer_sources` | Source membership is bound to the exact target commit; no generated compile action was found |
| Target-level defines | Exact `BUILD.gn` adds `NDEBUG` in the non-debug branch and `ENABLE_ASM_ASSERT` only when `enable_asm_assert` is true | Conditional behavior is bound to the target commit; actual product arg values remain unknown |

Raw-byte SHA-256 values for the local GN evidence:

| File | Bytes | SHA-256 |
|---|---:|---|
| `openharmony/arkcompiler/ets_runtime/BUILD.gn` | 82,005 | `b3c8effde42ae810e825437b7cfcaabf1a3fdbdf` | `8e5f0d4d829578200b75175ea81e8ef2c8370fe4c331ab6a3b255cad95988a89` |
| `openharmony/arkcompiler/ets_runtime/ecmascript/compiler/BUILD.gn` | 23,777 | `e6f28ab0562deea4a0ece18851e1ea927b806c1d` | `34f23416b2983f5635c00f881b444c4b15975e7ff8d9657b03ae65847ada103a` |
| `openharmony/arkcompiler/ets_runtime/js_runtime_config.gni` | 22,839 | `c8d1de004c93829a5236f497b911d268647a8761` | `c088d81878bd6b3c38244e8e1ee9ab90252f64029d85e68a6c23163725c3bbb1` |

The Git blob IDs and SHA-256 values above were obtained from the exact commit using WSL Git and match the bytes read from the workspace. The Git store is usable under WSL; only the Windows Git view of the Linux symlinks is unreliable.

## Selected product configuration evidence

The current manifest (`openharmony-manifest-current-20261018.xml`) pins `vendor/hihope` to commit `b40eabbe69943126c65df1f9ff28057f56e93e46` (tree `aa95785ef84ddde8d1c3622e2c2d80d6b388caeb`) and `device/board/hihope` to commit `5d368fb765920c2b1cad41eb86164563461a7074` (tree `992544086dffa1a73ea444f7a22eeed25b149107`). Local bytes match these exact Git blobs:

| File | Bytes | Blob | SHA-256 |
|---|---:|---|---|
| `vendor/hihope/rk3568/product.gni` | 644 | `60e39596b26e52829b8ff4b2698cb15e1a88fed5` | `762ce8c4e909ed94d91b7dcbc4d40b3d509b5b0b02f20b3c3b38e47f50f6da86` |
| `vendor/hihope/rk3568/ohos.build` | 690 | `ea4b61b7e495cdb0a22bb64752f509832e2a9c98` | `73faae48e7bcf9a100e6bb8f1def7602958a9590f9e70636f0cf22346154fbc7` |
| `vendor/hihope/rk3568/config.json` | 10,569 | `fc7fed801d07f19f05a752878e738d8d40f1bc01` | `46dc640a6ca988687245de967f4e2ec3aebd20ed3423472c48b89bc845c28408` |
| `device/board/hihope/rk3568/device.gni` | 1,340 | `60d5f0b22c3ff6a1447aeef583ceb5c141e8d43b` | `19a5a8c0a56ab973e59d959e6c7a149fd674019d04c59c8acd440b253fb41840` |
| `device/board/hihope/rk3568/config.gni` | 812 | `12776e4d60dea146dd31c91ca93f84b3e41f6920` | `ca368f4a9db0302b4cd6c656c30e0c196070591251ac8777079861c0fd7d45b4` |
| `device/board/hihope/rk3568/BUILD.gn` | 1,389 | `748520a75b2b185a3d83ab2d995cd14433cae2bc` | `83c7881c7bad49ee2f962ae8b58141c87bc01ae760b6772ede7064968765c39e` |
| `device/board/hihope/rk3568/ohos.build` | 690 | `9d1dd250dfd061ad6c024e333ad58548b5fa7a5e` | `2723fd9d5d4497c99a0fbcaa38c3fa5bf5981024ee1549871cd0392755386c58` |

These entries identify the user-selected product configuration and board inputs. They do not bind the evaluated GN arguments, generated build graph, compiler invocation, effective macros, include closure, or toolchain. C1 therefore remains blocked pending an exact-snapshot product output or trustworthy compile database.

## Reproduce the exact object binding

Run from PowerShell with WSL available. These commands only read the existing repo-tool object store:

```powershell
wsl.exe bash -lc 'git --git-dir=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime/.git rev-parse HEAD'
wsl.exe bash -lc 'git --git-dir=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime/.git rev-parse a65a2853ccae13da167d9aa4720ab8b11ec16656^{tree}'
wsl.exe bash -lc 'git --git-dir=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime/.git ls-tree HEAD ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp BUILD.gn ecmascript/compiler/BUILD.gn js_runtime_config.gni'
wsl.exe bash -lc 'git --git-dir=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime/.git show HEAD:ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp | sha256sum'
```

Expected HEAD/tree are listed above. Expected target source SHA-256 is `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`. The relevant GN blob IDs and raw hashes are recorded in the preceding table.

## Similar-looking build evidence rejected

An existing output tree at `D:\openHarmonyScanner\outputs\ark-runtime-isolated-validation-20261018\openharmony-5.0.2` contains `out/rk3568/args.gn` with `target_cpu="arm"`, `is_debug=true`, `is_asan=true`, and `runtime_mode="release"`. Its args file SHA-256 is `549dafda36d81cadd9c2b9be8480853bcf2c1bcb739a42251002407ffb1b4d2`; this is evidence only for that separate 5.0.2 output directory.

The corresponding Ark Runtime target file is 125,705 bytes with SHA-256 `863a13e665fb9627830a658bfea082153f814b047b72ad42f052f93010a60d9d`, which does not match the exact target digest. GN stopped at `//drivers/peripheral/distributed_camera/hdi_service/test/sample/BUILD.gn:49` because OHOS component `cJSON` was not found, before producing an Ark Runtime compile action. The error log SHA-256 is `f62c0298063b6d9bc6901380ed63c66d2d6a8084fa36b79603022a84c59af631` (1,555 bytes). A filename search across the workspace's `tmp/` and `outputs/` found only this 5.0.2 `args.gn`; it found no `compile_commands.json`, `build.ninja` or compiler response file bound to the exact target commit.

An isolated rebuild was not available: `docker version` could not connect to the Docker Desktop Linux engine named pipe. The OpenHarmony workspace has no `openharmony/out` directory. No GN generation/build command was run because this source tree's GN files can execute build scripts and there is no active isolated build engine in this environment.

Therefore the 5.0.2 args, its target source, and any macros inferred from them are rejected as profile evidence for commit `a65a2853…`.

## Next evidence required

1. Product build arguments/configuration and a successful GN generation/build at `a65a2853…`, or a trustworthy `compile_commands.json`/Ninja command database bound to the same tree.
2. The expanded target compile command, compiler/preprocessor binary identity, toolchain version, target platform, ordered include paths, effective defines, generated headers and their hashes.
3. Repeated profile capture showing a stable canonical digest, plus fail-closed behavior when any profile input is missing or changes.

Until these are supplied, C1's product profile remains blocked; C2 semantic-impact judgments and C4 complete dependency identity must remain unknown/blocked. The exact commit was recovered from the already present repo-tool object store, so the earlier direct fetch rejection is no longer a blocker. No product build, test, push, or PR action was performed during this recheck.

## 2026-10-18 isolated HB GN-generation probe

The selected product was `hihope/rk3568`, bound to the current manifest and the exact Ark Runtime snapshot recorded above. The build project is `openharmony/build@6b6d6533967db07e8e7d40d140fc63d0faabacbd`. I used the manifest-pinned HB entry point with `--build-only-gn true` and `--gn-flags=--export-compile-commands`, inside a local Docker container with network disabled, a read-only root filesystem and source mount, a separate writable output directory, 16 GiB memory, eight CPUs, and 384 process limit. Exact Python 3.12.10, GN 2026, Ninja 1.13.2 and OHOS Clang 15.0.4 package and executable identities are recorded in the C4 manifest.

Product preload completed and generated the `out/preloader/rk3568` metadata. HB then logged `[LOAD] Checking all build args...` and made no further progress. After more than 17 minutes, one Python worker was in uninterruptible WSL `p9_client_rpc` I/O wait on the Windows-mounted `/mnt/d` source; sibling workers waited. No `out/rk3568/args.gn`, `build.ninja` or `compile_commands.json` was produced. The probe was interrupted and remains blocked. This is evidence of an execution-path I/O stall, not a product GN failure or a valid compile profile.

The captured HB log is `hb_probe_20261018.log` (SHA-256 `01d69ec000492bba2605c51de522ed2152d02ebc4e8cee17c8b327571ddd85f7`). Tool downloads were authenticated against their published sidecar SHA-256 values; downloads and extracted tools remain in the outer workspace scratch directory, not the C-line repository. A rerun needs a source view on WSL ext4 or another filesystem that avoids the observed 9P random-read bottleneck. Until GN generation yields exact target arguments and a target compile action, C1 stays blocked and C2 dependency semantics stay unknown.

## Current-manifest revision resolution (2026-10-19)

Ran `repo manifest -r` from the original OpenHarmony checkout; it resolved the current checkout HEAD of all 525 manifest projects. The resolved XML is 117,629 bytes with SHA-256 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55` and is preserved as `source_manifest_resolved_20261019.xml`. A full path/revision comparison against `openharmony-manifest-current-20261018.xml` found 525 expected projects, 525 resolved projects, zero missing paths, zero extra paths and zero revision mismatches. The four C1-critical revisions match the already bound objects: Ark Runtime `a65a2853ccae13da167d9aa4720ab8b11ec16656`, build `6b6d6533967db07e8e7d40d140fc63d0faabacbd`, vendor/hihope `b40eabbe69943126c65df1f9ff28057f56e93e46`, and device/board/hihope `5d368fb765920c2b1cad41eb86164563461a7074`. This proves manifest-to-checkout commit mapping; it does not prove the projects' worktrees are clean or establish an effective product compile profile. A full `repo status` read-only audit is still running at capture time.

## Critical product-source worktree status (2026-10-19)

Ran `repo status --jobs=4 build arkcompiler/ets_runtime vendor/hihope device/board/hihope` from the original OpenHarmony checkout. Exit code was 0; output says `nothing to commit (working directory clean)`. This confirms the four critical C1 repositories are clean at their resolved manifest revisions. The captured command output (312 bytes) is `repo_status_critical_20261019.txt`, SHA-256 `9f84db351a624576164e2d4b8bdbda38344929b1e1e1c920169927a5bea7f805`. The separate all-project `repo status` audit is still in progress; no full-workspace cleanliness claim is made.

## WSL transfer-path comparison (2026-10-19)

To check whether the ext4 source-copy path could be accelerated without replacing the active copy, measured an isolated tar-stream copy of `arkcompiler/ets_runtime` from the Windows-mounted checkout into a separate WSL ext4 scratch directory. The source subtree contains 10,472 files / 79,554,309 logical bytes. Tar completed in 133.53 seconds; the exact target source SHA-256 matched on both sides (`76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`). During the transfer the tar reader was observed in WSL `p9_client_rpc`; this path did not show an improvement over the active `cp -a` copy. The full ext4 copy remains active and untouched. This timing is an isolated subtree observation, not a complete-checkout throughput guarantee or build-profile evidence.

The Windows multi-threaded `robocopy` alternative was also tested on this same subtree into a separate scratch destination (`/MT:8`, symlinks copied as links). It completed in 87 seconds and the target source SHA-256 matched, but returned exit code 9 (Robocopy reports at least one copy failure), and WSL mode metadata differed on the checked source (`777`) and destination (`644`). No per-file failure list was retained, so this is not a complete or mode-faithful transfer. Do not use it as the product-build source. Keep the original `cp -a` copy running; no transfer strategy is promoted on this evidence.

## Full manifest worktree audit (2026-10-19)

The read-only `repo status` audit across the 525-project checkout completed with exit code 0. Its final output is 9,322 bytes with SHA-256 `5b5adfe66111a489b42247012278c3b4717ebd0dbac4b697dd234cb46f2db2a4`; it is byte-identical to the immutable snapshot captured while the process was still running. The complete audit reports ten project blocks with 142 changed-path records: 61 `M-` and 81 `-m`. Per project: `applications/standard/app_samples` (10), `base/tee/tee_os_kernel` (1), `foundation/multimedia/av_codec` (26), `foundation/multimedia/image_framework` (4), `kernel/linux/linux-5.10` (13), `kernel/linux/patches` (16), `kernel/linux/linux-6.6` (13), `third_party/icu` (1), `third_party/iptables` (38), and `test/xts/acts` (20). The four C1-critical repositories separately passed the targeted clean check, while these ten other projects are dirty. The captured log is currently named `repo_status_partial_20261019.txt` because it was saved before the audit finished; hash equality proves it contains the final output as well. Do not treat the original checkout or its in-progress ext4 copy as a clean exact build input. After the copy finishes, compare all project HEADs with the resolved manifest, then restore dirty worktrees only inside that isolated copy before any product build. The original checkout remains untouched.

## Exact manifest Git-archive materialization attempt (2026-10-19)

To avoid the WSL 9P random-read stall, exported each of the 525 pinned manifest project Git trees with `git archive` to a new WSL ext4 snapshot. All 525 project archives completed and the output occupies approximately 34 GiB. The user-selected `vendor/hihope/rk3568` product source is present in this tree. This is not yet a complete source materialization. The final audit covers 525 archived manifest projects and finds 19 nested gitlink entries whose exact commit trees are not included in either the exported archive or the source checkout; the corresponding directories are empty. These are nested commits outside the resolved manifest project list, which is why the materializer report records zero `unresolved_gitlinks`. The resolved manifest declares five root linkfiles. The exact `vendor/ohemu@9a85a1cece50806a5159beb23eb229ee6e83cd53` tree lacks the declared `common/qemu-run` source. That exact commit does contain `virt/qemu_run/qemu-run` (SHA-256 `d8edc3c278a1281b8ce0c949073279118238c3ebaa89032446f98d49f0f02b6c`), a different path that is not substituted. The materializer ended with status `failed` after all project archives completed and before it created root linkfiles. The report is captured in-repository at `research/experiments/ark_runtime/c1_20261017/materialization_manifest_20261019.json`, with a reproducible directory/source audit in `snapshot_gitlink_linkfile_audit_20261019.json`.

The ext4 archive tree is useful for future investigation but is not admitted as a complete build input. No HB/GN action was run against it, no `args.gn` or compile database was produced, and no profile facts are inferred from its presence. Resolve the exact pinned gitlinks and the manifest linkfile inconsistency, then perform a repeatable isolated `hihope/rk3568` GN generation before C1 can advance. C1 remains blocked; C2 semantic impact and C4 dependency closure remain unknown/blocked.

## Reproducible `hihope/rk3568` GN profile (2026-10-19)

The selected product was generated twice from the same pinned top-level source export on WSL ext4. Both runs used the manifest-pinned HB entry point and this invocation: `build/hb/main.py build --product-name rk3568@hihope --build-only-gn true --gn-flags=--export-compile-commands --ccache false --enable-pycache false --no-prebuilt-sdk true --clean-args false`. Each container had networking disabled, read-only root and source mounts, a separate writable output mount, 16 GiB memory, eight CPUs, and 384 process limit. The only source-directory overlay was the camera VDI config directory: GN calls `touch` on generated `config.c` and `params.c` there. The two zero-byte generated outputs and the original `.gitignore` were mounted writable for GN; no Ark Runtime source was overlaid. Both HB invocations exited 0 and logged `rk3568@hihope build success`.

The first successful output and the independent replay produced byte-identical `compile_commands.json` (4,103,004,071 bytes, SHA-256 `f4ac150e2af2d2d0eff5da063e5be3beee973c459d998c50ca119530019cee7e`) and `build.ninja` (SHA-256 `eb313a6a3f282c71c72186e6f3e2022973e6fa0d07efc18426e7505ce7fc8951`). Both compile databases contain 234,245 commands. The exact target source has five actions: two `arm-linux-ohos` actions, plus host x64 and Windows host variants. The ARM actions are `libark_jsoptimizer_set` (60 ordered definitions, 51 ordered include paths; command SHA-256 `c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88`) and `libark_jsoptimizer_set_with_maple` (63 definitions, 67 include paths; command SHA-256 `7471f97a0bfab59e0e350be060391af4f17511aa4c019a861822f5154750e82a`). The commands, definitions and include paths are preserved in `product_profile_20261019.v1.json`; exact args are copied to `product_args_20261019.args.gn`; the replay transcript is `hb_probe_20261019_replay2.log`.

The raw `args.gn` hashes differ because HB embeds `ohos_build_time` and `ohos_build_datetime`; normalizing only those two fields yields the same SHA-256 in both runs (`e961c620e0c91881a67280e14e5153430e364a7007f96a2a0639171d161b6cf4`). The normalized profile digest is `e86461191c065e3e140afb734c9d8c27818851ae51651f9ba004231fa7d52063`. Exact tool binary hashes match the earlier package records: Python 3.12.10 `02e619087c33f723f4bd8e7f7443f35d87d4383d9592de04b66a3c05a5d4f316`, GN `aa76f11ec5ab820695fdd0973d644d205305b1a23fabcc43e230871f502230a7`, Ninja `2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b`, and OHOS Clang++ 15.0.4 `2b28a71dbd71e1bc7f2b9b793f4add7499bee5d533e2d581df2bd0f716e7011c`. The saved profile JSON SHA-256 is `302858fc2c09bba77165da607cc95158358fecc78a3263cedbf5972d4c150c78`; successful replay log SHA-256 is `bc59e17c2fdf33c4364d19816577abc119b570afe941f6e1c5fc0f35560267ce`.

This materially advances C1, but the profile remains partial. No target object was compiled and no translation unit was preprocessed, so active transitive includes, resolved generated headers, and compiler-derived macro state are not yet confirmed. GN also reports `device_company` as an unused build argument and resolves `device_path` to `device/board/rockchip/rk3568` while the selected product path is `vendor/hihope/rk3568`; preserve this observed distinction for C2/C4 review. The exported source tree still has 19 nested Gitlink commit trees outside the manifest archive and the missing `vendor/ohemu/common/qemu-run` manifest linkfile source. GN success does not close those snapshot completeness gaps. C1, C2 semantics, and C4 remain fail-closed.

## Compiler preprocessing and Ninja closure attempt (2026-10-19)

Using the two preserved ARM compile commands and the exact Clang++ 15.0.4 tool package, attempted preprocessing, dependency-only scanning, and macro dumping for both Ark Runtime target actions inside the same no-network container. All six invocations returned 1. The first missing header is `<features.h>`: the compile command points at `obj/third_party/musl/usr/include/arm-linux-ohos`, but that generated target sysroot has not been materialized. The compiler successfully resolved its packaged OHOS libc++ headers before reaching that missing sysroot header. The complete invocation argv and stderr digests are in [preprocessor_observation.json](preprocessor_attempt_20261019/preprocessor_observation.json); the captured stderr files accompany it.

A read-only `ninja -t query` attempt against the generated graph also fails during graph parsing: `toolchain.ninja:463` reports duplicate generation of `obj/applications/standard/contacts_data/Contacts_DataAbility.stamp`. Therefore Ninja cannot currently build the missing sysroot or the target object. The captured failure is [ninja_query.log](preprocessor_attempt_20261019/ninja_query.log). This is a new source-graph blocker distinct from the earlier WSL 9P stall. The GN/compile-command profile remains repeatable, while compiler-derived include closure, preprocessed output, and macro dump remain unknown; C1/C2/C4 stay partial or blocked.

## Successful selected-action preprocessing follow-up (2026-10-19)

The exact retry3 GN output was advanced using only declared Ninja outputs and `-w dupbuild=warn`. In addition to the Musl header target set and `logger_enum_gen.h`, the following Ark Runtime generated headers were produced by their declared targets: `libpandafile/type.h`, `include/file_format_version.h`, `include/source_lang_enum.h`, `include/bytecode_instruction_enum_gen.h`, and `include/bytecode_instruction-inl_gen.h`. Their output hashes and Ninja logs are preserved in `preprocessor_success_20261019/`.

Both preserved ARM compile actions were then rerun against that same retry3 output. For each action, preprocessing (`-E`), dependency scanning (`-M`), and compiler macro dumping (`-dM -E`) returned exit code 0. The preprocessed translation units, dependency files, macro dumps, empty stderr captures, tool/container/profile identity, generated-header hashes, and a machine-readable observation are bound in `preprocessor_success_20261019/evidence_manifest.v1.json`. This closes the selected actions' active include-resolution and compiler-expanded macro observations; it does not establish a target object build or product image.

The generated Ninja invocations still emit duplicate-output warnings and required `-w dupbuild=warn`. The exact source export remains incomplete (19 nested gitlink commit trees outside the manifest archive and the missing manifest linkfile source). Keep the whole-snapshot/product-build gate partial/blocked, and keep all 18 C2 dependency semantics `unknown` until each row is reviewed against this profile. Do not treat the normalized GN profile digest alone as a complete dependency digest.
