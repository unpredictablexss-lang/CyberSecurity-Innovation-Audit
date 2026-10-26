# C3 current Ark Runtime snapshot binding and Runner replay

Date: 2026-10-18 (Asia/Shanghai)

## Decision

The local source identity is verified, so the exact target snapshot was added to the Ark Runtime research detector model, version `0.6.2` (the prior C4 experiments used `0.6.1`). The catalog entry remains `kind=research_candidate`, `default_enabled=false`, and requires explicit selection of `ohscanner.ark.runtime.type_safety`.

This is a research-only applicability entry. It does not make the result production-ready: the current source parses as partial, the detector cannot recover the exact namespace/class owner after Tree-sitter error recovery, and 18 of 19 model-supporting source blobs differ from the reviewed historical model inputs. No current-version candidate was emitted.

## Verified source identity

| Field | Value |
|---|---|
| Repository | `openharmony/arkcompiler_ets_runtime` |
| Checkout | `D:\openHarmonyScanner\openharmony\arkcompiler\ets_runtime` |
| Commit | `a65a2853ccae13da167d9aa4720ab8b11ec16656` |
| Tree | `8781f036a3e7e04d8e0b34970d5f623b42875016` |
| Path | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` |
| Index mode | `100644` |
| Git blob | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| File SHA-256 | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| Parser | `partial` |
| Component checkout status | clean |

The commit, tree, index entry, Git blob, and SHA-256 were read from the local Git object store through WSL. The CLI independently loaded the pinned Git commit and reported the same commit/tree and target-source SHA. No network fetch was used.

`git rev-parse HEAD:<path>`, the index entry, and `git hash-object <path>` all returned blob `68fb3b0…`; `git cat-file -s HEAD:<path>` returned 150,610 bytes. The checked-out working tree was clean.

## Run results

The explicit current-version CLI run selected one file. It returned `blocked`, zero diagnostics, `not_analyzed=1`, `complete=0`, `partial=0`, and `validated_vulnerability=0`. The file's parser status remains `partial`; the detector limitations include `runtime_owner_not_resolved` and `target_not_resolved_in_partial_ast`. Since the analyzer did not resolve the target function, zero candidates here means unknown coverage, not a fixed or safe result.

The unbound parent commit `6518536b40ae58ef959a0572d82ddfece862eda0` contains the same target-file blob but has a different tree and is not an admitted commit. Explicit Runner execution returned `blocked`, zero diagnostics, and `not_analyzed=1`. This checks the exact commit gate even when file bytes happen to match.

The existing C4 historical evidence supplied for this work reports type-origin parent/fix candidate counts `1/0` and exception-guard parent/fix `2/0`, all partial/blocked. The current component Git object store lacks those historical commits, so that parent/fix result could not be replayed from this checkout. The old commit tests are explicitly skipped when their Git objects are absent; no source bytes were relabeled as `git_object` provenance.

The Runner contract controls passed: a fixed/safe control does not produce a rule candidate; a bound partial positive control remains blocked; and a valid local candidate plus evidence obligations survive aggregate blocked status. These controls are synthetic fixtures, separate from the current exact-source result and the unavailable historical Git replay.

## Model context drift

The runtime model references 19 supporting source blobs (effect summaries and allocation/type dependencies). At the current commit, 1 blob is unchanged and 18 differ. These supporting files have not been semantically re-reviewed for this snapshot. The exact target file binding therefore authorizes only a bounded research attempt; it does not validate the old model assumptions against the current product build. The full expected/observed list is in `model_dependency_comparison.json`.

## Exact commands

Metadata checks (read-only; the `.git/config` link in the component checkout is a repo-tooling symlink that Windows Git cannot read, so Git metadata commands use WSL):

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime && git rev-parse HEAD && git rev-parse HEAD^{tree} && git status --short && git ls-files --stage -- ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp && git hash-object -- ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp && sha256sum ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
```

Current exact-source CLI replay (C4 Runner/CLI path; detector explicitly selected):

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m src.cli ohscan-run --repo-dir /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/experiments/ark_runtime/c3_20261018/current-run.json --md-out research/experiments/ark_runtime/c3_20261018/current-run.md'
```

Unbound same-blob parent negative control:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m src.cli ohscan-run --repo-dir /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit 6518536b40ae58ef959a0572d82ddfece862eda0 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out research/experiments/ark_runtime/c3_20261018/unbound-parent-run.json --md-out research/experiments/ark_runtime/c3_20261018/unbound-parent-run.md'
```

Regression command and result:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && export PYTHONPATH=$PWD OHSCANNER_ARK_REPO=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime && /tmp/ohscanner-c4-py312/bin/python -m unittest tests.detectors.ark_runtime.test_type_origin tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_ir_path tests.detectors.ark_runtime.test_c3_mechanisms tests.detectors.ark_runtime.test_detector_cases tests.detectors.ark_runtime.test_exception_guard tests.detectors.ark_runtime.test_historical tests.test_runner_applicability -v'
```

Result: **95 tests passed, 2 skipped**. Both skips are historical Git pair suites whose exact bound commits are absent from the supplied local component store. An initial `unittest discover -s tests/detectors/ark_runtime` attempt failed because it imported package tests without their package context; the explicit module invocation above is the successful rerun.

The explicitly run safe/fixed fixture controls and blocked-candidate retention controls were:

```powershell
wsl.exe -d Ubuntu -- bash -lc 'cd /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4 && PYTHONPATH=$PWD /tmp/ohscanner-c4-py312/bin/python -m unittest tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C04_target_type_has_same_identity tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C05_local_object_alias_preserves_identity tests.detectors.ark_runtime.test_type_origin.TypeOriginTests.test_C06_token_copy_preserves_origin tests.detectors.ark_runtime.test_exception_guard.ExceptionGuardSyntheticTests.test_exception_return_before_use_suppresses_candidate tests.detectors.ark_runtime.test_detector_cases.ContractAdapterTests.test_aggregate_limited_does_not_discard_valid_local_candidate tests.detectors.ark_runtime.test_detector_cases.ContractAdapterTests.test_exactly_bound_partial_fixture_preserves_candidate_and_unknown_scope -v'
```

Result: **6 passed**. The four safe/fixed synthetic controls emitted no candidate; the two positive fixture controls kept a candidate and its obligations when aggregate status was blocked. They are synthetic parser/model controls, not substitutes for the historical upstream fixed commits that are absent locally.

## Files and limitations

- `current-run.json` / `current-run.md`: exact current-source CLI report.
- `unbound-parent-run.json` / `unbound-parent-run.md`: exact-commit mismatch report.
- `model_dependency_comparison.json`: expected and current blobs for all 19 model dependencies.
- No component source was changed. No push or merge was performed. The A-line checkout was not edited/reset/cleaned/stashed.
- This is one file of one commit, one `light-ast` profile, and a bounded syntax/IR model. Build flags, product packaging, runtime reachability, trigger conditions, security impact, and the changed model dependencies remain unverified.
- `validated_vulnerability` remains zero. Neither zero candidates nor blocked/not-analyzed coverage is a security verdict.

## 2026-10-18 dependency semantic review follow-up

## Exact product build/preprocessor context (2026-10-18)

The C3 source identity and target-file SHA-256 are present in the earlier source-binding evidence, but this checkout could not produce an exact product compile profile. The current Windows Git executable cannot read the component checkout's `.git/config` tooling symlink; the recorded WSL route failed to start in this session. The current target file still hashes to `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`, matching the previously bound bytes. This does not refresh commit/tree provenance.

Static build-system inspection found the target listed at `arkcompiler/ets_runtime/ecmascript/compiler/BUILD.gn` and the runtime product groups `ark_js_packages` / `libark_jsruntime` in `arkcompiler/ets_runtime/BUILD.gn`. Those declarations establish source/target membership only. We found no `compile_commands.json`, GN `args.gn`, or Ninja graph in the exact-source checkout or supplied isolated 5.0.2 output tree. Therefore the actual platform, product, build target, compiler/version, macros, include search order, generated headers and exact command are all **unknown**. No hand-authored macro list is used.

The separate OpenHarmony 5.0.2 validation attempted `rk3568` with `ark_js_host_linux_tools_packages`, `is_debug=true`, and `is_asan=true`. Its logs show failure before Ark Runtime compilation: hb startup could not import `jinja2` on Ubuntu 24.04.4, outside that release branch's stated Ubuntu 18.04/20.04/22.04 host support. The target is a Linux host-tools package, not proof of a `rk3568` device image build. These attempts are diagnostic evidence only and do not define the C3 product profile. Logs and their hashes are indexed in `outputs/ark-runtime-isolated-validation-20261018/README.md` and `validation.json`.

`build_profile.json` records this exact binding as blocked, with every unavailable product field set to unknown. `build_profile.py` is an explicit local capture/replay tool. It accepts only a pre-existing compilation database, requires one exact source entry, checks repository/commit/tree/blob and source SHA, runs the selected compiler's dependency-only preprocessing to enumerate and hash resolved headers, and emits a profile digest. `replay` then runs the same command with `-E -dD`; it reports a preprocessed translation unit only after that compiler invocation succeeds. It never invokes GN, Ninja, `build.py`, `build.sh` or other repository scripts. Missing profile/database/source/header, mismatched Git identity, or compiler failure returns exit 2 with a diagnostic and no success record.

From a compatible Linux checkout where Git metadata works, the intended explicit calls are:

```sh
python3 research/experiments/ark_runtime/c3_20261018/build_profile.py capture \
  --manifest research/experiments/ark_runtime/c3_20261018/build_profile.json \
  --source-root /path/to/arkcompiler_ets_runtime \
  --compile-db /path/to/gn-out/compile_commands.json \
  --build-root /path/to/gn-out \
  --output /path/to/evidence/profile.json

python3 research/experiments/ark_runtime/c3_20261018/build_profile.py replay \
  --manifest research/experiments/ark_runtime/c3_20261018/build_profile.json \
  --source-root /path/to/arkcompiler_ets_runtime \
  --compile-db /path/to/gn-out/compile_commands.json \
  --build-root /path/to/gn-out \
  --output /path/to/evidence/typedarray.i \
  --record /path/to/evidence/replay-profile.json
```

The replay command requires an already generated profile input (`compile_commands.json`); it does not create one or configure a product. It records compiler version and profile-tool version/code hash. Compiler response files are expanded and individually hashed. Until the exact build output is supplied from a supported environment, profile status remains `blocked`, preprocessing remains unexecuted, and parser token rewriting is not treated as preprocessing. No untrusted build script was run.

Tool verification on the current host:

```powershell
python research/experiments/ark_runtime/c3_20261018/build_profile.py self-check
```

Result: `passed`, stable repeated fixture digest `691765441b2014a876220181c579fdbc7a90f74b49a83236945d1ff40b212af0`; changing one macro, a dependency hash, compiler version, or compile parameter changed the digest in each case. This deterministic fixture tests digest behavior, not a product profile. `python -m py_compile .../build_profile.py` passed. A real capture attempt against the component checkout exited 2 with `git identity check failed (rev-parse HEAD)` because Windows Git cannot read `.git/config`; a missing manifest also exited 2. The current host therefore could not perform an end-to-end successful profile capture/replay. A filesystem search found no compilation database or `args.gn` in the inspected exact-source/5.0.2 output trees.

The original 0.6.2 run artifacts above are retained as historical evidence. The 19 supporting source pairs were subsequently checked against their exact old commits and `a65a2853ccae13da167d9aa4720ab8b11ec16656`; 18 changed and one blob is identical. The function-context review found material differences around IR wrappers/control flow, HClass/type predicates, TypedArray creator/allocation, and the caller/sink surface, so no semantic equivalence was granted. The per-dependency sources, commits, blobs, inspected symbols/intervals, and reasoning are in [dependency-review-20261018.md](dependency-review-20261018.md).

The default model is now `0.6.3`, digest `79e69842146939fd1d278b10165bc4b1c468cf26676b56c04eaf09bf9c7f82e6`. It retains prior exact historical bindings but removes `a65a…` as an admitted target and carries the exact blocked tuple: commit `a65a…`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, snapshot SHA-256 `7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2`, and comparison-manifest SHA-256 `c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d`. The Detector returns `not_analyzed` before analysis for that snapshot. Its limitation records the tree, snapshot, manifest and model digests. The rule remains non-default and explicit-selection only.

The follow-up Runner report is `dependency-gated-run-20261018.json` / `.md`: target `a65a…`, tree `8781f036…`, one selected file, `partial` parser, Detector `blocked`, 1 `not_analyzed`, 0 diagnostics, `validated_vulnerability=0`, top-level `completed_with_limitations`. This is unknown coverage, not a safe/fixed result.

Exact old commits were absent from the component object store at first. Fetching from the configured gitcode remote failed before object transfer (`bad line length character: <CH`); fetching the four model-pinned commits from `https://github.com/openharmony/arkcompiler_ets_runtime.git` succeeded. No branch was updated and the component worktree remained clean. With those objects available, the C1 historical parent/fix Runner replay and exception-guard parent/fix pair ran as part of the regression command and passed.

```powershell
wsl.exe -d Ubuntu -- git -C /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime fetch --no-tags https://github.com/openharmony/arkcompiler_ets_runtime.git 830e85b40240677039719fcbf14f721ad3b19050 a0e30483ab3e4aead67ecfb5c708489915e447f9 c758818dbfd0b146a908d43d21f6ca1706c33783 81ca57487d04ea30cd11c271e86494a4e130f43e
```

Runner gate reproduction:

```powershell
wsl.exe -d Ubuntu -- env PYTHONPATH=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review /mnt/d/openHarmonyScanner/.venv-scanner-wsl/bin/python -m src.cli ohscan-run --repo-dir /mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review/research/experiments/ark_runtime/c3_20261018/dependency-gated-run-20261018.json --md-out /mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review/research/experiments/ark_runtime/c3_20261018/dependency-gated-run-20261018.md
```

This produced the one-file `blocked`/`not_analyzed` report described above with exact commit/tree/snapshot, manifest, and model digests.

Regression command:

```powershell
wsl.exe -d Ubuntu -- env PYTHONPATH=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c3-review OHSCANNER_ARK_REPO=/mnt/d/openHarmonyScanner/openharmony/arkcompiler/ets_runtime /mnt/d/openHarmonyScanner/.venv-scanner-wsl/bin/python -m unittest tests.detectors.ark_runtime.test_type_origin tests.detectors.ark_runtime.test_parser_owner tests.detectors.ark_runtime.test_ir_path tests.detectors.ark_runtime.test_c3_mechanisms tests.detectors.ark_runtime.test_detector_cases tests.detectors.ark_runtime.test_exception_guard tests.detectors.ark_runtime.test_historical tests.test_runner_applicability -v
```

Final result after the report/digest assertion: **101 passed, 0 skipped, 0 failed**. The same command also exercised the retained exact parent/fix Runner bindings after their commits were fetched. The matrix in the review file maps positive, fixed/safe, unrelated and unknown controls to their tests. Those are synthetic/history controls for the established model mechanisms; they do not resolve the changed dependency semantics, and no rule candidate is enabled for C3.
