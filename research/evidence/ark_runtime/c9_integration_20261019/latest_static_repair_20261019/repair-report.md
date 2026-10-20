# C9 latest static integrity repair

## Baseline and scope

- Independent checkout: `E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019`
- HEAD: `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457`
- HEAD tree: `d15b91627c94d9c3043d7d58d47fcf9af7e42454`
- Pinned source reviewed for migration: `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`, tree `307ac8237263db793028e0bf34a82a85f60821a5`
- Detector adapter remains `0.6.2`; `c_line_static_model()` remains `0.8.13`.
- Eligible write scope was the independent worktree's `src/ohscanner/detectors/ark_runtime` and `tests/detectors/ark_runtime`; actual edits are source modules only. No contracts, Runner, Catalog, tests, commit, push, merge, reset, or fetch.

## Repair

The import graph required five modules absent from HEAD. `type_origin.py` was also absent although not listed in the initial blocker, and is required by `analysis.py` and `test_type_origin.py`. Each was copied as a raw pinned `e4e0761` blob and verified with `git hash-object --no-filters`.

| path | source blob | SHA-256 |
|---|---|---|
| `src/ohscanner/detectors/ark_runtime/runtime_ir.py` | `e68e3191deef7a7825fe5ce9ab083e16d9ef7368` | `f3c2c85f086e223cb5897150f7d1e6890bf568599a287c1a6fe6e5411c2a39ca` |
| `src/ohscanner/detectors/ark_runtime/syntax.py` | `8507a127856d22af01a6eaa64738c8030ed414af` | `c3616ad6404967927d1a4a98c46257f8df19c3c36990efbae82c859f5108bcf9` |
| `src/ohscanner/detectors/ark_runtime/type_origin.py` | `e2c8712bfb98d7fee7cd02e518e4ce12eb2ab7d5` | `a5ca62d12988de3ee8019b02ca146d3a333b96c56021e2b7239a0e6f587bfd29` |
| `src/ohscanner/detectors/ark_runtime/runtime_exception.py` | `ff9ecb72ed099745f9f20b04d2b14fedb761230d` | `c253edcb7716b4f785ab132bbc7b519aabaf9b736280bcc631a37f96306385ac` |
| `src/ohscanner/detectors/ark_runtime/size_overflow.py` | `c76fbb814091060c458ee2b38ba62bc5c14ab47a` | `6d2bab177c9525ddd68d3ff345480765f4d922b76b85918b02234c79f0b1282f` |
| `src/ohscanner/detectors/ark_runtime/receiver_guard.py` | `abd68c990a60fe82eb9f0546b6bb9878e19a84c2` | `80cb6c3239cfc18be3ef3c47e26a10ac44084ff671df828dd88a70dbe0833461` |

`receiver_guard.py` at HEAD was repaired by replacing the corrupted line-137 splice and its accidental `OriginState`/`OriginEvaluator` tail with the intact pinned module. The complete generated patch is [repair.diff](E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019\research\evidence\ark_runtime\c9_integration_20261019\latest_static_repair_20261019\repair.diff), SHA-256 `a35c9d0482da41aeac4b6e26c6647bb6f8ddaad4ba92d9928a44be385f8cda94`.

## Exact verification

Exact argv, environment, cwd, exit code, wall time, and full stdout/stderr are in [check-records-wsl.json](E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019\research\evidence\ark_runtime\c9_integration_20261019\latest_static_repair_20261019\check-records-wsl.json) and `logs-wsl/`.

| check | result | exact outcome |
|---|---|---|
| import smoke | **pass** | 11/11 modules imported: `known_cves`, Catalog, Runner, Ark model/adapter and all repaired modules |
| `tests.detectors.test_known_disclosed_cves` | **blocked / fail** | 21 run, 2 failed |
| Ark `unittest discover -s tests/detectors/ark_runtime -t . -v` | **blocked / fail** | 115 run, 6 failed, 1 error, 3 skipped |
| `tests.test_owner_cd_admission` | **pass with skips** | 7 run, 0 failed, 2 skipped |

### Fail-closed root causes

1. `known_disclosed_cves`: `test_appdomainverify_cve_2026_58313_real_lru_fix_pair` and `test_libpng_neon_palette_cve_2026_33636_exact_upstream_pair` read worktree fixture bytes and compare raw Git blob SHA-1. The checkout has CRLF fixture bytes (`git hash-object --no-filters` differs), while `git hash-object` with the configured clean filter matches the committed blobs. This is an exact fixture identity/worktree line-ending mismatch; no known-CVE rule pass is claimed.
2. Ark discover imports `test_runtime_exception`, which requires `_verified_generated_branch_owners`; that helper is absent from the pinned `runtime_exception.py` blob. No source in the allowed pinned candidates supplies it, so this is explicitly blocked rather than inventing semantics.
3. Six `test_c3_mechanisms` expectations remain semantically incompatible with the pinned implementation (`matched` returned where tests require `unknown`/`candidate`, including G07). The same six failures reproduce with the untouched `e4e0761` checkout, so they are not introduced by this repair. They remain blocked pending an authorized semantic patch.

## Current state

The latest static baseline is import-runnable, but not integration-passing. Do not report known-CVE coverage or Ark acceptance as safe/pass. The minimal next slice is to resolve the runtime-exception helper contract and the six C3 semantic mismatches in separate, reviewed algorithm patches; normalize fixture identity for exact known-CVE replay without changing rule code.

## Reproduction commands

The exact commands are preserved in `check-records-wsl.json`; the high-level forms were:

```text
/usr/bin/python3 -B -m unittest -v tests.detectors.test_known_disclosed_cves
/usr/bin/python3 -B -m unittest discover -s tests/detectors/ark_runtime -t . -v
/usr/bin/python3 -B -m unittest -v tests.test_owner_cd_admission
```

No commit/push/merge/reset/fetch was performed.
