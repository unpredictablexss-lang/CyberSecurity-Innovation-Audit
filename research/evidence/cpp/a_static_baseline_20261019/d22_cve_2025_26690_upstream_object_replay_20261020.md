# CVE-2025-26690 upstream-object replay (D22)

Date: 2026-10-20 (Asia/Shanghai)

## Disposition

**No detector change. Case remains PARTIAL/BLOCK.** The scanner now replays the exact upstream vulnerable and fixed commits from a local Git object store. It reports five unassessed null-dereference candidates on the vulnerable source and zero same-rule candidates on the fixed source. The source parses completely, but `ohscanner.cpp.null_dereference` reports blocked/partial semantic coverage for this file. This is not a complete static pass, a safe verdict, or vulnerability confirmation. No reproducible rule miss was observed, so changing the detector would not be evidence-driven.

## Source identity

Repository: `openharmony/communication_dsoftbus`

Path: `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp`

| Variant | Commit | Tree | Git blob | Bytes | Raw SHA-256 |
|---|---|---|---|---:|---|
| Vulnerable | `258662cd9840b55a31546a72d91027f6368cea84` | `366a4ced9400653c9628c0b677e4ae657c0e7bd8` | `a82b71fb5520b02278a4af695bbe918d14c1048e` | 8502 | `5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6` |
| Fixed | `192f3e11d74beeaa3d879333471deb8a24a7e1c5` | `1d58ba0ef706a6f69dd372bd496c8058810882aa` | `13ddbe93a7f617784dec0f3761e09f66b5c3217c` | 9387 | `5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81` |

The exact commit objects were fetched from `https://gitcode.com/openharmony/communication_dsoftbus.git` into a separate bare object store, then checked out from those objects into two isolated worktrees. The scanner loads the pinned Git objects; the working-tree files on Windows have CRLF checkout conversion, so the hashes above were computed from `git show <commit>:<path>` bytes, not checkout bytes. Tree and blob IDs were read from the actual upstream objects.

## Current CLI replay

Detector: `ohscanner.cpp.null_dereference` v0.6.0. Candidate rule: `ohcpp-null-dereference-candidate-001` v1.4.0. Profile: `light-ast`. Scope: one pinned C++ file.

| Variant | Source parse | Detector status / coverage | Candidates |
|---|---|---|---|
| Vulnerable | complete (1/1) | blocked; partial (0/1 semantically complete) | 5 at lines 71, 82, 97, 108, 123 |
| Fixed | complete (1/1) | blocked; partial (0/1 semantically complete) | 0 |

The five vulnerable candidates are `new (std::nothrow)` results assigned to `clientProxy` followed by method dereferences without a local null guard. The fixed commit adds `clientProxy == nullptr` early-return checks immediately before the corresponding method calls at all five sites. The observed candidate/fixed differential agrees with the source patch. The candidate findings explicitly retain unknown guard dominance, missing compile context, caller boundary, attacker control, reachability, trigger, and CIA impact obligations.

CLI artifacts are adjacent JSON and Markdown files:

- `d22-cve-2025-26690-vulnerable.json` / `.md`
- `d22-cve-2025-26690-fixed.json` / `.md`

Commands, from the D22 scanner worktree:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-vulnerable --repository openharmony/communication_dsoftbus --commit 258662cd9840b55a31546a72d91027f6368cea84 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/a_static_baseline_20261019/d22-cve-2025-26690-vulnerable.json --md-out research/evidence/cpp/a_static_baseline_20261019/d22-cve-2025-26690-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-fixed --repository openharmony/communication_dsoftbus --commit 192f3e11d74beeaa3d879333471deb8a24a7e1c5 --include core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp --detector ohscanner.cpp.null_dereference --json-out research/evidence/cpp/a_static_baseline_20261019/d22-cve-2025-26690-fixed.json --md-out research/evidence/cpp/a_static_baseline_20261019/d22-cve-2025-26690-fixed.md
```

## Controls and verification

The existing detector regression and signal-control suites were run without modifications: `python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -q` — **21 tests passed**. The bound 19-control manifest includes positive, fixed, safe, and unrelated categories, verifies fixture hashes, and exercises partial-coverage fail-closed behavior. These fixture controls validate the detector mechanism; they are not substitutes for product-specific safe/unrelated `communication_dsoftbus` source controls, which remain unavailable in this replay.

No new source fixture or detector code was added: the exact upstream fix provides the fixed control; existing independently hashed detector fixtures provide safe/unrelated and partial mechanism controls. Since the rule already emits the five expected candidates and the semantic coverage remains partial, expanding the rule is not warranted by this evidence.

## Remaining limits

- No product build configuration, compiler flags/macros, runtime allocation-failure test, real caller/reachability trace, or impact evidence was available.
- Exact upstream safe/unrelated source controls were not identified; detector fixture controls are mechanism-only.
- The CLI emits candidates, not confirmed vulnerabilities. The zero fixed findings are a same-rule differential only and do not establish component safety.
- Historical raw reports were not present and are not reconstructed or represented as recovered; the attached CLI outputs are new runs from exact upstream commits.
