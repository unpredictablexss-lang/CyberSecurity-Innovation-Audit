# OHScanner taskbook progress report, 2026-10-17

## Executive conclusion

This report consolidates the current A, B and platform evidence after the 2026-10-17 taskbook review. It is complete as a current-state competition report, but the taskbook itself remains **incomplete** because product-level closure, whole-community scale and a large independent holdout are not proven.

Validated historical CVE capability exists for CVE-2025-26690, CVE-2025-0587 and CVE-2025-23420. New real-source candidates remain `candidate/unassessed`; `validated_vulnerability=0`.

## Repository and branch state

- Branch: `codex/full-runtime-performance-audit-20261014`.
- Latest pushed head: `8276bfe408dcaecb6c374ea3e0f53438b7a013c4`.
- Local and remote heads match.
- `origin/main`: `de4d42a025404d87bdef59013c8999ff22a6d3a0`.
- Codex 0 reconciliation is in `CODEX0_BRANCH_RECONCILIATION_20261017.md`.
- `work/ipc-20261017` is absent from the current remote ref inventory and cannot be treated as executable current evidence.

## Shared engine and public facts

CLI and Web use the same OHScanner core. Historical source-bound v1 is preserved; v2 diagnostics bind source hashes and obligations.

`build_fact_view_v2` exposes reviewed slots for:

- symbols;
- CFG edges;
- numeric ranges;
- call edges;
- taint facts;
- explicit unknowns.

Missing facts stay unknown and are never inferred as safe. Ordinary scans auto-select approved security detectors; the example detector remains opt-in.

## A line: C/C++ memory safety

| Detector | Version | Main capability |
|---|---|---|
| `ohscanner.cpp.bounds` | 0.2.0 | array/copy bounds, index intervals, stable element access |
| `ohscanner.cpp.integer_bounds` | 0.2.0 | arithmetic overflow/underflow, truncation, narrowing index |
| `ohscanner.cpp.resource_lifetime` | 0.1.0 | UAF/double-free lexical state machine |
| `ohscanner.cpp.unsafe_memory_call` | 0.1.0 | unbounded calls and non-literal format candidates |
| existing null/lifetime/shared_ptr | 0.2.0 / 0.4.0 / 0.5.0 | null, owner invalidation and shared owner race candidates |

Five pinned OpenHarmony components were scanned:

- 4,983 files / 51,551,827 bytes.
- 33 candidates / 22 lexical groups.
- 67.107s summed wall time.
- 282,972 KiB process peak RSS.

Candidate counts are not vulnerability counts. Groups are lexical deduplication, not root causes.

## B line: IPC and ArkTS/JS

Current IPC six-family synthetic coverage census:

| Family | Controls | Matched | Mismatch |
|---|---:|---:|---:|
| AUTH-01 | 23 | 23 | 0 |
| AUTH-02 | 6 | 6 | 0 |
| AUTH-03 | 7 | 7 | 0 |
| AUTH-04 | 6 | 6 | 0 |
| CAP-01 | 3 | 3 | 0 |
| DATA-01 | 3 | 3 | 0 |
| Total | 48 | 48 | 0 |

This proves current synthetic rule coverage only, not product authorization or vulnerability truth.

The JS/TS/ArkTS frontend reports syntax/outline coverage and five bounded rule families: dangerous eval, path taint, component exposure, WebView bridge and native bridge. The pinned scan produced zero candidates in the selected current components; zero is not a safe verdict.

## Cross A/B case

The controlled Parcel case composes:

- A: destination capacity and `RangeFact`;
- B: `MessageParcel`, `ReadInt32`, `ReadBuffer`, `memcpy` semantics and obligations.

Positive: A copy candidate + B `ipc.parcel.copy-range` + unbounded range.
Fixed: both layers quiet + `[0,64]` bounded range.

This is a synthetic integration case, not a real product exploit.

## Historical vulnerability capability

| Case | CVE | Vulnerable | Fixed |
|---|---|---:|---:|
| `communication_dsoftbus_null_deref_001` | CVE-2025-26690 | 5 candidates | 0 |
| `arkcompiler_ets_runtime-atomic-index-overflow-2025-03` | CVE-2025-0587 | 1 candidate | 0 |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | CVE-2025-23420 | 5 candidates | 0 |
| `c_utils-singleton-uaf-2026-01` | no CVE in benchmark | 2 candidates | 3 residual candidates |

Four applicable historical cases produced 4 vulnerable `possible_hit`; three fixed revisions were quiet and one retained a synchronization-related residual candidate. Two kernel race/user-kernel cases are not applicable to the current lexical rules.

This is not product Precision/Recall or global Recall.

## PoC and fix/revalidation

- CVE-2025-23420 mechanism: ASan `heap-use-after-free`; stable/index fixed control exits 0.
- Generic bounds: ASan `stack-buffer-overflow`; fixed guard exits 0.
- Resource lifetime: ASan `attempting double-free`; null/reallocate controls exit 0.
- CVE-2025-0587 narrowing index: deterministic bounds-check bypass; fixed wide-index control rejects.
- Integer wrap control: `UINT32_MAX + 1 -> 0`; fixed checked arithmetic rejects.

These are runnable isolated mechanism PoCs. The CAP-01 source-bound component model executed in Docker, but direct OpenHarmony/ArkCompiler product builds were not executed.

## CAP-01 real-source component replay

A source-bound `window_window_manager` CAP-01 capability-export case was replayed in the isolated project Docker image:

- 10/10 pinned source blobs and 18/18 quoted source relations verified.
- Vulnerable / fixed_control / patched variants built with clang 14 and UBSan.
- 4 scenarios x 3 variants x 3 repeats: 36/36 expected behaviors, 0 mismatches.
- Vulnerable exports to unauthorized and authorized callers; fixed/patched deny unauthorized callers and preserve authorized export.
- Proposed patch adds the existing system-caller guard before `GetRenderSession`.
- `component_model_dynamic_validation=true`, `stable_replay=true`, `product_dynamic_validation=false`, `validated_vulnerability=0`.

Source review further establishes that the transaction path lacks the same `SessionPermission::IsSystemCalling()` guard used by nearby service methods; the returned object remains an opaque RS UI/session token. This is the strongest current real-source replay, but deployed caller acquisition, remote-object capability surface, runtime/CIA and release evidence remain open.
## Recent increment and scale

The local 2026-10-02..2026-10-18 increment covered 12 locally available repositories:

- 4 first-parent commits.
- 118 unique changed source files summed by repository.
- 9.413s planning/scan wall time.

Whole-community/807-repository execution is explicitly `not_executed` because only local cloned repositories were authorized and no extra repositories were fetched.

## Performance environment

- CPU: AMD Ryzen 7 7735H, 8 cores / 16 logical CPUs.
- WSL2 Linux 6.18.54.1-microsoft-standard-WSL2.
- WSL memory: 7.4 GiB total, 2.0 GiB swap.
- Python 3.10.12.
- C/C++ frontend: Tree-sitter C/C++.
- Web TypeScript and build passed.

## Validation

- Full Python regression: 719 executed, 711 passed, 8 skipped, 113.122s.
- Workbench/M2: 51 tests passed.
- Fact v2: 3 tests passed.
- Cross A/B: 1 test passed.
- ArkTS/JS: 4 tests passed.
- `compileall`, JSON parsing, docs budget and `git diff --check`: passed.
- Web TypeScript and `build.mjs`: passed.

## Competition deliverables

| Deliverable | Evidence state |
|---|---|
| Accurate/complete current-state analysis | Supplied |
| Supported CWE/CVE | CWE-119/125/190/191/200/415/416/680/681/787; CVE-2025-26690, CVE-2025-0587, CVE-2025-23420 |
| Runnable reproducible PoC | Supplied at mechanism level |
| Affected module/version/branch | Exact modules and vulnerable/fixed commits; branch containment limited for detached local history |
| Fix and revalidation | Historical fixes plus paired fixed controls |
| Performance/innovation | Wall/RSS, incremental run, old/new comparison, shared facts and precision exclusions |
| Complete report | This report |

## Remaining work

1. Direct product-build or independently isolated real-product PoC.
2. Restore/provide `work/ipc-20261017` and selectively reconcile its product IPC evidence.
3. Execute a genuinely authorized whole-community scale run.
4. Freeze a larger independent labelled holdout and then compute root-cause Precision/Recall/F1.
5. Complete product permission/entry/CIA/version/branch evidence for any new candidate.

Until those items are proven, the correct taskbook status is `incomplete`.
