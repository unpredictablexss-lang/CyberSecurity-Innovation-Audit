# A line memory-safety delivery, 2026-10-17

## Scope and identity

- Role: teammate A, C/C++ Detector research.
- Branch: `codex/full-runtime-performance-audit-20261014`.
- Base merge: `9f3fcb249b6eb59d7497341ae740b230f8a7b859`.
- Detector implementation commits: `d8175fd8dbc54ccc5a30aa327d0cecda33f3a32f`, `0e4e8e7e345030d29d1f2cf0ec2e2d70f3beca29`.
- Pinned scan/review commit: `465168693b8ecd05a8eebd6a2ca33862f284f17a`.
- Isolated PoC commit: `8f556e73c5d1269f6e67edd9da5464c77df40fff`.
- Historical OOB replay commit: `5a0225cdd1d218e1e204f02f01d9732006b52626`.
- Final delivery commit is the Git commit containing this report. Worktree source hashes are in `A_MEMORY_SAFETY_SOURCE_HASHES_20261017.json`.

## Implemented capabilities

| Capability | Detector/version | Result |
|---|---|---|
| Array/copy bounds | `ohscanner.cpp.bounds` `0.2.0` | fixed array/`std::array`, copy length, index interval, stable sort element access, narrow guards |
| Integer/size arithmetic | `ohscanner.cpp.integer_bounds` `0.1.0` | `* + -`, constant truncation, allocation/copy consequence, checked arithmetic controls |
| Resource lifetime | `ohscanner.cpp.resource_lifetime` `0.1.0` | local Alloc/Release/Alias/Null/Realloc state, UAF and double-free candidates |
| Reusable lexical facts | `memory_safety.py` | masked C/C++ text, function/guard spans, declarations, intervals and precision exclusions |
| Fixed-source verification | `run_cpp_memory_safety_scan.py` | exact pinned Git object reads, double-read drift checks, source-bound reports |
| Historical replay | `replay_cpp_historical_memory_cases.py` | vulnerable/fixed capability replay across null, UAF and OOB families |

Candidate categories: CWE-119/125/787 for bounds, CWE-190/191/680/681 for integer/size calculations, CWE-415/416 for resource lifetime. Historical published CVEs are ground truth, not new discoveries.

## Real OpenHarmony evidence

Five pre-existing local component manifests were used. No fetch, checkout, external scanner or online service was used.

| Component | Commit | Files | Bytes | Candidates | Groups | Wall s |
|---|---|---:|---:|---:|---:|---:|
| `communication_dsoftbus` | `652f88e0261ce4d0610f73cc451c26b84d2597af` | 1656 | 15243597 | 4 | 3 | 18.107 |
| `distributeddatamgr_kv_store` | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` | 1446 | 11765303 | 11 | 8 | 14.129 |
| `security_access_token` | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | 550 | 3484891 | 4 | 2 | 4.958 |
| `update_updateservice` | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | 219 | 851345 | 3 | 2 | 1.173 |
| `window_window_manager` | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` | 1112 | 20206691 | 4 | 2 | 22.678 |

Total: 4983 files / 51551827 bytes, 26 candidates / 17 lexical groups, 61.046s summed wall and 282476 KiB process peak RSS. Groups are lexical deduplication only.

## Historical CVE and fix/revalidation

| Historical case | CVE | Detector | Vulnerable | Fixed |
|---|---|---|---|---|
| `communication_dsoftbus_null_deref_001` | CVE-2025-26690 | `ohscanner.cpp.null_dereference` 0.2.0 | 5 candidates | 0 |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | CVE-2025-23420 | `ohscanner.cpp.bounds` 0.2.0 | 5 candidates | 0 |
| `c_utils-singleton-uaf-2026-01` | no CVE in benchmark | `ohscanner.cpp.shared_ptr_race` 0.5.0 | 2 candidates | 3 residual candidates |
| `kernel_liteos_a-getgroups-oob-2025-03` | CVE-2025-20042 | not applicable to lexical bounds | N/A | N/A |
| `kernel_liteos_a-os-copy-user-param-bypass-2025-03` | CVE-2025-21098 | not applicable to current A rules | N/A | N/A |

Applicable historical cases: 3. Vulnerable `possible_hit`: 3/3. Fixed `miss`: 2/3; residual candidate: 1/3. This is a small historical capability set, not product Precision/Recall or global Recall.

CVE-2025-23420 is bound to `openharmony/arkcompiler_ets_runtime`, vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11`, fixed `1b23531531e768398682582969c2a9f17e72cafe`, module `ecmascript/js_array.cpp`, symbol `JSArray::SortElementsByObject`, patch SHA-256 `e0b61dde4058080ee28184d49b3d7da80e4ad428bc2030a04fc5f69bccbc0512`. The commit message identifies OpenHarmony 5.0.2; local detached/grafted refs do not prove branch containment.

CVE-2025-26690 is bound to `openharmony/communication_dsoftbus`, vulnerable `258662cd9840b55a31546a72d91027f6368cea84`, fixed `192f3e11d74beeaa3d879333471deb8a24a7e1c5`, module `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp`. The fixed revision adds allocation null guards.

## PoC and isolated revalidation

- CVE-2025-23420 mechanism harness: vulnerable ASan `heap-use-after-free`; fixed per-access stability/index guard exits 0.
- Generic bounds harness: vulnerable ASan `stack-buffer-overflow`; fixed length guard exits 0.
- Generic integer harness: deterministic `UINT32_MAX + 1 -> 0`; fixed overflow guard exits 0. The allocator did not trap the zero-byte write, so no crash is claimed.
- A-RES-01 harness: vulnerable ASan `attempting double-free`; fixed null-after-release guard exits 0.

These are runnable mechanism PoCs and fix controls. They are not direct ArkCompiler/OpenHarmony product builds and do not prove product exploitability.

## Old/new comparison

Against `ea7d13a69852d5e639e090671b040f7dcd32eebc`: candidates 16 -> 26, lexical groups 10 -> 17, wall 52.078s -> 61.046s. The delta is added resource-lifetime coverage, not an accuracy improvement.

## Controls and validation

- Hash-bound controls cover positive/fixed/safe/unrelated/unknown for bounds, integer and resource lifetime.
- Precision exclusions include `strnlen` guards, macro-only sizes, placement-new pointer arithmetic, narrow integer promotion, branch/label-separated releases and `kvstoremock/**` scope leakage.
- Full Python regression: 704 tests executed, 696 passed, 8 skipped, 109.836s.
- Memory-safety-specific regression: 20 tests passed.
- `compileall`, JSON parsing and `git diff --check`: passed.
- Exact commands, logs and hashes are in `research/evidence/cpp/a_memory_safety_poc_20261017/` and `research/evidence/cpp/a_historical_memory_replay_20261017/`.

## Competition deliverables

| Requirement | Status |
|---|---|
| Accurate/complete analysis | Complete within explicit lexical/static boundaries |
| Supported CWE/CVE | CWE-119/125/190/191/415/416/680/681/787; CVE-2025-26690 and CVE-2025-23420 historical replay |
| Runnable reproducible PoC | ASan mechanism PoCs for OOB, UAF/double-free and fix controls |
| Affected module/version/branch | Exact module and vulnerable/fixed commits; release-line evidence; exact branch containment unknown for detached local objects |
| Fix and revalidation | Historical fix diffs plus paired fixed harnesses |
| Performance and innovation evidence | Fixed-source wall/RSS, reusable intervals/state machines, precision exclusions, old/new comparison |
| Complete report | This report plus source-bound JSON/Markdown evidence |

## Remaining boundary

No newly discovered confirmed/reportable product vulnerability is claimed. New real-source findings remain `candidate/unassessed`; `validated_vulnerability=0`. Product builds, permission/entry boundaries, attacker traces, CIA impact, complete affected deployment versions, upstream CVE closure for new candidates and large independent labelled holdout remain open. Precision/Recall are not published.
