# A line memory-safety delivery, 2026-10-17

## Scope and identity

- Role: teammate A, C/C++ Detector research.
- Branch: `codex/full-runtime-performance-audit-20261014`.
- Base merge: `9f3fcb249b6eb59d7497341ae740b230f8a7b859`.
- Detector implementation commits: `d8175fd8dbc54ccc5a30aa327d0cecda33f3a32f`, `0e4e8e7e345030d29d1f2cf0ec2e2d70f3beca29`.
- Pinned scan/review commit: `465168693b8ecd05a8eebd6a2ca33862f284f17a`.
- Isolated PoC commit: `8f556e73c5d1269f6e67edd9da5464c77df40fff`.
- Source worktree SHA-256 values are recorded in `A_MEMORY_SAFETY_SOURCE_HASHES_20261017.json`; PoC source/log hashes are in `research/evidence/cpp/a_memory_safety_poc_20261017/hashes.json`; Git blob identities are fixed by the commits above.

## Implemented capabilities

| Capability | Detector/version | Result |
|---|---|---|
| Array/copy bounds | `ohscanner.cpp.bounds` `0.2.0` | fixed array/`std::array`, copy length, index interval, stable sort element access, narrow guards, fail-closed budgets |
| Integer/size arithmetic | `ohscanner.cpp.integer_bounds` `0.1.0` | `* + -`, constant truncation, allocation/copy consequence, checked arithmetic controls |
| Reusable lexical facts | `memory_safety.py` | masked C/C++ text, function/guard spans, declarations, intervals, macro/strnlen/promotion exclusions |
| Real-source verification | `run_cpp_memory_safety_scan.py` | exact pinned Git object reads, double-read drift check, source-bound JSON/Markdown |

Supported candidate categories are CWE-119/125/787 for bounds and CWE-190/191/680/681 for integer/size calculations. Synthetic controls have no CVE. Historical `CVE-2025-23420` is used as known published ground truth, not as a new discovery.

## Real OpenHarmony evidence

Five pre-fixed local component manifests were used. The scanner never fetched, checked out or invoked an external scanner.

| Component | Commit | Files | Bytes | Candidates | Lexical groups | Wall s |
|---|---|---:|---:|---:|---:|---:|
| `communication_dsoftbus` | `652f88e0261ce4d0610f73cc451c26b84d2597af` | 1656 | 15243597 | 4 | 3 | 15.178 |
| `distributeddatamgr_kv_store` | `acfb22aac16161d8fb0cefb6cc9b92f04f489a80` | 1446 | 11765303 | 8 | 5 | 11.972 |
| `security_access_token` | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | 550 | 3484891 | 4 | 2 | 4.266 |
| `update_updateservice` | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | 219 | 851345 | 0 | 0 | 1.047 |
| `window_window_manager` | `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7` | 1112 | 20206691 | 0 | 0 | 19.615 |

Total: 4983 files / 51551827 bytes, 16 candidates / 10 detector-rule-symbol groups, 52.078s summed component wall and 282652 KiB process peak RSS. Groups are lexical deduplication only, not root-cause or vulnerability counts. Full commit/tree/snapshot/file/blob/source binding is in `research/evidence/cpp/a_memory_safety_scan_20261017/`.

Reviewed high-value shapes include `userDataLength + 1`, network/discovery `size + 1`, DB `len + KV_SUM_BLOCK_SIZE`, and channel `len + 1` allocation/copy paths. Each remains candidate/unassessed because product entry, permission boundary, attacker control, trigger, build reachability and CIA impact are unknown.

Reviewed exclusions include `kvstoremock/**` scope leakage, `strnlen` + upper-bound guard, `uint16_t + 1` promotion, macro-only sizes, and placement-new pointer arithmetic. These are documented as precision controls, not proof that the reviewed source is safe.

## Controls and fix/revalidation

`tests/detectors/fixtures/cpp_memory_safety/manifest.json` binds self-authored positive/fixed/safe/unrelated/unknown controls. Regression covers source hashes, deterministic identity, partial/failed parse, 1MiB/unit and 32MiB/run fail-closed behavior, and known false-positive shapes.

`validation/cpp_memory_safety_poc/` contains vulnerable/fixed pairs:

- Bounds vulnerable: ASan stack-buffer-overflow, exit 1.
- Bounds fixed: oversized copy rejected, exit 0.
- Integer vulnerable: deterministic `UINT32_MAX + 1 -> 0` wrap, exit 0 with `allocated=0`; no crash is claimed because this allocator did not trap the subsequent write.
- Integer fixed: overflow rejected, exit 0.

This validates the detector mechanism and synthetic fix controls. It does not fix or validate an OpenHarmony product vulnerability.

## Validation

- Full Python regression: 700 tests executed, 692 passed, 8 skipped, 111.220s.
- New memory-safety regression: 16 tests passed.
- `compileall`: passed.
- Docs context budget: `default=11400/13500`, `docs=20605/32500`.
- `git diff --check`: passed.
- Pinned source scan and isolated PoC commands are recorded in their evidence packages.

## Historical CVE replay and mechanism PoC

`CVE-2025-23420` (`arkcompiler_ets_runtime-jsarray-sort-oob-2025-02`) is bound to `openharmony/arkcompiler_ets_runtime`, vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11`, fixed `1b23531531e768398682582969c2a9f17e72cafe`, affected module `ecmascript/js_array.cpp` / `JSArray::SortElementsByObject`. The fixed commit message identifies the OpenHarmony 5.0.2 cherry-pick line; exact branch/ref is unknown in the local detached objects.

- `ohscanner.cpp.bounds` 0.2.0 produces 5 direct `ElementAccessor::Get/Set` candidates on the vulnerable blob and 0 on the fixed blob.
- The fixed patch routes accesses through `CheckStableArrayAndGet/Set`, which re-checks stable-array state and `index < GetElementsLength`.
- `validation/cpp_memory_safety_poc/cve_2025_23420_vulnerable.cpp` reproduces the comparator-mutates-backing-store mechanism under ASan (`heap-use-after-free`, exit 1).
- The paired fixed harness revalidates each index and exits 0.
- Exact vulnerable/fixed commit/tree/blob/source/patch hashes and detector output are in `research/evidence/cpp/a_historical_memory_replay_20261017/` and `research/evidence/cpp/a_memory_safety_poc_20261017/`.

This closes the historical CWE/CVE, affected module/revision, patch, and runnable mechanism PoC deliverables for one known root-cause family. It does not turn the current new-source candidates into confirmed vulnerabilities.

## Competition boundary

No newly discovered confirmed/reportable vulnerability or direct ArkCompiler product build PoC is claimed. CVE-2025-23420 is historical ground truth with a mechanism-level PoC; its affected revision is exact, while the local branch/ref is unknown. Precision/Recall are not computed without an independent reliable labelled holdout. The deliverable demonstrates new C/C++ memory/length facts, fixed-source execution, four-class controls, isolated reproducibility, false-positive review and measured performance; the remaining product evidence gate is explicit rather than replaced by candidate counts.
