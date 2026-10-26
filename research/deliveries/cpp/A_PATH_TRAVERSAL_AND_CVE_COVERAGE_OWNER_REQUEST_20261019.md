# A 线 detector 接入与已披露 CVE 归因请求（2026-10-19）

## Baseline

- Latest base: `origin/main` / `db77164fdc2af0da02e4d3efc056d84694fd68e8`.
- A-line detector worktree: `codex/a-path-traversal-detector-20261019`.
- A0 sample 2 actual profile (`run_meta.json`): `ohscanner.interface.ipc`, `ohscanner.cpp.lifetime`, `ohscanner.cpp.shared_ptr_race`.
- A0 scan repository/scope: DataShare only (`foundation/distributeddatamgr/data_share`). The adjacent Contacts issue source is in `applications/standard/contacts_data`, a distinct repository and scope. This is not a direct miss in the original A0 scan scope.

## Request 1: explicit path-traversal profile admission

Please review `src/ohscanner/detectors/cpp/path_traversal_detector.py` plus `tests/detectors/test_cpp_path_traversal_detector.py` and its fixtures for optional admission as `ohscanner.cpp.path_traversal` in an explicit C/C++ security profile. Do not add it to the default profile without a profile-level false-positive/coverage review.

The detector is bounded lexical source-to-file-sink analysis for typed `DataShareValuesBucket` string access, same-TU propagation, direct libc file APIs, and one explicit `Contacts::FileUtils::DeleteFile` API model. The exact-source Contacts excerpt produces DeleteFile candidates at lines 23/24/28 and open candidates at 42/53; overall unit coverage remains blocked due to unrelated external calls. Findings are `partial` CWE-22 candidates with source hash and evidence obligations. Cross-file implementation of `FileUtils::DeleteFile` is not in this fixture; admission review should require binding its exact definition and verifying its `unlink` semantics, or keep the method model explicitly allowlisted and documented.

Admission owner actions:

1. Verify detector contract compatibility, deterministic ordering, limits and partial/blocked behavior.
2. Decide whether a separately selected `contacts_data` repository can be scanned alongside DataShare targets and how target profile exposes optional detector selection.
3. Add catalog metadata/profile wiring and compatibility tests only after accepting the research implementation; keep default detector IDs unchanged unless separately justified.
4. Preserve A0's historical profile and findings; do not retroactively claim it directly scanned the Contacts source.

## Request 2: KnownDisclosedCveDetector precision/attribution review

At this base, `ohscanner.known_disclosed_cves` covers most named public-CVE source patterns but `src/ohscanner/detectors/catalog.py` keeps it disabled by default. The rule being present is not ordinary-scan coverage. The report and code review also surfaced CVE tags needing root-cause mapping before these patterns are described as coverage:

| CVE tag | Current rule shape | Audit concern | Minimum next evidence |
|---|---|---|---|
| CVE-2026-58313 | LRU list/map iterator and concurrency shape | Source report says the advisory summary does not map precisely to this cache; local current source has protection indications. | Exact advisory root cause → named source object → fixing PR hunk → parent/fix replay. Until then keep as unattributed generic concurrency candidate, not CVE match. |
| CVE-2026-28733 | StorageDaemonStub iterator escape across map clearing | Source report evidence describes `storage_daemon_provider.cpp` access statistics under one mutex, not this Stub iterator path; common root cause is unproven. | Bind advisory source/fix and demonstrate the same iterator escape in exact before/after objects. |
| CVE-2026-28751 | MTP full-length xattr allocation/string termination shape | The source report explicitly does not map the advisory to this local root cause. | Locate authoritative root-cause/fix source and validate exact source pair; otherwise remove the CVE attribution while preserving any separately justified generic candidate. |

Before stating “all reported vulnerabilities are scannable,” publish an explicit profile coverage table: CVE/version applicability, detector enabled state, exact source inclusion, candidate rule outcome, fixed/safe control outcome, parse status, and product-reachability unknowns. `CVE-2026-92392` is not applicable to the reviewed curl 8.8.0 version; don't make it a current finding. CVE-2026-46675/33636 and other component-level patterns remain distinct from product-confirmed issues.

## Verification evidence in this A-line delivery

- `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v` — 9 tests passed on this worktree after the typed `Contacts::FileUtils::DeleteFile` model and unrelated receiver control were added.
- A same-source standalone detector run retains `blocked` status while emitting source-bound candidates; this is deliberate because other external wrappers remain unresolved.
- No shared catalog, default profile, runner, contract or API files were changed.

Status: owner review requested; no production registration or default-profile enablement has occurred.
