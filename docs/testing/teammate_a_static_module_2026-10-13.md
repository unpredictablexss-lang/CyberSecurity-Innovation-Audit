# Teammate A static module integration — 2026-10-13

## Scope

This change integrates the teammate A C/C++ detector branch with the latest
locally available historical static-benchmark work. It adds analysis-side
support for snapshot, revision-range and cross-version audits. Repository
sync, Web/jobs/storage, deployment and Agent orchestration remain Core-owned.

## Implemented

- `src/ohscanner/analysis.py` binds revision role, analysis mode, build/TU
  profile, include completeness and source/query hashes without changing
  `ToolRunResult v1`.
- Baseline/endpoint comparison emits `new`, `persistent`, `disappeared` or
  `unknown`; incomplete coverage always forces `unknown`.
- Multi-revision observation emits only `possibly_affected`, `not_present` or
  `unknown`. It does not assert product `affected/fixed` status.
- `src/ohscanner/patch_obligations.py` records guard/effect obligations from
  reviewed patches separately from historical labels.
- `src/ohscanner/readonly_facts.py` exposes source, syntax, detector and
  coverage facts that already exist in `ScanContext`; absent CFG/call graph,
  guard dominance and reachability return `unknown`.
- Root-cause matrix rows now preserve `match_basis`
  (`file_overlap`, `symbol_overlap`, `patch_region`, `guard_relation`,
  `path_evidence`) while keeping the original four result states.
- `src/benchmark/differential.py` classifies vulnerable/fixed/safe/unrelated
  observations as `vulnerable_only`, `both_revisions`, `control_hit` or
  `unknown`; these are not TP/FP/FN.
- `src/providers/infer.py` and `scripts/run_infer_experiments.py` provide the
  single new external research engine requested by the plan. The production
  Detector path has no Infer dependency.

## Research artifacts

- Patch obligations are included for the c_utils singleton and arkcompiler
  JSArray historical examples.
- Joern root-cause query specifications are saved under
  `scripts/joern_queries/root_cause_queries.json` with status
  `designed_not_executed`.
- CVE-2025-0587, CVE-2025-27536 and CVE-2025-21098 were not promoted into the
  benchmark because their exact merged commit/parent/blob/symbol bindings were
  not independently materialized. The negative record is
  `benchmarks/historical/research/candidate_exclusions_2026-10-13.json`.

## Verification

Command run in WSL2 Ubuntu 22.04, Python 3.10.12:

```text
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && python3 -m unittest discover -s tests -q"
```

Output:

```text
[OK] wrote /tmp/tmppf5fwvdx/fixture_evidence.json
[OK] shared_ptr_race fixture evidence matches
[OK] wrote /tmp/tmp1b0r_d8m/evidence.json and /tmp/tmp1b0r_d8m/evidence.md
[OK] wrote /tmp/tmp1b0r_d8m/evidence.json and /tmp/tmp1b0r_d8m/evidence.md
[OK] wrote /tmp/tmpr9u0ei26/evidence.json and /tmp/tmpr9u0ei26/evidence.md
[OK] shared_ptr_race native evidence outputs match
[OK] wrote draft binding manifest /tmp/tmpkcjjvd44/prepared-binding.json with SHA-256 1647e456f6465eb5a4ac6910fd823969065686d529f0912eacd09209128d6bc4
----------------------------------------------------------------------
Ran 391 tests in 51.713s

OK (skipped=2)
```

The two skips are the existing optional native-replay tests that require
ignored external manifests. Targeted static-module tests pass 12/12. The
Infer research script's `--help` path was smoke-tested; Infer itself is not
installed and no Infer result is claimed.

## Remaining limitations

- Production Catalog registration for `lifetime` and `shared_ptr_race` remains
  an owner review/merge decision.
- Clang SA and CodeQL still require real compilation/TU context before their
  historical misses can be interpreted as capability misses.
- Joern query specifications have not been executed.
- The three new CVE candidates are exclusions, not benchmark samples.
- No Agent, Web, task queue, deployment, new PoC, finding promotion or remote
  push/PR/merge is implemented by this change.
