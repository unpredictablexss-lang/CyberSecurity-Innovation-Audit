# C9 exception-guard acceptance slice

Status: local scanner-semantics regression complete; product/security assessment
remains `candidate/unassessed`.

## Final outputs

- Focused synthetic: 23/23 executed tests passed, 0 skipped.
- Full focused module: 23 executed tests passed, 1 historical test skipped and
  not counted as a pass.
- Ark Runtime suite: 113 executed tests passed, 8 tests skipped and not counted
  as passes; 0 failures/errors among executed tests.
- `compileall` and `git diff --check` passed.
- The docs-budget script is absent from this worktree; its recorded invocation is
  an error and is not counted as a pass.

## Semantic result

`guard-before-effect`, `guard-after-effect`, `missing guard`, and
`unknown effect` are separated. Guard-after-effect and a pending branch that
continues to copy/store remain candidates. Same-instruction copy/store order is
unknown. Zero-length return paths remain unknown while valid later nonzero
candidate/matched observations are preserved. No unknown is converted to safe.

See `control_matrix_20261019.json`, `minimal.patch`,
`limitations-and-next-slice.md`, `run_manifest.json`, and `logs/`.


## Latest baseline update (2026-10-19)

The C9 line was additionally compared read-only against latest static baseline `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` and parent `origin/main` `db77164fdc2af0da02e4d3efc056d84694fd68e8`. The current dirty worktree remains based on old C-line `7af25f5ced471e5d6acc8cf5efd4c696275ce940`; no reset, checkout, fetch, commit, push or merge was performed.

- Runtime-exception focused tests: 40 executed, 40 passed, 0 skipped.
- Combined focused tests: 64 executed, 63 passed, 1 historical skip.
- Ark Runtime suite: 161 executed, 153 passed, 8 historical skips.
- `compileall` and `git diff --check` passed.
- Authoritative patches: `old_baseline_7af25f5_minimal.patch` and `latest_static_09ba5aba_minimal.patch`.
- Comparison and conflict details: `latest_baseline_comparison.md`, `latest_baseline_run_manifest.json`, `control_matrix_runtime_exception_20261019.json`, `latest_static_09ba5aba_conflicts.json`.
- `origin/main` `src/ohscanner/detectors/known_cves.py` version 0.16.0 was verified and not duplicated.

The results remain local semantic controls at `candidate/unassessed`. The 09ba static baseline has runtime-exception tests and a rule ID but lacks the imported `runtime_exception.py` implementation; production CLI integration for I7E0FM remains a next slice and is not claimed here.
