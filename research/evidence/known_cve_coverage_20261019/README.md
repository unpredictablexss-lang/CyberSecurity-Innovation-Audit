# C10-LATEST-KNOWN-CVE-MIGRATION evidence

- target checkout: `E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019`
- target baseline: `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457` / tree `d15b91627c94d9c3043d7d58d47fcf9af7e42454`
- pinned source checkout: `E:\网安\CyberSecurity-Innovation-Audit-main-latest-20261019`
- pinned source head: `db77164fdc2af0da02e4d3efc056d84694fd68e8`
- Detector: `ohscanner.known_disclosed_cves@0.16.0`, unchanged blob `a2ddd5ff2afc2f6fb0f1677ea3ffbbfc580a195b`
- migration result: known_cves 21/21 pass; `compileall` exit 0; `git diff --check` exit 0.
- preserved Ark repair dirty state: 1 tracked modified file and 5 untracked modules; hashes in `preserved_ark_dirty_state.json`.
- no commit, push, merge, reset, fetch, or checkout.

## Evidence map

- `minimal.patch` / `migration.diff`: minimal target migration diff for `tests/detectors/test_known_disclosed_cves.py`.
- `source_identity.json`: worktree SHA-256, normalized-LF SHA-256, baseline blob and pinned Git blob identities.
- `run_manifest.json` plus `migration_*_run.json`: exact argv, cwd, environment boundary, exit code and byte counts.
- `migration_*_stdout.txt` / `migration_*_stderr.txt`: exact process output; two path-related compileall failures are retained.
- `control_matrix.json` / `dispositions.md`: upstream 17 CVE control matrix and human-readable dispositions.
- `cve_disposition_summary.md`: migration-facing 17 CVE summary.
- `limitations.md` / `next_minimal_slice.md`: residual evidence-gate limits and next bounded slice.
- `preserved_ark_dirty_state.json`: hashes proving the existing Ark repair worktree state remained present.
