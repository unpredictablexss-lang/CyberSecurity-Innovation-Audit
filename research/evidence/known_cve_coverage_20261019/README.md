# C10-KNOWN-CVE-REGRESSION evidence

- checkout: `E:\网安\CyberSecurity-Innovation-Audit-main-latest-20261019`
- origin/main HEAD: `db77164fdc2af0da02e4d3efc056d84694fd68e8`
- Detector: `ohscanner.known_disclosed_cves@0.16.0`
- review blob: `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`
- result: 21 tests passed, 0 failed, 0 skipped; `compileall` exit 0; `git diff --check` exit 0.
- tracked changes: ['tests/detectors/test_known_disclosed_cves.py']
- new untracked evidence: ['research/evidence/known_cve_coverage_20261019/baseline_test_stderr.txt', 'research/evidence/known_cve_coverage_20261019/baseline_test_stdout.txt', 'research/evidence/known_cve_coverage_20261019/compileall_stderr.txt', 'research/evidence/known_cve_coverage_20261019/compileall_stdout.txt', 'research/evidence/known_cve_coverage_20261019/control_matrix.json', 'research/evidence/known_cve_coverage_20261019/dispositions.md', 'research/evidence/known_cve_coverage_20261019/git_diff_check_stderr.txt', 'research/evidence/known_cve_coverage_20261019/git_diff_check_stdout.txt', 'research/evidence/known_cve_coverage_20261019/hashes.json', 'research/evidence/known_cve_coverage_20261019/known_cves_test_stderr.txt', 'research/evidence/known_cve_coverage_20261019/known_cves_test_stdout.txt', 'research/evidence/known_cve_coverage_20261019/limitations.md', 'research/evidence/known_cve_coverage_20261019/minimal.patch', 'research/evidence/known_cve_coverage_20261019/next_minimal_slice.md', 'research/evidence/known_cve_coverage_20261019/run_manifest.json', 'research/evidence/known_cve_coverage_20261019/source_identity.json']

## Evidence map

- `run_manifest.json`: exact argv, cwd, exit codes, stdout/stderr filenames and environment boundary.
- `source_identity.json`: worktree SHA-256, normalized-LF SHA-256, pinned Git blob SHA-1 and pinned blob SHA-256.
- `control_matrix.json`: 17 CVE vulnerable/fixed/safe/unrelated/unknown or explicit not-applicable controls.
- `dispositions.md`: human-readable 17 CVE disposition table.
- `minimal.patch`: minimal tracked diff.
- `hashes.json`: SHA-256 for source/evidence artifacts.
- `limitations.md`: evidence-gate limitations.
- `next_minimal_slice.md`: next bounded implementation slice.

No commit, push, merge, reset, fetch, or checkout was performed.
