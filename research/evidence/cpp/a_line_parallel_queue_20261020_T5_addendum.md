# T5 task-tree addendum — PR #35 per-run date provenance

Role: independent evidence provenance reviewer.  
Target: PR #35 evidence paths whose filenames carry 2026-10-21 through 2026-10-30, excluding the 13 D54/T61/T62 paths already reconciled by T3.  
Baseline: `91747d4cad7503e58c466402e905088153f1deb4`.

T5 inspected original worktree artifacts for the queue packages T44, T45, D47–D49, D51–D53, T48, T53, and T55–T60. The inventory records **79 date-proven files** across 16 task packages: exact source worktree, worktree HEAD, per-file local write time, and SHA-256 matching the baseline artifact. No filename, report date field, detector, A0 row, or prior finding status was changed.

The other **192 future-named paths remain BLOCK** because this pass did not locate direct originating-worktree run evidence for them. Git commit timestamps, source identities, detached checkout timestamps, and the artifact text alone are not treated as run-date evidence. The D54/T61/T62 13-item confirmation set remains a separate T3 reference and is excluded to avoid double counting or another rename.

This closes no technical PARTIAL/BLOCK state: T55–T60 and D53/T59 retain their existing coverage, parser, product-context, and control limitations. The machine inventory, methodology and verifier are [T5 provenance report](t5_pr35_date_provenance_20261020.md), [JSON](t5_pr35_date_provenance_20261020.json), and [verifier](verify_t5_pr35_date_provenance_20261020.py). Reproduce with `python research/evidence/cpp/verify_t5_pr35_date_provenance_20261020.py` and `python scripts/check_change_scope.py --base 91747d4cad7503e58c466402e905088153f1deb4 --lane cpp`.
