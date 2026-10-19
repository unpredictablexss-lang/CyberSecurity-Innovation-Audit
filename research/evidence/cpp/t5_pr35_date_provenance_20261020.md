# T5 — PR #35 per-run date provenance inventory

Audit date: 2026-10-20 (Asia/Shanghai)  
Inventory baseline: `91747d4cad7503e58c466402e905088153f1deb4`  
Disposition: **PARTIAL/BLOCK**

## Result

This pass inspected the originating worktrees and artifact write times for current queue packages. It found direct, per-file workstation evidence for 79 future-named artifacts from 16 task packages: T44, T45, D47–D49, D51–D53, T48, T53, and T55–T60. Each listed artifact was present in its originating worktree, had a local last-write timestamp on 2026-10-20, and matched byte-for-byte by SHA-256 with the artifact at the inventory baseline. The originating worktree HEAD is recorded per task. CLI outputs, reports, machine records and replay/verifier files are included only when the exact file passed those checks.

The 79 files are classified **date-proven with weak local-workstation corroboration**: their per-file OS write time is visible in the task's originating worktree, the exact file hash matches the inventory baseline, and the recorded worktree HEAD contains the artifact. This is directly reviewable but not strong or independent proof: filesystem timestamps can be changed and are not signed execution logs. Do not present them as equivalent to CI/operation logs. Git author/committer time, file contents, source-object identity, and mtimes from detached or later checkouts were not used alone as proof.

The 13 D54/T61/T62 paths already corrected and referenced by T3 are listed as an excluded confirmation set; this pass does not duplicate or rename them. Another 192 future-named paths have no qualifying per-run provenance located in this audit and remain **BLOCK**. They are listed unchanged in the machine inventory. Filenames and report date fields across both groups remain untouched; the inventory states what evidence exists and what is still missing.

The T55–T60 and D53/T59 evidence remains subject to its original PARTIAL/BLOCK technical conclusions. Resolving when an artifact was written does not upgrade vulnerability status, parse coverage, product applicability, or safety conclusions.

## Reproduction

From the T5 worktree, run:

```powershell
python research/evidence/cpp/verify_t5_pr35_date_provenance_20261020.py
python scripts/check_change_scope.py --base 91747d4cad7503e58c466402e905088153f1deb4 --lane cpp
git diff --check
```

The verifier checks the recorded originating worktree HEADs, exact source and integration file hashes, per-file write timestamps, the 79/192/13 partition, and exclusion of T3's confirmation set. For a spot review, inspect an originating worktree directly:

```powershell
Get-Item D:\openHarmonyScanner\worktrees\t55-wifi-fuzz-audit-20261029\research\evidence\cpp\t55_cr0337_cli_20261029.json |
  Select-Object FullName, LastWriteTime
git -C D:\openHarmonyScanner\worktrees\t55-wifi-fuzz-audit-20261029 rev-parse HEAD
```

Structured records and blocked paths are in [the JSON inventory](t5_pr35_date_provenance_20261020.json); [the verifier](verify_t5_pr35_date_provenance_20261020.py) performs the checks without changing evidence files.
