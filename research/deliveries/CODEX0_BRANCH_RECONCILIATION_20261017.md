# Codex 0 branch and PR reconciliation, 2026-10-17

This report uses current local Git refs plus the taskbook's 2026-10-17 GitHub snapshot. GitHub PR live state was not re-queried after network sync; therefore PR statuses below are snapshot evidence, not fresh API proof.

## Main baseline

- Local `origin/main`: `de4d42a025404d87bdef59013c8999ff22a6d3a0`.
- Working branch and remote: `acec73267590eebda9a16f405141c9161f2d4cfa`.
- Main was merged into the working branch before A development; current work intentionally exceeds main.

## Ref reconciliation

| Ref | vs main | Focused differences | Disposition |
|---|---|---|---|
| `origin/feat/interface-ipc-detector` | 44 ahead / 41 behind | Adds interface `audit.py`, richer analysis/index/models and IPC tests; deletes legacy `m2_adapter.py` in that branch's projection | Pending selective review; do not merge whole branch |
| `origin/codex/teammate-a-static-module-20261013` | 35 ahead / 125 behind | A review modules, historical holdout plans, fixtures and evidence tests; also contains interface history | Mostly superseded by current A work; selectively compare review/evidence utilities |
| `origin/feat/unified-audit-v2` | 23 behind / 0 ahead | No focused detector delta beyond main | Duplicate/history; do not re-apply |
| `origin/feat/workbench-integration` | 34 behind / 0 ahead | No focused detector delta beyond main | Duplicate/history; do not re-apply |
| `work/ipc-20261017` | ref absent | Taskbook cites six-family IPC coverage and Parcel diagnostics | Missing from current remote ref inventory; evidence cannot be reproduced from this ref until restored or supplied |

## PR snapshot from taskbook

- #13 and #14: closed and reflected in main.
- #12, #9, #11, #10, #8: open/draft at taskbook snapshot. The taskbook recommends avoiding duplicate migration for #12/#9/#10 and selectively reconciling #11/#8 after code review.
- No claim is made that closed PRs prove tests passed.

## Module-level conclusion

1. Already merged/duplicated: unified workbench baseline, v2 protocol history, workbench integration history, portions of A and B research.
2. Pending selective migration: `feat/interface-ipc-detector` interface `audit.py`, source-derived entry index improvements, macro normalization, consequence/impact reports and corresponding tests.
3. Missing authoritative ref: `work/ipc-20261017`; its six-family census/Parcel diagnostics cannot be treated as current executable evidence.
4. Forbidden action: no whole-branch reset/merge. Any migration must be file-by-file with source identity and tests.
