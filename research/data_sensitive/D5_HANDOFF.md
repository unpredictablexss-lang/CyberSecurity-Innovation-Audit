# D5 handoff update: D12 type-identity candidate retention

## Branch and source identity

- Worktree: `/home/audit/ohscanner/worktrees/teammate-d-20261018-pushed`
- Branch: `feat/teammate-d-sensitive-exposure-20261017`
- Latest main used as base: `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`; `git merge-base` confirms this is the D branch base.
- D12 detector/test/evidence commit: `7f37af2e57d822c0bbaf6d6aa82517081af1fcf7`.
- PR #17: prior metadata showed open/Draft; no PR state was changed. Immediately before this D12 commit, `refs/pull/17/merge` had parents latest main `1c21ac6` and prior PR head `e2d295b`. The remote PR ref must be rechecked after pushing D12. GitHub Actions status for the new local commit is not available until it is pushed and the run completes.
- The public `docs/项目现状与下一步.md` was restored to the latest main version; D-specific evidence remains under `research/data_sensitive/`.

## D12 result

Detector version 0.8.0 / source-model version 0.2.0 preserves a candidate for the configured sensitive field when a same-name local type declaration makes compiler identity unresolved, with a `type_identity` obligation. The explicit `SessionKey.len` metadata control stays non-sensitive. Existing D10 real-source replay remains one unresolved cross-file candidate and 3 complete / 6 partial files; historical D4 replay remains 1 old / 0 post-hardening candidates, both blocked.

The change keeps evidence at candidate level. It does not establish a product leak, affected release, authorized/unauthorized log reader, or a deployed fix. `validated_vulnerability=0`; product H01–H08 remain `not_run`.

## Verification

Exact commands and results are in `D12_VALIDATION.json`. The D data suite passed 53/53; the full Python suite passed 887 tests (882 passed, 5 skipped, 0 failed); Web tests passed 16/16; TypeScript and production build exited 0 with the project Linux Node 22 runtime. `npm ci` followed the lockfile and reported 0 vulnerabilities. `compileall`, script `py_compile`, and `git diff --check` passed. Both manifest-bound source replays passed their integrity checks and remain blocked because 6/11 files are partial per historical version and 6/9 selected D10 code files are partial.

## Gates

- M0: not met. Latest PR-head CI is unverified, full Git-object/public Runner replay is outstanding, and the dependency/license review is incomplete. Keep D unregistered and disabled.
- M1: not met. Shared partial-AST admission and report/UI integration require the platform owner.
- M2: not met. One reviewed component/source family, no independent labeled holdout, no comparative performance/RSS or end-to-end Worker measurement.
- M3: not met. No product build/output/reader evidence or validated product patch. Candidate only.

Do not mark PR #17 Ready or merge it without the separately required authorization and gates.
