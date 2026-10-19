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

## D13 source Git object verification

D13 independently verified the D4 source manifest against the exact upstream Git commit/tree and file blob objects. The manifest has 22 files per revision (44 total), not 11; this corrected an earlier validation count assumption. Both commit SHAs, both tree SHAs, and every commit:path blob match SHA-1, SHA-256, and byte size. Verification ran with lazy fetch disabled after the explicitly authorized retrieval of only the manifest-pinned raw files into an isolated partial clone.

The later commit subject is "Remove unused sensitive prints", with the before commit as its parent. This is provenance/history evidence only: it is not a security advisory, product release/deployment proof, or exploitability proof. D13 does not change validated_vulnerability=0; D4 historical replay remains blocked and product H01-H08 remain not_run.

D13 implementation and reproducible commands are in D13_IMPLEMENTATION.md; machine-readable per-file evidence is in D13_SOURCE_GIT_OBJECT_VERIFICATION.json. The D13 unit tests cover both matching local commit objects and manifest-digest rejection. This does not meet M0-M3 or authorize panel registration, PR Ready, merge, or product confirmation.

## D13 delivery identity

- Branch: feat/teammate-d-sensitive-exposure-20261017.
- D13 code/evidence commit: 478d3d6fdc7febc66064f0b7e513b8f9e2993248; pushed to origin.
- Post-push check: remote branch and refs/pull/17/head both resolved to 478d3d6fdc7febc66064f0b7e513b8f9e2993248. The fetched PR merge ref parents were latest main 1c21ac60890fca0ce6be5d50d82e4757dd5e4623 and that PR head. The working tree was clean.
- D13 data tests: 55 passed. Full Python suite: 889 run, 884 passed, 5 skipped, 0 failed. compileall and git diff --check passed.
- PR #17 metadata and latest Actions status were not refreshed by this handoff update; the last observed PR state was open/Draft. No PR state was changed.

## D14 high-recall sink privacy handling and D5 replay

D14 changed detector version 0.9.0 / sink-model version 0.3.0 so sensitive data reaching a private or default-private log slot remains a conditional candidate with sink_privacy obligations. This is a review candidate, not a claim that private logging is exposed. D1 frozen fixture bytes remain unchanged; D5 additive controls now override the old private-as-safe expectation, and D9 has a private-slot positive candidate.

Exact Git-object D5 replay now runs on the ten files required by the historical model. Before commit: 1 candidate at trans_tcp_direct_message.c:671, 4/10 complete, 6/10 partial, blocked. After commit: 0 candidate, 4/10 complete, 6/10 partial, blocked. Both report detector implementation hashes. D11's separate 11-source manifest replay remains 1/0 at 5/6 parsing. The static delta is not product confirmation.

D14 validation: data tests 55/55; full Python 889 (884 passed, 5 skipped). See D14_IMPLEMENTATION.md, D14_VALIDATION.json, D14_D5_HISTORICAL_BEFORE.json, and D14_D5_HISTORICAL_AFTER.json. M0-M3 remain not met; public partial admission, panel, Catalog, product runtime/reader proof and independent holdout are open.


## D15 external source experiment

Added an exact-commit AccessTokenID/FullTokenID source profile, with LOGF/E/W/I/D sinks scoped to the pinned source file to avoid treating generic LOGI names as global sinks. The pinned `security_access_token` file produced 5 direct log candidates and 3 unresolved cross-component candidates; its parser outcome is partial and aggregate status blocked. The identifiers are authorization principals, not bearer secrets, and all outcomes retain unknown impact obligations. Two exact-snapshot reruns produced identical candidate identities and obligations; see `D15_REPEAT_STABILITY.json`. See `D15_ACCESS_TOKEN_REPLAY.md/.json`.

The D5 historical ten-file replay was repeated under the current detector implementation: before revision retains 1 candidate, after revision 0; both remain blocked with 4/10 complete and 6/10 partial. Exact `PackRequest`/`UnpackRequest` blobs were reverified against Git blob SHA-1, SHA-256, and size, confirming that `SESSION_KEY` carries `AppInfo.sessionKey` in the request. The extracted-function component Harness was also rerun successfully: the synthetic marker reaches only the old logger stub; ordinary reply and decrypt-failure controls behave as expected. Full current-run observations are in `D15_COMPONENT_HARNESS_RERUN.json`. The historical finding remains candidate/unknown; product build, unauthorized-reader impact, and product PoC remain unverified. See `D15_D5_CANDIDATE_ASSESSMENT.md` for evidence and bounded remediation.

Validation on 2026-10-18: D data tests 58/58; full Python suite 892 run, 887 passed, 5 skipped, 0 failed; compileall, report JSON parsing and `git diff --check` passed. The external AccessToken experiment is one file, not an independent holdout or full scan; no PoC, product fix test, confirmed vulnerability or impact is established. `validated_vulnerability=0`.

Delivery remains research-only and unregistered. The lane checker currently rejects `--lane D` because `config/collaboration/ownership.json` has no D lane; no scope policy or shared owner files were changed.

## D16 fixed-profile DSoftBus replay

The default 9-file session-key profile at commit `0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132` was executed twice through the offline reviewed-detector registry. Both runs were identical: one unresolved-escape candidate at `auth_hichain.c:136`, 3 files partial and 6 not analyzed; aggregate status `completed_with_limitations`. The candidate is a call to `AuthSessionSaveSessionKey`, not a demonstrated log sink. See `D16_DSOFTBUS_REPLAY/`; no vulnerability or complete scan is claimed.


D17 follow-up: exact commit-tree blobs now bind AuthSessionSaveSessionKey through AuthManagerSetSessionKey to AddSessionKey. The reviewed bounded path copies the key into the internal session-key list and does not pass key bytes to logging macros. The detector candidate remains visible; downstream readers and product/runtime behavior remain unknown. See D17_DSOFTBUS_CALLEE_BINDING.md.
