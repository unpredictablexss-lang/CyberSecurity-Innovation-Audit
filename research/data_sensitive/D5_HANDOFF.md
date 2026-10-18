# D5 handoff

Base: latest `origin/main` observed at `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`.
Worktree: `/home/audit/ohscanner/worktrees/teammate-d-20261018`, branch
`work/teammate-d-20261018`. Imported D-only paths from Draft PR #17 head
`1d0c53bc992784c88e31132f6aa75973ff38f19f`; this worktree has not pushed,
merged, or changed the PR state. PR #17 was last verified open and Draft against
an older base `e510c99c67f31ec6c73365f9ab749c79ca6ff0a`.

D5 implementation changes the local analysis to keep loop-body and post-loop
may-flows, plus same-name local copy/format writes, as candidates with evidence
obligations. A same-file sink implementation that is
uniquely visible and empty is not treated as the external modeled sink. This
preserves the frozen D1/D2/D3 historical controls; changed loop expectations
are in `tests/fixtures/data_sensitive/d5_cases.json`. The D2 synthetic loop and
new copy-name control remain candidate-only regressions, not product findings.

The offline fixed-source replay entry point, H01–H08 design/matrix, and
D-to-Agent/panel consumer RFC are now present. Historical D4 Git objects could not be restored into a local cache in
this run, so dual-version replay is blocked. No dynamic Harness ran, no
independent holdout exists, and no independent product patch was built.

Latest validation is recorded in `D5_VALIDATION.json`. The isolated D suite
passed 35/35, the full Python suite passed 869 tests with 5 documented skips
and no failures, and the frontend Node tests passed 16/16. The prebuilt `web/`
artifact came from another worktree whose `web/` source is byte-identical to
this base; only ignored build output was copied. M0 remains unmet because the
fixed-source dual replay is blocked and latest-main CI plus dependency/license
review are still outstanding. M1/M2/M3 remain not met, and D remains
disabled/research-only.
