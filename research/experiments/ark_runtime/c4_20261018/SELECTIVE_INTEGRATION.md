# C4 selective integration notes

This directory preserves the C4 research delivery from `origin/work/c4-ark-runtime-20261018`. The C1, C2, C3 (2026-10-17), and C4 records are included as historical research artifacts. The existing C3 (2026-10-18) and C6 parser records on the receiving branch remain intact.

The receiving branch already contains the C4 applicability selector in `src/ohscanner/runner.py`, the default-off catalog entry, and the explicit experimental-rule selection in the audit UI. These shared integration points were already present and were not recopied from C4.

The receiving detector implementation remains the C-line version. It uses model/detector version `0.6.2`, binds the `a65a2853ccae13da167d9aa4720ab8b11ec16656` source snapshot for both rule families, and can run both rule families for a source when both bindings match. Its `syntax.py` also retains partial-parse namespace owner recovery, with regression coverage in `tests/detectors/ark_runtime/test_parser_owner.py`.

C4's `C4_VALIDATION.json` and related reports describe the separate C4 branch at model version `0.6.1`. That model omits the `a65a2853...` bindings, and its detector chooses one rule family per source. The C4 report's replay and test counts therefore remain claims about that recorded C4 state; they do not verify the receiving `0.6.2` implementation. C4's `detector.py`, `model.py`, and `syntax.py` changes were intentionally not copied because they would remove the receiving branch's dual-rule handling, source binding, or owner recovery.

No C4 source-level behavior was changed by importing these records. The receiving worktree was verified with:

- Focused C-line suite (`tests/test_runner_applicability.py`, `tests/test_owner_integration.py`, and `tests/detectors/ark_runtime`): 114 passed, 5 skipped, 41 subtests passed. The five skips are the C1/C2 and exception-path history cases whose pinned commits are absent from the supplied Ark Git store.
- Full Python suite: 925 passed, 17 skipped, 0 failed, 770 subtests passed in 339.20 seconds. Other skips cover unavailable preserved artifacts/corpora and the Docker-only runtime harness.
- Frontend: `npm test` passed 17/17; `npm run build` passed, including `tsc --noEmit`.

The current `a65a2853...` source commit is present locally. Attempts to fetch the missing historical commits into a separate temporary mirror failed: GitCode returned an invalid protocol response and the GitHub Git endpoint could not connect on port 443. The original Ark checkout was not changed. Those history-dependent skips remain unverified and are not counted as passes. These results verify the receiving branch's current test behavior; they do not retroactively verify the C4 `0.6.1` report or establish a product vulnerability.
