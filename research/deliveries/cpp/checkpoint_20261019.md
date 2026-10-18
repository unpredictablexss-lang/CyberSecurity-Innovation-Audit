# A-line checkpoint — 2026-10-19

## Current baseline and workspace

- Scanner: `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit`, branch `codex/a-line-scanner-regression-20261018`, HEAD `f8e3a0ad7463f216db4be7502bd8a19eec545908`, upstream `origin/main`, ahead 6.
- Worktree contains pre-existing unrelated edits. No reset, clean, stash, broad checkout, push, merge, or external message was performed.
- Production entry: `python -m src.cli ohscan-run`; Python 3.13.9, tree-sitter 0.26.0.
- A-line ownership is limited to `src/ohscanner/detectors/cpp/**`, `tests/detectors/test_cpp_*.py`, `tests/detectors/fixtures/cpp_*/**`, `research/evidence/cpp/**`, `research/methods/cpp/**`, and `research/deliveries/cpp/**`.

## Root family selected

libtiff CVE-2025-9900: unsigned output-height subtraction flows into scaled output pointer arithmetic. Upstream patch removes the underflow-prone row offset and delegates crop placement to the dimension-clamping reader. The rule only identifies a source-level candidate; caller buffer capacity, input control, reachability, build profile, and product impact remain unknown.

## Completed

- Verified upstream vulnerable release v4.7.0 source identity, exact patch commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, parent, tree, file blobs, and ancestry; verified local OpenHarmony libtiff pin `d4a0516c477dfbaf1153ae295893ab75aadd63d4` and source hash.
- Baseline M2 production CLI on the same two-file source scope: no diagnostics, but parser partial/blocked on both files. This is not an unaffected result.
- Added generic pointer-offset unsigned-underflow candidate rule in the existing integer-bounds detector, version 0.2.4; no CVE/path/hash/function-name matching.
- Unit controls: vulnerable dimension pattern and renamed-member variant detect; guarded/signed/unrelated examples are quiet; incomplete parse stays blocked. Targeted tests: 4/4 pass.
- Production M2 replay: upstream vulnerable release 1 candidate; exact fixed commit 0 same-rule candidates; local OpenHarmony source 1 candidate at line 621. Each full-source replay carries parser partial limitations.
- Post-freeze synthetic holdout variant detects without CVE metadata; this is not an independent real-world labeled sample.
- Broad A-line detector suite: 143 tests, 136 pass, 4 fail, 3 errors. All seven failures are in pre-existing unrelated fixture/hash or shared_ptr input mismatches; captured log is in the evidence directory. No unrelated fixture was changed.
- Candidate inventory recorded for libpng lifecycle advisories, curl MIME cleanup, and two cJSON cases. libpng `CVE-2026-33416.patch` dry-run fails at the `pngset.c` core independent-palette hunk and ends truncated; build script catches patch failure, so effective product patch state is unknown.

## Evidence and delivery

- Machine-readable inventory: `coverage_ledger_20261019.json`.
- Replay reports, detector suite log, hashes, and root-cause/replay card: `research/evidence/cpp/libtiff_cve_2025_9900_20261018/`.
- Rule source: `src/ohscanner/detectors/cpp/integer_bounds_detector.py`.
- New focused tests: `tests/detectors/test_cpp_pointer_offset_underflow.py`.

## Failed / not executed

- Whole-source proof is incomplete because the scanner reports partial parsing; keep the M2 results as candidate/partial.
- Parser diagnostic extraction is complete: `tif_getimage.c` errors are at lines 1383, 1393, 1687, 1707, 1831, and 1833, in macro-expanded `UNROLL` bodies (`UNROLL8`); `tiffio.h` reports missing nodes around lines 483–498 and 650 inside declarations/attributes. These are preprocessor/configuration-sensitive constructs, not syntax in the candidate arithmetic at line 621. Repeating the unchanged parse is not useful; public parser support for controlled macro preprocessing or a compile-command-aware parse profile is needed to upgrade coverage.
- No libtiff build or dynamic reproduction was run; available Windows toolchain lacked the required native build utilities and WSL lacked CMake/autoconf for this source setup.
- No product build/profile, entry reachability, attacker-control, or impact validation; product vulnerability remains unknown.
- No full A-line regression green result because of the seven unrelated pre-existing failures/errors noted above.
- No scanner core API/runner/catalog changes were made.

## Exact next operation

Prepare the narrow parser integration request in `A_LINE_PARSER_PREREQUISITE_REQUEST_20261019.md`; it should ask the shared frontend owner for explicit compile-definition/preprocessing inputs (or an equivalent configured parse profile), record macro identities and source binding, and preserve partial/blocked when configuration is absent. Then test the request against this pinned libtiff pair. Completion condition: the same fixed two-file scope parses fully and the production CLI reproduces one vulnerable candidate and zero same-rule fixed candidates, with controls still passing.

If parser progress stalls twice, record the exact failing diagnostics and switch to proving the libpng patch-application state; do not repeat the same failed parse/build command.
