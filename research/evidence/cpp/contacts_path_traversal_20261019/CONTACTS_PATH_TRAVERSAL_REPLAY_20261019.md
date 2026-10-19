# Contacts path traversal detector replay (D1)

Date: 2026-10-19. Base: PR #30 head `8ec5f56a12e90bba56953b39eb17faa20e154da9`.

## Exact target identity and status

The read-only T1 product evidence record binds the Contacts case to repository `applications/standard/contacts_data`, commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`, tree `2054824c04bb403eeea128a9262edfb3001efa4f`, path `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, and Git-object SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. This is the vulnerability source identity asserted by the source review; this run did not independently retrieve those exact Git bytes.

The available Windows OpenHarmony working copy was 85,339 bytes with checkout SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`, which differs from the pinned Git-object hash. Per the T1 note, line-ending conversion can explain this difference; the D1 replay therefore uses the working-copy bytes only and remains source-identity `PARTIAL/BLOCK`, not an exact A0 replay.

## Detector result

- Detector/rule: `ohscanner.cpp.path_traversal` / `ohcpp-path-traversal-source-to-file-sink-candidate-001` / `0.1.0`.
- Scope: one translation unit, `contacts_data_ability.cpp`; parse status supplied as `partial` because no exact parser coverage result was established for this working copy.
- Result: `blocked`, file outcome `partial`; 3 root-chain candidates at lines 792, 793 and 797 in `HandleContactPortrait`.
- Lines 792 and 797 are `fileUtils.DeleteFile(srcFilePath)` on the Save failure and success paths. Line 793 is `DeleteFile(filePath)`, where the two other bucket string fields also flow into an output path; their validation semantics are unknown, so this is retained as a candidate requiring review. The helper's `open(srcFilePath.c_str(), O_RDONLY, ...)` is not separately emitted because the source function's helper parameter mapping is outside the current bounded path summary; this is a known analysis limitation.
- Main cause: `srcFilePath = groupPath + portraitFileName`, with `portraitFileName` copied from a string field in the DataShare value; no canonical containment check appears in the reviewed `HandleContactPortrait` body. The actual source snippet and exact source provenance remain in the original A0/T1 evidence, not copied into this repository.
- Command: `python research/evidence/cpp/contacts_path_traversal_20261019/direct_replay.py 'D:\openHarmonyScanner\openharmony\applications\standard\contacts_data\dataBusiness\contacts\src\contacts_data_ability.cpp' --parse-status partial`, using `CppPathTraversalDetector.detect` on a single `SourceUnit`. It reports checkout SHA `c9d1f03d...`, 85,339 bytes, and 0.176994 seconds on this run. The production `ohscan-run` CLI cannot select this detector because Catalog is owner-controlled and unchanged in this branch.
- Focused tests: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v` — 6 passed, 0 failed, approximately 0.01 s.
- Direct replay runtime: less than 0.01 s in the local Python invocation (not a performance benchmark).

## Controls and disposition

Synthetic fixed-shaped basename control, explicit `starts_with` containment control, unrelated API/no-sink controls all produce no finding. A deliberately partial input preserves the candidate and reports `blocked`/`partial`; zero findings never imply safety. There is no independently verified upstream fixed Contacts source, so a real fixed comparison is `BLOCK`. The synthetic controls are mechanism tests only. No precision/recall or product-security claim is made.

Catalog registration requires owner acceptance of `research/deliveries/cpp/CONTACTS_PATH_TRAVERSAL_CATALOG_REQUEST_20261019.md` and a later production CLI integration replay.
