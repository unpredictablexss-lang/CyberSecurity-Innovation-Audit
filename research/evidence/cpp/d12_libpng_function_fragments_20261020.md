# D12 libpng function-fragment replay

Date: 2026-10-20 (Asia/Shanghai)
Baseline: `983afb846ceaa34daf690c39e4918703c4ac99a7`
Detector: `ohscanner.cpp.resource_lifetime` `0.4.0`
Disposition: both CVE cases remain `PARTIAL/BLOCK`; no detector code or rules changed.

## Method

The replay script verifies every supplied full source file against the SHA-256 values recorded in prior A-line evidence, extracts selected functions by parser-reported source line range, preserves original line positions by blanking omitted lines, parses each isolated fragment, and runs the existing detector. It records both original translation-unit parse state and fragment parse state. A clean fragment syntax parse does not promote the original file to complete and does not establish type, control-flow, ownership, or call-order semantics.

Sources are local byte-identical material previously bound to these identities: 33416 vulnerable commit/tree `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` / `e01f5780f93eaa6d74cca003bb39b427c8f1e910`; fixed `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` / `a28bb962645843af84063c77f574f6d88da79f76`. For 46675 the exact GitHub file blob IDs and SHA-256 values are recorded in the JSON; full upstream trees remain unavailable.

## Replay

| Case / variant | Functions | TU parse | Fragment parse | Findings | Detector time |
|---|---:|---|---|---:|---:|
| 33416 vulnerable | 4 | partial | 4 partial | 0 | 0.487s |
| 33416 fixed | 4 | partial | 4 partial | 0 | 0.494s |
| 46675 vulnerable | 7 | partial | 6 complete, 1 partial | 0 | 1.469s |
| 46675 fixed | 7 | partial | 6 complete, 1 partial | 0 | 3.592s |

### CVE-2026-33416

The vulnerable and fixed variants were hash-checked across `pngset.c`, `png.c`, `pngread.c`, and `pngrtran.c`. Isolated fragments: `png_set_PLTE`, `png_set_tRNS`, `png_free_data`, and `png_do_expand_palette`. All whole translation units and all eight fragments parse `partial`; no finding was emitted. The root cause remains a cross-file alias/release/use sequence involving fields owned by `png_info` and `png_struct`. This experiment does not establish whether the function fragments are semantically isolated from parse recovery, so no candidate or safe/fixed inference is made.

### CVE-2026-46675

Vulnerable/fixed `pngrutil.c` bytes match the previously verified Git blobs and SHA-256 values. Isolated fragments: `png_inflate_claim`, `png_inflate`, `png_decompress_chunk`, `png_inflate_read`, `png_handle_iCCP`, `png_handle_zTXt`, and `png_read_IDAT_data`. Both parent translation units remain `partial`. Six of seven function fragments parse complete for each variant; `png_handle_iCCP` remains partial. The complete function fragments produced zero findings on both vulnerable and fixed bytes. This shows the current resource-lifetime model does not express the zstream input-buffer state transition and later IDAT consumption, but does not demonstrate a detector-level root cause candidate. The zero result is inconclusive.

## Controls and decision

No new rule was added because the required exact-source vulnerable candidate was not demonstrated. Therefore no new libpng-specific fixed/safe/unrelated controls were fabricated. The existing detector control suite was rerun separately and includes positive, fixed, safe, unrelated, and partial fixtures; `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v` passed 8/8, and the complete C++ detector suite `python -m unittest discover -s tests/detectors -p "test_cpp_*.py" -v` passed 159/159. These synthetic controls validate existing rules only and do not close either libpng case.

Minimum unblock inputs:

- CVE-2026-33416: parser-visible declarations and field/type identity for the involved structures; a candidate contract that isolates each function from unrelated conditional-compilation parse errors; and source-bound safe/unrelated state controls.
- CVE-2026-46675: a complete or reviewed local-fragment contract for `png_handle_iCCP`, plus call/order-aware evidence connecting chunk decompression cleanup to `png_read_IDAT_data`; include the malformed chunk trigger and fixed/read-rows/safe controls.
- Product conclusions for both cases still require the selected product build and application call path.

## Reproduction

```powershell
python research/evidence/cpp/d12_libpng_function_fragments_20261020.py `
  --33416-vulnerable <local-v1.6.55-root> `
  --33416-fixed <local-v1.6.56-root> `
  --46675-vulnerable <local-v1.6.55-root> `
  --46675-fixed <local-official-fixed-root> `
  --output research/evidence/cpp/d12_libpng_function_fragments_20261020.json
```

The script rejects source bytes whose SHA-256 differs from the recorded values. It stores exact source file and fragment hashes, source function line ranges, parser issues, detector/rule version, finding positions, and elapsed time in the JSON artifact.
