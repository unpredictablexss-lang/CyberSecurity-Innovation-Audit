# D36 libtiff CVE-2025-9900 full-TU parser blocker

Date: 2026-10-20 (Asia/Shanghai). Scanner baseline: `73d5c356b1b1dbc081727948d89d6502c862f3af`.

## Outcome

No detector change is justified. On the exact vulnerable and fixed commits, the current lightweight frontend reports both selected files as `partial`; `ohscanner.cpp.bounds@0.3.0` consequently remains blocked with zero whole-scope findings. The exact local `TIFFReadRGBAImageOriented` probe still parses completely and gives a 1/0 candidate differential at vulnerable `tif_getimage.c:621`, so the bounds rule is not the blocker. The CVE row remains **PARTIAL/BLOCK**, and the 1/0 function slice is not a full-source pass.

## Concrete parser findings

`tif_getimage.c` has six tree-sitter C error/missing nodes on each source side. They cluster at two macro-driven loop tails and two corresponding closing braces:

| Side | Lines | Parser node | Source context |
|---|---:|---|---|
| vulnerable | 1383, 1393 | error | braces closing functions that contain `UNROLL4`/`CASE4` macro-controlled code |
| vulnerable | 1687, 1707, 1831, 1833 | error/missing | `UNROLL8(w, ..., expression; pp += samplesperpixel)` invocations |
| fixed | 1411, 1421 | error | corresponding macro-controlled closing braces |
| fixed | 1715, 1735, 1859, 1861 | error/missing | corresponding `UNROLL8` invocations |

The standalone grammar sees macro arguments as ordinary C syntax. In particular, the `UNROLL8` third argument intentionally spans lines and contains semicolon-separated statements; only preprocessing expands it into a valid block. The frontend currently does not consume compile commands, macro definitions, or preprocessed translation units.

`tiffio.h` is classified as C++ by the repository's generic `.h` suffix mapping. The C++ grammar reports seven missing nodes: six around variadic C declarations followed by compiler-format attributes (vulnerable lines 483–498; fixed lines 498–513), and one at the final conditional `}` (vulnerable line 650; fixed line 668). Parsing this header as C is not a safe local workaround: tree-sitter C reports 22 issues on each side, including errors in the same variadic declarations. The final conditional brace is also affected by parsing mutually exclusive preprocessor branches without evaluating them.

These are parser/driver limitations, not bounds detector findings. Relabeling a selected function as complete or allowing the detector to treat a partial whole-file parse as complete would erase the existing uncertainty contract. A sound full-TU improvement needs a bounded preprocessor/compile-context input (or a verified preprocessed source map) and tests for both active and inactive conditional branches; that is a parser/frontend capability change outside this detector-local slice. A bounded local function remains available and already catches the issue, but it cannot represent full-TU coverage.

## Source identity and reproduction

The exact commit/tree/blob/SHA identities are recorded in `t6_remaining_matrix_replay_20261020/source-identities.json`. Vulnerable source: commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, tree `986499c84247e9a1f49560128bbe7580d8ebea1a`, `tif_getimage.c` blob `6c7b5031a1937bb48cc79808a59618d8a4f6237e`, SHA-256 `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`. Fixed source: commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, tree `77361ef7262189e16a2010b5c333f6b275d17f09`, blob `2774caa0eef24bce2a619d2686a23d59fb5ef9db`, SHA-256 `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`.

Using a local clone containing both commits:

```powershell
python research/evidence/cpp/d36_libtiff_parser_blocker_20261020.py `
  --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream `
  --output research/evidence/cpp/d36_libtiff_parser_blocker_20261020.json
python research/evidence/cpp/verify_t6_remaining_matrix_replay_20261020.py `
  --scanner-repo .
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py `
  --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream `
  --output-dir D:/openHarmonyScanner/tmp/d36-libtiff-probe-20261020
```

The JSON from the first command captures all parser issue lines, exact source object hashes, parser grammar comparison, and function inventory on both versions. The D21 replay independently verifies the local vulnerable/fixed function result and source bindings. The T6 verifier confirms the fresh whole-scope CLI projections remain 0/0, partial, and blocked.

## Smallest useful missing input

To make the full translation unit actionable without guessing macros, provide or generate from the exact source revision a compile command containing include paths, defines, language mode, and target headers, or a preprocessed `.i` plus a source map back to the pinned original blob. Until then, the blocker is reproducible and bounded; findings/absence outside the complete local function slice remain unknown.
