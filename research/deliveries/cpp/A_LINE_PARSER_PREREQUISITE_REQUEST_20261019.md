# A-line parser prerequisite request — 2026-10-19

**Status: proposed for shared-interface review; not integrated.** No public runner, parser, contract, or catalog file was changed in this A-line delivery.

## Observed source-bound evidence

On pinned OSGeo/libtiff vulnerable commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, the production `ohscan-run` report marks both selected files partial under `light-ast`:

- `libtiff/tif_getimage.c`: parser errors at lines 1383, 1393, 1687, 1707, 1833 and a missing node at 1831. The latter group is inside `UNROLL8` macro invocations; earlier issues are in macro definitions/expansion-sensitive code. The target expression at line 621 itself is extractable and yields a candidate.
- `libtiff/tiffio.h`: missing nodes at lines 483, 485, 487, 489, 496, 498 and 650, in compiler-attribute-bearing declarations and surrounding configuration-sensitive header syntax.
- Fixed commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` exhibits the same parser limitation; therefore the paired zero-candidate result is not a complete safe verdict.

Exact diagnostics and source hashes are retained in `research/evidence/cpp/libtiff_cve_2025_9900_20261018/vulnerable-v4.7.0.json` and `fixed-commit-3e0dcf0.json`.

## Minimum shared capability requested

Existing call path is `src/ohscanner/runner.py` → `src/ohscanner/frontend.py:index_sources` → `src/parser/ast.py:parse_source`; direct `parse_source` consumers include `src/core/ast_scanner.py`, benchmark source mapping/history, and parser tests. The proposed change must stay backward compatible for those current callers.

Smallest candidate diff for shared-owner review (not applied):

```diff
-def parse_source(code: str, language: str = "c") -> AstIndex:
+def parse_source(code: str, language: str = "c", *, parse_profile: Optional[ParseProfile] = None) -> AstIndex:
```

`ParseProfile` would be an immutable shared type containing explicit compiler identity/version, language mode, defines, include roots, and source-mapped preprocessed bytes or an already-produced preprocessing artifact plus its digest. The canonical production request would carry a profile id and digest into `index_sources` and source provenance. Default `None` keeps existing direct callers unchanged. A CLI-level option should only select a predeclared/local profile; it must not execute arbitrary repository build scripts or fetch dependencies. The shared owner should choose the final contract shape before implementation.

1. Allow a caller to supply a pinned compilation profile or explicit preprocessing definitions/include configuration for a source unit, rather than silently guessing project defaults.
2. Bind that profile and all preprocessing inputs to the run/source provenance; never fetch or execute project build scripts implicitly.
3. Preserve the unpreprocessed source locations so diagnostics map to original lines and bytes.
4. Keep `partial`/`blocked` and coverage obligations when macros or required configuration remain unresolved; preprocessing must not imply that the project builds or that the resulting code is reachable.
5. Provide a no-configuration baseline mode that retains current behavior, so the result is deterministic and comparable.

Compatibility expectation: all current `parse_source(code, language=...)` calls and `SourceUnit` users retain behavior when no profile is passed; parser output schema remains additive; profile parse results remain bound to original source blob and profile digest. This has not been implemented or compatibility-tested because the shared interface is owner-controlled.

## Acceptance check for the interface

Run the existing M2 production CLI on the same exact scope (`tif_getimage.c`, `tiffio.h`) at the recorded vulnerable and fixed commits with one explicit pinned profile. Require full parse status for both files or retain partial status; require the vulnerable candidate at the root-cause expression, no same-rule finding in fixed source, original-source line binding, and unchanged safe/unrelated/incomplete controls. No runtime or product claim follows from parser completion.

## Why A-line cannot resolve this locally

The failure originates in shared `src/parser/ast.py` / frontend syntax coverage and source configuration, outside A-line ownership. A detector-only text rewrite could produce a private candidate but cannot upgrade the canonical `SourceUnit` parse state or establish compilation semantics. The A-line detector therefore retains an explicit partial result pending shared-interface review.

## Additional libpng parser blocker and value (2026-10-19)

A separate real root-cause family now demonstrates why the shared parse context matters. The OpenHarmony `install.py` generated libpng 1.6.55 `pngrutil.c` is 153,818 bytes with `light-ast` `parse_status=partial`; the saved M2 report records a parser error spanning lines 18–4716, so the production lifetime detector returns `blocked` with zero diagnostics. This is not a negative detector result.

The exact same byte-bound generated source was compiled in an isolated static ASan build. A crafted zTXt error followed by longer tEXt, then `png_read_info` → `png_read_end` without row reads, gives a heap-use-after-free at `pngrutil.c:529`; ASan traces the old buffer to `png_handle_zTXt` and a later `png_read_buffer` reallocation. Reading a row first avoids the UAF. The root cause needs source state spanning chunk decompression, buffer reallocation, zlib `next_in`/`avail_in`, and later IDAT consumption. A detector-only parser bypass cannot upgrade the canonical source coverage or bind the necessary macro/config context.

Evidence: `research/evidence/cpp/libpng_cve_2026_46675_20261019/README.md` and `baseline-oh-generated.json`. Required shared capability remains an explicit, source-bound preprocessing profile that preserves original line mappings and leaves coverage partial when inputs are absent/ambiguous. The request is still proposed and not integrated; no public runner/parser/contract was changed by A-line.

## Additional libpng CVE-2026-33416 current M2 revalidation (2026-10-19)

The current A-line revalidation now has a fresh, reproducible M2 snapshot from hash-bound SourceForge release files. Vulnerable 1.6.55 source commit wrapper `afad740f043acd9bee412677d0a5ff1e046aaa24` / tree `5d18312a3b10c4aa1a488b91ac41d010606640ef` produces two `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` findings at `pngrtran.c:1187` and `1228`. Fixed 1.6.56 wrapper `dcd78000a2e39558bd0b9340633d7acff796d37b` / tree `444dba821b3f8b58326ce85d0daf056f64029ec7` produces zero same-rule findings. Both use exact scope `pngset.c`, `png.c`, `pngread.c`, `pngrtran.c`, detector v0.1.9, profile `light-ast`, and remain 4/4 partial/blocked. Full source hashes, blobs, snapshot digests, per-run cost and outputs: `research/evidence/cpp/libpng_cve_2026_33416_20261019/current-m2-source-identities.json`, `current-m2-vulnerable.json/.md`, `current-m2-fixed.json/.md`.

This demonstrates that the registered static rule retains the real vulnerable observations despite partial parsing and stays quiet on exact fixed bytes, but it does not establish complete parse or fixed safety. Existing component ASan evidence reproduces both paths on vulnerable 1.6.55 and reports no UAF on fixed 1.6.56 or no-free controls. The OpenHarmony product-selected libpng binary, actual caller sequence, and impact remain unknown. The request remains a proposed parser-profile integration request; A-line has not edited any shared parser/runner/contract/catalog file.

An attempted replay used upstream commit IDs against the synthetic transport repository and failed before scanning with `Needed a single revision`; it produced no scan report. It was corrected by creating the above exact-byte synthetic commit pair. Source sync and scanning remain separate.


## Current-turn libpng alias-UAF replay diagnostics (2026-10-19)

The current-checkout M2 replay was repeated on the exact same source wrappers/profile/scope recorded above. Fresh files: `research/evidence/cpp/libpng_cve_2026_33416_20261019/turn-rerun-vulnerable.json`, `turn-rerun-fixed.json`, and `turn-rerun-openharmony-install.json`. The synthetic wrapper commit/tree pairs and source hashes are recorded in those reports and `current-m2-source-identities.json`; no upstream commit identity is substituted for the wrappers.

All three reports still show 4/4 C files partial. The parser issue counts are: vulnerable `png.c` 76, `pngread.c` 73, `pngrtran.c` 58, `pngset.c` 62; fixed `76/73/58/63`; full OH ordered installer output `76/80/58/62`. In each file errors begin near the leading include/configuration area (e.g. png.c:27; pngread.c:21; pngrtran.c:40; pngset.c:23) and recur through later declarations/functions; the final pngset node is missing around line 1980/2003/2041 respectively. The reports use raw-source `light-ast`, with no compile definitions, include roots, build profile or macro expansion. This pattern is consistent with missing preprocessing/configuration context, but the precise sufficient configuration is not proven by these issue nodes alone.

The fresh CLI results remain: vulnerable 2 cross-member alias candidates at `pngrtran.c:1187/1228`; fixed zero same-rule; OH generated output zero candidates. All are blocked/partial, so the OH silence is uninterpretable as a detector safety result. The requirement is an owner-reviewed experiment with an explicit, source-bound profile that preserves original line/source mapping and reports complete parsing only if the exact evidence supports it. If preprocessing context alone does not resolve the errors, the owner must identify the additional parser capability required; A-line will not add a lexical fallback or modify shared parser files.


## Current-turn libtiff exact parser nodes and scope probe (2026-10-19)

Fresh reports `research/evidence/cpp/libtiff_cve_2025_9900_20261018/turn-tif-getimage-{vulnerable,fixed}.json` and `turn-twofile-{vulnerable,fixed}.json` bind the same full vulnerable/fixed upstream commits and show why the header belongs in the acceptance scope. `tif_getimage.c` alone gives 0 diagnostics on both versions (1/1 partial); adding `tiffio.h` restores 1 vulnerable candidate at line 621 and 0 fixed candidates (2/2 partial). All scans use M2 v0.2.6 with lazy fetch disabled.

Exact parse nodes: vulnerable `tif_getimage.c` errors at 1383, 1393, 1687, 1707, 1833 and missing at 1831; fixed equivalents shift to 1411, 1421, 1715, 1735, 1861 and missing 1859. The sites are inside/adjacent to `UNROLL`/`CASE` macro invocation/expansion bodies, not the candidate subtraction at line 621. `tiffio.h` missing nodes at vulnerable 483/485/487/489/496/498 and 650; fixed at 498/500/502/504/511/513/668. These declarations attach `TIFF_ATTRIBUTE((__format__(__printf__, ...)))` attributes through the configured `TIFF_ATTRIBUTE` macro. The current profile is raw-source `light-ast`; it supplies no compiler defines, include configuration, or preprocessing map. This makes macro expansion and compiler-attribute support concrete shared-parser requirements to test, but does not yet prove an explicit profile alone will eliminate all errors.

The acceptance check must keep `tif_getimage.c` plus `tiffio.h`: the candidate rule depends on header context, while the fixed and vulnerable translation units remain partial. A shared owner should test a source-bound C profile with controlled macro expansion and attribute handling, preserving byte/source mapping; if grammar support is insufficient, report that separately. No A-line change was made outside its owned files.


## OpenHarmony libtiff build-profile evidence checked locally (2026-10-19)

- Pinned local source is declared libtiff 4.7.0; `tif_getimage.c` SHA-256 is `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`, `tiffio.h` is `a1a60c10109f8086c9470c6922eb3d56509aa3d1bad286d7e4a346542cff8994`. Existing manifest commit/tree binding is recorded in the coverage ledger; the checked-out .git config remains unreadable, so these hashes are the directly verified local file identity.
- OpenHarmony `third_party/libtiff/BUILD.gn` SHA-256 `23fe746dc2f2e1bfe6972e078238ce46c296f252cf8f5ac80f75e9538aa70f25` includes `libtiff/tif_getimage.c` in `base_libtiff_source`. `libtiff_config` adds generated `$code_dir/libtiff` and `$code_dir/config` include roots. Feature defines are conditional GN args (default values are in the file, but selected product overrides are unknown).
- The GN action invokes `install.sh` (SHA-256 `8990f0eeb2efc05add8711213597719e92516398aa3f4cdc6cd6cb6803ba44c7`). Its source shows it copies the component then runs `autogen.sh`, `configure`, and `cmake . -DCMAKE_BUILD_TYPE=Release`; generated code/config outputs are not present in the checked-out product output. The source `libtiff/CMakeLists.txt` uses C99 and `configure_file` to generate `tif_config.h`, `tiffconf.h`, and `tiffvers.h`; the CMake target consumes generated `tif_config.h` and `tiffconf.h`. The source template `tiffconf.h.cmake.in` contains host/configuration-derived type and feature values.
- `openharmony/out/rk3568` currently contains only `build.1792344452.3203762.log` and `build.log`; no `build.ninja`, target args/profile, or `compile_commands.json` was found. Therefore an exact generated configuration profile cannot be reconstructed from current artifacts. No build/configuration script was run.
- This establishes that preprocessing needs both GN-selected definitions/include roots and generated configure outputs. It does not establish the exact profile selected for the product image. Keep shared-owner profile work pending; no macro substitutions are used to promote parsing.
