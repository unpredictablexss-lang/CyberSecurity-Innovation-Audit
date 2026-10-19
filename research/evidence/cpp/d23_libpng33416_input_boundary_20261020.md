# D23 libpng CVE-2026-33416 input-boundary assessment

Date: 2026-10-20 (Asia/Shanghai)  
Baseline: `b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e`  
Detector: `ohscanner.cpp.resource_lifetime` `0.4.2`  
Disposition: **NO CHANGE; PARTIAL/BLOCK**.

## Bound source and prior replay

This assessment uses the exact D20/D12 identities and slices. Vulnerable libpng is commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`; fixed libpng is commit `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`, tree `a28bb962645843af84063c77f574f6d88da79f76`. The four vulnerable/fixed function slices and source hashes are in [D20 replay JSON](d20_libpng33416_replay_20261020.json); the original byte-preserving extraction method and upstream identities are in [D12 fragment record](d12_libpng_function_fragments_20261020.md).

The D20 replay reports all eight slices `partial`, each detector run `blocked`, and zero findings. Zero findings on these inputs do not establish safe or fixed behavior. No detector, test, fixture, or shared parser files were changed in this assessment.

## Exact syntax boundaries

The parser errors were inspected as tree-sitter nodes against the same hash-pinned whole-file bytes. The relevant nodes are:

| Function(s) | Exact parser boundary | Interpretation |
|---|---|---|
| `png_set_PLTE` and `png_set_tRNS` in `pngset.c` | `PNGAPI` token at function declaration; additionally indented `#ifdef PNG_MNG_FEATURES_SUPPORTED` / `#endif` inside a conditional expression in `png_set_PLTE` | Requires macro/preprocessor context; not fixed by adding local variable declarations. |
| `png_free_data` in `png.c` | `PNGAPI` token at function declaration | Requires macro context. The body also uses conditionally compiled cleanup branches whose active set is not determined by the raw slice. |
| `png_do_expand_palette` in `pngrtran.c` | Missing semicolon nodes at the `PNG_UNUSED(png_ptr)` macro sites | Requires the macro's expansion semantics; the macro invocation alone does not expose the parsed statement. |

These are source/preprocessor-context boundaries. Replacing macro tokens, deleting directives, appending guessed typedefs, or stitching functions together would create synthetic inputs. Equal-length whitespace replacement might preserve reported offsets, but it would not preserve semantics or establish that the substituted macro/build configuration is the one used by the exact source. A clean parse obtained that way would only be a local syntax experiment, not an accepted basis for an ownership finding or for promoting source coverage.

## Why this cannot produce a credible narrow candidate

The source relationship is still spread across files and functions: `png_set_PLTE` stores palette state on `png_struct` and `png_info`; `png_free_data` frees/nulls info-owned members; and `png_do_expand_palette` consumes palette/transparency pointers. The current detector's resource state is local to a function and lexical flow segment. It does not establish `png_struct`/`png_info` field identity, object aliasing, or the release-before-use ordering across these functions/files. The fourth selected function's syntax recovery would not supply those missing facts either.

Therefore no local declaration or function-slice adjustment supported by the current parser/model can yield the required vulnerable candidate plus exact-fixed/safe/unrelated discrimination. No CVE-specific control was fabricated. The fixed tree remains an exact source identity, but its partial result is not a fixed PASS.

## Minimum next input

Without changing the shared parser, the smallest useful next package is a parser-owner-reviewed, source-offset-mapped slice contract containing:

1. The active, source-bound macro/build configuration for `PNGAPI`, `PNG_UNUSED`, and `PNG_MNG_FEATURES_SUPPORTED` for both exact trees.
2. Exact declarations (with source file and hash) proving the `png_struct` and `png_info` member types/identity for `palette`, `trans_alpha`, and related ownership state.
3. The source-bound call/order context connecting the setter, cleanup, and expansion/use paths in each variant, including the relevant caller(s).
4. Exact vulnerable and fixed replay inputs plus source-bound safe and unrelated state controls, with original offsets and independent coverage labels.

Until that package exists, the status remains PARTIAL/BLOCK. Even a candidate on reviewed slices would not upgrade whole translation-unit coverage or establish product build selection/reachability.

## Changed files and verification

Only this evidence note was added. Detector and dedicated tests were not changed or run because no detector behavior change was supported. The D20 replay remains the reproducible source-bound baseline; it records the source/fragment hashes, offsets, parser issues, coverage, and blocked zero-finding outcomes.
