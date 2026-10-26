# A-line shared parser prerequisite request: C preprocessor context for C/C++ AST coverage

Status: **pending shared-owner review; not implemented or admitted**
Date: 2026-10-19
Owner lane: A_CPP

## Observed blocker

The production M2 `light-ast` run on byte-identical OpenHarmony cJSON 1.7.19 `cJSON.c` and `cJSON_Utils.c` reports `cJSON.c` partial and detector status blocked. The tree-sitter C parser reports errors at lines 158-173 and missing nodes at 3152/3169. Direct replay with `src.parser.ast.parse_source` reproduces eight errors. The failing declarations use `CJSON_CDECL`, which is defined through `cJSON.h`; the shared frontend parses raw source and has no compile-definition/header preprocessing input. Trying C++ grammar is worse (84 parser issues). This prevents a complete baseline for a disclosed recursive cleanup issue.

## Minimal capability requested

A shared, immutable, source-bound preprocessing context for C/C++ indexing, either:

1. a verified compile-command/configuration profile containing include roots and `-D`/`-U` definitions, where each input and derived preprocessed buffer has provenance hashes and the original source remains the diagnostic identity; or
2. an explicitly supported bounded macro-normalization facility for known ABI/calling-convention macros, with a recorded transformation map and no claim of type/semantic equivalence.

The producer must bind configuration to the pinned repository commit/tree and selected build target. Missing/ambiguous configuration must preserve `partial`/`unknown`. The facility must not silently run host preprocessing or infer product flags from package version.

## Conformance needed before use

- Reproduce original `cJSON.c` partial status without configuration.
- With an explicitly supplied and source-bound `CJSON_CDECL` configuration, show whether the two cJSON files parse completely; preserve original source SHA and diagnostic locations.
- Negative control: absent/ambiguous profile remains partial; malformed macro configuration cannot upgrade coverage.
- Run existing parser and production CLI regressions for affected C/C++ fixtures and check resource/cost bounds.
- Keep the feature shared-owner gated; A-line does not edit parser/frontend/contracts/runner/catalog.

## Evidence

- `research/evidence/cpp/cjson_cve_2026_67215_20261019/README.md`
- `research/evidence/cpp/cjson_cve_2026_67215_20261019/baseline.json`
- `research/evidence/cpp/cjson_cve_2026_67215_20261019/baseline.md`
- Current API path: `src/ohscanner/frontend.py` calls `parse_source(text, language=...)`; `src/parser/ast.py` exposes only source text and language. Both are outside A_CPP's allowed write scope.

This request is not approval, implementation, or integration. The detector must retain blocked/partial status until an admitted source-bound preprocessing capability or another complete parser path is available.

## Source-bound parser-gap probe (2026-10-19; research-only)

The A-line replay script `research/evidence/cpp/cjson_cve_2026_67216_20261019/parser_context_probe.py` is bound to local `cJSON.c` SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb` and `cJSON.h` SHA-256 `25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee`. Raw parsing reproduces six errors on `CJSON_CDECL` uses at lines 158, 159, 160, 165, 169, 173 and missing nodes on the `cJSON_ArrayForEach` invocations at lines 3152 and 3169. Applying only the explicitly selected non-Windows empty `CJSON_CDECL` branch and the exact `cJSON_ArrayForEach` expansion read from this header yields complete tree-sitter C parsing, with original line count preserved; `cJSON_Compare` at 3066-3189 and recursive call nodes at 3131, 3161, 3177 become available. The transformed-buffer SHA-256 is `d51cd016de813303a872427a58cfd51861cdf417ef977790c6614bf9691eb115`; report is `research/evidence/cpp/cjson_cve_2026_67216_20261019/parser-context-probe.json`.

This experiment does **not** upgrade production coverage: it does not supply a product-bound compile profile, full C preprocessor, byte/column source map, or production CLI integration. The OH component `BUILD.gn` locally shows include root `//third_party/cJSON` and `CJSON_NESTING_LIMIT=(128)` for the selected GN branches; actual product generated args and compile command remain unavailable. A conforming shared capability still needs to bind those inputs to the selected target and retain original-source diagnostic identity. This evidence refines the request but is not an approval or implementation.

## Current source-bound CVE-2026-67215 replay (2026-10-19)

The old temporary repo path cited in the CVE-2026-67215 README no longer exists. A new synthetic Git snapshot was created from the exact byte-hash-matched OpenHarmony `cJSON.c` and `cJSON_Utils.c` files; it has the same tree (`3c07134d5a05aa546b15739e32503a2ca192d258`) and snapshot digest (`c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`) as the earlier evidence, but a new synthetic commit. Current M2 production CLI v0.1.9 reports 0 diagnostics, `cJSON.c` partial and `cJSON_Utils.c` complete, overall blocked. This still cannot be called a static miss or safe result. Report: `research/evidence/cpp/cjson_cve_2026_67215_20261019/revalidation-current.json`.

Upstream status was rechecked: Red Hat says no upstream fix as of 1.7.19; GHSA patched versions remain unknown; issue #1073 is open without a linked PR. PR #1064 targets MergePatch recursion under issue #995 and PR #1078 adds comparison recursion limits; neither resolves JSON Patch subtree amplification followed by recursive `cJSON_Delete`. Links and root-cause distinction are in the adjacent `upstream-status-and-current-replay-20261019.md`.
