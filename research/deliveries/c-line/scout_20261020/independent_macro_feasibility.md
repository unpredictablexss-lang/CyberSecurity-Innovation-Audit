# Independent macro-aware parse feasibility check — 2026-10-20

## Checkout and inputs

The isolated test worktree was clean at start, HEAD `3004ebf0d65166e4a0dc236d2f4fb3d7152f1f5c`. No production files or dependencies were changed. The imported `src/ohscanner/detectors/interface/cpp_macros.py` has the same SHA-256 as the scout worktree copy (`64e13bcf611a4d2f1a3b33082e1120f753874c479f5870bba0509187da8fe7e1`). The tests were run against the local copy.

I read the target and three macro headers directly from local bare Git store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git` at C1 commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. Their exact Git blob and SHA-256 identities were independently rechecked in the previous parser-control report and match the pinned catalog provenance in the expander output. `macro_catalog(sources)` receives only those pinned source bytes; `expand_with_catalog(source, catalog)` returns `source`, `line_map`, `expansions`, `refused`, and `fatal`. An `Expansion` is fully resolved only when both `fatal` and `refused` are empty.

## Reproduced controls

- Supported `IR_ELSE`: raw control parses `partial`; expansion yields `else if (_ife.IsFalseBranch())`, parses `complete`, has no refusal/fatal entries, and records definition provenance as `stub_builder.h:1569` with the bound header SHA-256. The expanded line maps back to original line 4 (`original_line(4) == 4`).
- `IR_IF`: expander applies nothing and returns `refused=[("IR_IF", "variadic_stringify_or_token_paste")]`; `fully_resolved=false`. The raw minimal snippet happens to be accepted as syntactic C++ (`parse_status=complete`) because the macro invocation resembles a call. This is an important integration boundary: the expansion API preserves an explicit refusal, but a caller that discards `refused` and trusts Tree-sitter status alone could mislabel an unexpanded macro as a fully understood parse. The expander result itself does not silently claim full resolution.
- `BRANCH`: expander applies nothing and refuses with `variadic_stringify_or_token_paste`; the raw/returned source parses `partial`; `fully_resolved=false`.
- Typed-array case-list macro: the outer `BUILTIN_COMPILER_TYPED_ARRAY_TYPES` expansion applies once, then refuses all 11 nested `BUILTIN_COMPILER_TYPED_ARRAY_LABEL` calls because its body uses token paste (`TYPE##_ARRAY_ROOT_HCLASS_INDEX`). There are 11 refusal records, no fatal entries, and `fully_resolved=false`; the returned source remains `partial`.
- Explicit token-paste control `#define PASTE(a,b) a##b` / `PASTE(foo, bar)`: no expansion; refusal is `variadic_stringify_or_token_paste`; `fully_resolved=false`. As with IR_IF, raw syntax alone parses complete, so consumers must preserve the refusal state.

These outputs validate bounded, source-mapped expansion for the one supported control and conservative refusal of unsupported control-flow/stringification/token-paste forms. The macro helper is not a C/C++ preprocessor and does not infer build configuration or select conditional definitions.

## C1 fallback without native toolchain/build configuration

All checked native tools were absent from PATH: `clang`, `clang++`, `clang-cl`, `g++`, `gcc`, `cl`, and `cpp` returned `None`. No native build configuration was supplied; the existing CLI evidence profile identifies `build_profile=none`, `product_manifest_locked=false`.

Cataloguing the exact pinned target plus exact headers and attempting full target expansion returns `fatal=["source_local_undef_not_supported"]`, `applied=false`, with no expansions; the helper returns original source bytes as fallback. Parsing that raw fallback yields `partial` with the same 13 issues at lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611, 3629. Missing toolchain/build config does not upgrade this source to complete.

Relevant existing interface tests also pass: `python -m unittest tests.test_ipc_macros tests.test_ipc_macro_failfast_descriptor` — 34 tests, OK.

## Limits

This is feasibility evidence for the bounded macro catalog/expander, not a complete C1 translation-unit parse. Full target expansion is refused because of the source-local `#undef`; IR_IF, BRANCH, and nested token-paste forms remain unresolved. A parser integration must treat fatal/refused expansion as unresolved even when a raw macro invocation is syntactically accepted by Tree-sitter. No product build, build flags, compile success, or security conclusion is inferred.
