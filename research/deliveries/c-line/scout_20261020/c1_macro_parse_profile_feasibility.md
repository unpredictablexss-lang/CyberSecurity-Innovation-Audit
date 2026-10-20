# C1 macro-aware parse profile feasibility — 2026-10-20

## Outcome

Scout started clean at `68f9371d4e967884404cf7ed4c70805cbc517499`. No production code was changed. A bounded, macro-aware parse profile is conceptually useful, but a real exact-C1 preprocessing run is **not currently feasible** in this environment: no native C/C++ compiler/preprocessor is on `PATH` (`clang`, `clang++`, `clang-cl`, `g++`, `gcc`, `cl`, and `cpp` all unresolved), and no compile database/build profile was supplied or found in the scanner checkout. The C1 replay itself records `profile_id=light-ast`, `build_profile=none`, `macro_expansion=false`, and `product_manifest_locked=false`.

The environment check also tested common locations for LLVM, Visual Studio 2022 Community/BuildTools, VS Installer, MSYS2, MinGW, Strawberry Perl, and Cygwin; none contained the expected compiler/preprocessor. The only matching PATH directory was `D:\anaconda3\Library\mingw-w64\bin`, which contained no `clang`, `gcc`, `g++`, or `cpp` executable. This records local tool availability only; it is not a workflow approval/prerequisite gate. Exact compile arguments and product build configuration remain unavailable/unknown, and no toolchain installation was attempted.

The only feasible probe was an isolated call to the repository's existing bounded token macro expander using selected exact header definitions from the pinned local Git store. Script and machine-readable output: `macro_parse_profile_feasibility_poc.py` and `.json` in this directory.

## Exact inputs and probe

Pinned source commit/tree: `a65a2853ccae13da167d9aa4720ab8b11ec16656` / `8781f036a3e7e04d8e0b34970d5f623b42875016`.

| Input | Git blob | SHA-256 |
|---|---|---|
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `68fb3b0adc4f9062889a861be51b7be90362e37a` | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h` | `017286724e4cd6df1a369589293efe920660c4c6` | `f5b25eed46bfe6e951c6ad8b79ff76bfee8d402868839d21e6d41cd84ef3f8e3` |
| `ecmascript/compiler/stub_builder.h` | `9e2fbd3ede1da91133dcd936018285e597944515` | `a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0` |
| `ecmascript/compiler/circuit_builder.h` | `df296de399f31a97417ed124f4ed8f8e4fd608b7` | `41ce63da35d4f9abf5e32bcd417384fadcb018718d002b798e339da11a1a7d70` |

Results:

- Existing `src/ohscanner/detectors/interface/cpp_macros.py` explicitly describes itself as a token expander, not a C++ preprocessor; it never follows `#include` and refuses uncertain constructs.
- Passing the complete pinned C1 target and the selected exact definitions fails closed with `source_local_undef_not_supported`, before any expansion.
- A synthetic `IR_ELSE` control using the exact pinned `stub_builder.h` definition changes from raw Tree-sitter `partial` to expanded `complete`. Its expansion record identifies definition `stub_builder.h:1569` and the call-site line; `Expansion.original_line(4)` maps expanded line 4 back to original line 4. This demonstrates line-level mapping for one simple object-like macro only.
- Exact-definition controls show `IR_IF` and `BRANCH` are refused as `variadic_stringify_or_token_paste`. `BUILTIN_COMPILER_TYPED_ARRAY_TYPES` expands one outer level but refuses each nested `BUILTIN_COMPILER_TYPED_ARRAY_LABEL` expansion for token-pasting. Thus the helper cannot resolve the C1 error set. An `applied` outer expansion with refusals is not a complete expansion.

## Existing interfaces and constraints

`src/ohscanner/indexing.py` fingerprints only the `light-ast` parse profile, `build_profile=none`, and no macro expansion. It indexes raw pinned Git source through Tree-sitter. Ark's `src/ohscanner/detectors/ark_runtime/syntax.py` explicitly documents no preprocessing; `ScanRequest.profile_id` is currently `light-ast`, and the exact-source adapter enforces that profile. The bounded IPC macro helper has a useful per-line provenance map and records macro definition path/line/hash, but refuses `#undef`, conditional variants, variadic/stringify/token-paste forms and does not resolve includes. It is not sufficient as a replacement for the C preprocessor on C1.

## Bounded profile shape to prototype next

Use a distinct opt-in profile (for example `ark-cxx-preprocessed-v1`), never silently replace `light-ast`. Its immutable manifest should bind:

- repository, full commit/tree, target path/Git blob/SHA-256;
- every resolved project header and forced include by path, Git blob and SHA-256, in include search order;
- compiler executable digest, exact version, target triple, language standard and resource/sysroot identity;
- ordered preprocessor arguments: defines, undefines, include paths, forced includes and relevant environment; exact command/normalized-command digest;
- preprocessor output digest plus a versioned source map, including output token/line ranges, original file/byte ranges and macro expansion definition/call stacks.

The current per-line `Expansion.original_line()` map is a feasibility seed, not enough for token-level findings after nested/function-like expansion. A real preprocessor source-map experiment should establish how diagnostics and macro-origin stacks are retained on the chosen compiler before using expanded AST locations in detector findings.

Fallback must be atomic: if compiler/profile identity, any required include/hash, compile arguments, preprocessing, macro expansion, source-map coverage or parse stage is missing, ambiguous, refused, over budget or fails, discard the partial expansion and keep the raw-source parse status (`partial` for C1). Never upgrade to complete solely because a partially preprocessed buffer parses cleanly. Unknown toolchain/build settings stay unknown; do not invent a product profile.

## Recommended next step

When an exact compile database/toolchain becomes locally available, run a temporary, non-production preprocessing experiment against this pinned commit and its complete include closure; compare raw and preprocessed parser issues and verify mapped locations at all 13 C1 issue sites, including macro-generated `case` branches. Keep the current scanner's `light-ast` behavior unchanged until that experiment has exact reproducibility, complete preprocessing, and tested source-map coverage. The current feasibility result supports research planning only; no C1 coverage upgrade or model/candidate claim is made.
