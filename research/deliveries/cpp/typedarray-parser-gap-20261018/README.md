# TypedArray C++ owner attribution gap

This investigation is bound to the `arkcompiler/ets_runtime` Git object snapshot
`a65a2853ccae13da167d9aa4720ab8b11ec16656`.

## Finding

Before the fix, the light C++ frontend parsed the target implementation as
`partial` (13 Tree-sitter error/missing nodes) and returned the two definitions
at lines 1436 (`Filter`) and 2662 (`Map`) with only their leaf names. The parser
now retains the class qualifier in additive `FunctionDef.owner` and
`qualified_name` fields while preserving the legacy `FunctionDef.name`. The
source spelling assigns both methods to
`panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder`. The class
declarations are generated through `DECLARE_BUILTINS_TYPEDARRAY_STUB_BUILDER`
and `BUILTINS_WITH_TYPEDARRAY_STUB_BUILDER`; the macro list maps the methods to
`TYPED_ARRAY_FILTER` and `TYPED_ARRAY_MAP`.
Several reported syntax nodes occur around `IR_ELSE` control-flow macro uses
(for example, lines 148, 151, 154, and 2862); the parser sees macro spellings,
not their `stub_builder.h` expansions. Other error nodes are preserved in
`reproduction.json` without attributing every one to preprocessing.

The pinned-source positive case now exercises the production parser; an
independent corrected AST-name extractor, a synthetic fixed-owner case, and an
unrelated-class safe control cross-check the behavior. These checks prove
method-name/owner attribution for those definitions only. They do not make the
whole source file safe, fully parsed, or semantically resolved.

## Fix plan and execution

1. Preserve the pinned Git identity and inspect the existing Tree-sitter AST
   failure and method declarators.
2. Add qualified name and syntactic owner fields without changing the legacy
   leaf `FunctionDef.name` used by existing detectors.
3. Carry those fields into OHScanner's syntax-only facts with an explicit
   `owner_resolution` label; do not treat syntax as type resolution.
4. Add positive, fixed behavior, unrelated-owner, lexical-class and free-
   function controls, then rerun the pinned source reproduction.
5. Keep source coverage partial until the real GN command, macro expansion and
   transitive dependency closure are available.

Steps 1–4 are implemented in `src/parser/ast.py`,
`src/ohscanner/facts.py`, and `tests/test_cpp_owner_attribution.py`; step 5
remains the evidence limit for the Ark Runtime translation unit.

## Provenance

| Item | Value |
|---|---|
| Repository | `arkcompiler/ets_runtime` (`https://gitcode.com/openharmony/arkcompiler_ets_runtime`) |
| Commit | `a65a2853ccae13da167d9aa4720ab8b11ec16656` |
| Commit tree | `8781f036a3e7e04d8e0b34970d5f623b42875016` |
| Target path | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` |
| Target blob | `68fb3b0adc4f9062889a861be51b7be90362e37a` |
| Target SHA-256 | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |

The exact header and build-file blob IDs and SHA-256 values are in
`provenance.json`. The `BUILD.gn` entry proves the file is part of
`libark_jsoptimizer_sources`; it does not provide the generated compiler
arguments.

## Dependency evidence and limits

The implementation directly includes its builder header, typed-array helper,
array-buffer and array builders, call builder, and object builder. Its builder
header includes `builtins_stubs.h`, `stub_builder-inl.h`, `js_arraybuffer.h`,
and `js_typed_array.h`. The header declaration macro comes from
`builtins_call_signature_list.h`. The builder header also defines
`BUILTIN_COMPILER_TYPED_ARRAY_TYPES`, used later in the same implementation to
generate the typed-array switch cases.

`Filter`/`Map` are confirmed methods of the TypedArray builder by their
qualified definitions and matching macro-generated class declarations. Their
parameter types are `GateRef`, `Variable *`, and `Label *`; other central types
include `DataViewType`, `JSTypedArray`, and `JSType`. Definition locations and
hashes for those types are recorded, including the `JSType` definition in
`js_hclass.h`; the active include path cannot be established without the real
compile command and include graph.

The pinned checkout has no generated `compile_commands.json`, `args.gn`, or
target `build.ninja` under `openharmony/out`, and no saved preprocessed
translation unit for this target. A bounded workspace search found no compile
database, GN args file, or preprocessed TypedArray translation unit (the only
`build.ninja` match was an unrelated third-party Ninja self-test). Thus GN
include paths, compiler defines, target/toolchain
arguments, transitive include closure, active macro values, and conditional
branches are unknown here. The `BUILTIN_COMPILER_TYPED_ARRAY_TYPES` list and
the Filter/Map method-registration macro are visible in pinned source, but
macro expansion was not observed in a compiler-produced artifact. Overall
translation-unit status is **partial/unknown**, never complete.

The local source tree also has no `out/` or `prebuilts/` directories; `gn` and
`ninja` are absent from the WSL PATH. A system `clang++` exists, but without the
GN-generated command, pinned toolchain, and generated headers it cannot stand
in as the target's real build configuration. These availability checks are
included in `reproduction.json`.

## Reproduction

Run with the OHScanner checkout on `PYTHONPATH` and its Tree-sitter C++
dependencies installed:

```sh
PYTHONPATH=/path/to/CyberSecurity-Innovation-Audit \
  python reproduce.py /path/to/openharmony/arkcompiler/ets_runtime
```

The recorded run used OHScanner commit
`f8e3a0ad7463f216db4be7502bd8a19eec545908`, parser source SHA-256
`52d15fad1f8d528743ccf3c791b01587349c0923bdf56ded6e2e760c96339e21`,
syntax-facts source SHA-256
`b17200c5988845c7580b796b5612eddb1c7e6ca50c8579643ecda43da872b389`,
Tree-sitter 0.26.0, and tree-sitter-cpp 0.23.4. `reproduction.json` records
both the pre-fix observation and the current production parser result.

The command checks commit/tree/blob/SHA-256, all recorded dependency objects,
frontend parse status, observed method names, current and prototype owner
extractors, and the safe unrelated-owner control. Its successful exit only
records those bounded checks.

The parser regression command used for the recorded run was:

```sh
PYTHONPATH=.:tests:<tree-sitter-site-packages> python -m unittest \
  tests.test_cpp_owner_attribution tests.test_ast \
  tests.test_ast_coverage_mapping tests.test_ohscanner_m15 -q
```

Result: **26 tests passed**. `compileall` passed for the modified parser,
syntax-facts module, and new regression test.

## Evidence status

- Source identity: verified from the pinned Git commit object.
- Filter and Map source owner: verified from qualified definitions, now
  preserved by the production parser as `BuiltinsTypedArrayStubBuilder`; class
  declaration route verified from pinned macro source.
- Syntax frontend: `partial` for the implementation and builder header.
- Namespace context is lost for recovered target methods; only the class
  qualifier is retained. `owner_resolution=syntax_qualified` is not type lookup.
- Type resolution, build defines/flags, full preprocessing, transitive
  dependency closure: unknown / not evidenced.
- Whole-file safety: not assessed and not implied.
