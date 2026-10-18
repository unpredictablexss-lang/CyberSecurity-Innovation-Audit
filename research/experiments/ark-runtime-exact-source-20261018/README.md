# Ark Runtime exact-source replay (research only)

Frozen C-line detector/model: `4ea5f4020884aed5860a88d50f5a926610e7b98a`, Detector `ohscanner.ark.runtime.type_safety` 0.2.0, rule `ark.runtime.typedarray-store-type-origin`, model SHA-256 `1421ec97eb81e0f08910a83d7b72cfdd9d5bcd22aa752105739faf36341c72fe`. The evidence bundle itself is at C-line commit `76f20af9e372189627f5117ed9a30815d1f49747`; that is a scanner commit, not an Ark Runtime source commit.

## Replayed pairs and controls

- **TypedArray type origin:** `830e85b40240677039719fcbf14f721ad3b19050` → `a0e30483ab3e4aead67ecfb5c708489915e447f9`, exact `builtins_typedarray_stub_builder.cpp` blobs. Parent yielded `candidate`; fix yielded `matched`. Safe `Set` yielded `matched`; unrelated `Map` yielded no observation. All have exact repo/commit/tree/blob/Git blob OID/SHA-256 and profile bindings in `raw-results.json`.
- **Exception propagation:** `2e2cebedf5a96fb798144c82296b8b55e2eb60c6` → `c80d853d1b3be23ca999618a199183bc854eaa6a`, exact `slowpath_lowering.cpp` blobs. Research-only rule `ark.runtime.callstub.pending-exception-propagation` 0.1.0 yielded `candidate` → `matched`; fixed regression source is separately bound. An unrelated `LowerCallRuntime` control was not applicable. The official C-line type-origin Detector has no exception rule: its result is `not_analyzed`, so do not interpret that as a miss-free or safe result.

## Partial and unknown status

The type-origin source analyses and controls are `limited/partial`, with `parse_dependency_contamination_unknown`, `production_runner_not_admitted`, and `research_only_partial_function_scope`. The exception-propagation candidate comes from a narrowly scoped research probe, not the shipped C-line Detector; full CFG/dominance and product exception-state semantics remain unknown. In the TypedArray fix, `GetObjectType(LoadHClass(newArray))` appears before `HasPendingException(glue)`, so validity of that read on an exceptional creation path remains an explicit unknown/evidence obligation.

The fixed tree's zero candidate count is scoped to these inputs and does not establish component safety. No dynamic runtime/build validation or security-impact confirmation was run.

## Dependency comparison

Parser packages match the frozen C3 run (`tree-sitter 0.26.0`, `tree-sitter-c 0.24.2`, `tree-sitter-cpp 0.23.4`). The rerun used Python 3.13.9 while the frozen run used Python 3.12.0. Build profile remains assumed (`NDEBUG=1`, `ENABLE_ASM_ASSERT=0`) and is not product-build verified.

See `commands.txt`, `raw-results.json`, `run-summary.json`, `source-git-bindings.txt`, source blobs/diffs, and `hash-manifest.json`.
