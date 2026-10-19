# T14 independent acceptance: D16 cJSON tree-amplification rule

Date: 2026-10-20 (Asia/Shanghai)

## Decision

**Synthetic regression for the D16 resource-sink correction: PASS. Exact-source CVE-2026-67215 candidate semantics: PARTIAL.** The focused resource detector suite passed 8 tests and the full C++ detector suite passed 160 tests. The new negative fixture named `unrelated_recursive_delete_name.c` remains quiet, and the partial fixture remains blocked. No fixed cJSON source is bound.

This acceptance does not treat the upstream source run's `blocked` status as a success or safe result. The candidate at `cJSON_Utils.c:861` is a function-level lexical candidate. Review of the exact control flow shows the reported line is in the special empty-path root replacement branch, which exits before the general nested ADD/COPY attachment path. The detector currently takes the first matching duplicate assignment in the function and associates it lexically with later attach/release operations without proving they share a feasible path. Therefore D16's anti-false-positive sink change is independently accepted, while the exact source root-operation binding remains PARTIAL.

## Source identity

The OpenHarmony checkout's Git project remote is `https://gitcode.com/openharmony/third_party_cJSON`. Independent Git object inspection verified:

- Upstream component commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`
- Upstream tree: `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`
- `cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, 80,529 bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`; parse status `partial`.
- `cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`; parse status `complete`.

The replay harness packages those exact bytes under a synthetic two-file Git snapshot: commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`, snapshot SHA-256 `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`. This transport identity is distinct from the upstream component commit/tree. The identity-checking replay and its independent output are [replay.py](replay.py) and [t14-replay.json](t14-replay.json).

## Replay and source semantics

The exact-source replay with detector `ohscanner.cpp.resource_lifetime` version `0.4.1` emitted:

- `ohcpp-resource-exhaustion-tree-amplification-candidate-004` at `cJSON_Utils.c:861`, symbol `apply_patch`.
- The separate recursive compare-cost candidate at `cJSON.c:3161`, symbol `cJSON_Compare`.
- Aggregate status `blocked`, because `cJSON.c` is parser-partial. `cJSON_Utils.c` is complete. No zero-result safety conclusion is made, and no trusted fixed source is available.

At line 861, `apply_patch` is handling the special root path (`path->valuestring[0] == '\0'`) and recursively duplicates the incoming value for root replacement; that branch then goes to cleanup. General COPY recursively duplicates at line 932, general ADD/REPLACE duplicates at line 950, and nested array/object attachment occurs later at lines 985, 997, and 1015. `cJSONUtils_ApplyPatches` iterates patch operations. The core `cJSON_Delete` recursively descends to children and releases node/string storage through `global_hooks.deallocate`.

The current detector's `_tree_amplification_candidates` selects the first matching recursive-copy assignment in a function and separately looks for attach/release shapes in that same body. It does not connect branch feasibility or ownership transitions. The line-861 finding therefore identifies the function containing relevant patterns, but not the actual nested ADD/COPY amplification operation. This is a location/control-flow limitation that needs a follow-up before claiming root-specific source coverage.

## Controls and verification

- Two synthetic recursive tree-amplification positive controls still emit the distinct candidate rule.
- The new misleading-name negative (`cJSON_Delete` that only traverses children and does not release memory) emits no tree-amplification candidate; its SHA-256 is `cca572fc63d6c0451b6f83dab0e8aaf8b69296f2a6ffb529988e72ecd989e145`.
- Existing unrelated recursive-tree control is quiet. The partial recursive-release control remains blocked with no candidate.
- Resource-lifetime tests: 8 passed. Full C++ detector suite: 160 passed.
- `scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: 0 violations. `git diff --check`: passed.
- This acceptance commit changes only the T14 JSON/Markdown evidence. It does not edit the detector, tests, fixtures, parser, Catalog, or public API.

Full machine-readable results and commands are in [t14-acceptance.json](t14-acceptance.json).
