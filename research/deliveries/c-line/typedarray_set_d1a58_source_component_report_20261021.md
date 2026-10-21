# Ark Runtime TypedArray.set source/component result — 2026-10-21

## Result

**Disposition: source-level candidate retained; runtime vulnerability and product impact remain unknown.** The pinned `d1a58d59166777e16574ceed64c15f0b2f44a76c` source still has an ordinary array-like `%TypedArray%.prototype.set` path where `srcLen + targetOffset` is checked in `uint64_t` without overflow-safe arithmetic, and the resulting byte index is narrowed to `uint32_t` before the backing-buffer write. A reproducible witness crosses the target TypedArray view boundary by 2,048 bytes while remaining within the 8,192-byte backing allocation. This does **not** establish a backing-store out-of-bounds access.

## Source identity, helper profile, and AST coverage

The source repository is `openharmony/arkcompiler_ets_runtime`, Gitee `master`/`HEAD` at review time. The exact commit is `d1a58d59166777e16574ceed64c15f0b2f44a76c`, tree `2cd854aa7d9f987de89d31a6a512e735779e75b6`. The report script verifies the checkout commit/tree, each Git blob OID, SHA-256, byte count, parser status, and the required Set/conversion/sink source shape before producing a candidate replay. Full file bindings are in [source replay JSON](typedarray_set_d1a58_source_replay_20261021.json). The independent a65→d1a58 path comparison is included in the [closeout evidence package](runtime_evidence_20261021/README.md).

| Role | Source objects | AST result |
|---|---|---|
| Target method and declaration | `builtins_typedarray.cpp` complete; `builtins_typedarray.h` partial (33 issues) | `BuiltinsTypedArray::Set`, lines 1146–1392, parses in a complete translation unit; declaration identity remains pinned but partial |
| Conversion | `js_tagged_value.cpp` complete; `number_helper.cpp` partial (2 issues) | `ToInteger` implementation is bound; Number helper partiality remains explicit |
| Backing write | `builtins_arraybuffer.cpp` complete | `SetValueInBuffer` and data-pointer helper are bound; target view length is not passed to the backing writer |
| Typed-array helper context | `typed_array_helper.cpp` complete; `.h` partial (4 issues) | Exact helper bytes are pinned; this array-like Set branch does not invoke a TypedArray species creator |

Creator dependency is **not applicable** to this builtin Set entry: its source path is directly in `BuiltinsTypedArray::Set`; the relevant execution boundary still needs Ark runtime dispatch/build evidence. The partial declaration/helper headers are not upgraded to complete. The production OHScanner candidate adapter remains pinned to the older `a65a2853ccae13da167d9aa4720ab8b11ec16656` profile; this d1a58 replay is a separate source-bound review artifact and does not claim the current production CLI accepts d1a58.

## Witness and controls

Run from the scanner checkout:

```powershell
python research/deliveries/c-line/typedarray_set_d1a58_source_replay.py `
  --source-repo D:\openHarmonyScanner\tmp\arkruntime-d1a58d5 `
  --json-out research/deliveries/c-line/typedarray_set_d1a58_source_replay_20261021.json
node research/deliveries/c-line/typedarray_set_boundary_harness_20261021.js
python -m unittest tests.detectors.ark_runtime.test_arraylike_set_bounds -v
```

Witness values: binary64 Number offset `18446744073709549568` (`2^64 - 2048`), source length `4096`, target view byte offset `4096`, target length `4096`, backing length `8192`, element size `1`. The source guard's unsigned sum wraps to `2048`, which passes the length check. The narrowed backing-relative write interval is `[2048, 6144)`: `[2048,4096)` is outside the target view but observable through a sibling view; `[4096,6144)` is inside the target view. The full interval remains inside the backing allocation.

The old-source arithmetic model ran and observed the 2,048-byte sibling-view mutation. An overflow-safe subtraction-guard control rejected before writes. In-range offset zero succeeded; a non-wrapping one-past range raised `RangeError`. Node/V8's native `TypedArray.prototype.set` control converted the offset object once, read the array-like length once, raised `RangeError`, read no indexed elements, and left the backing buffer unchanged. These are a component arithmetic harness and a separate ECMAScript-engine control, **not Ark Runtime execution**.

Existing exact-profile replay was reviewed in `typedarray_set_arraylike_independent_replay_20261020.md`: a65 positive candidate, wrong repository/commit, missing/mutated helper, incomplete profile, and arithmetic controls were checked; detector tests preserve fail-closed identity behavior. The focused rule suite reran for closeout: **11 passed**; full output and exit marker are in [detector regression evidence](runtime_evidence_20261021/detector_regression_11.log). It validates the detector's a65 profile and candidate shape; it does not bind d1a58 into that production rule.

## Severity, affected boundary, and remediation

Severity is **unscored**. If a caller relies on separate views of a shared ArrayBuffer as an isolation boundary, the modeled behavior could corrupt data before the requested view. The current evidence does not prove runtime reachability, a security boundary crossing, a crash, an allocation-boundary access, code execution, or product exposure. The source-only impact hypothesis is therefore limited to a conditional cross-view write.

The source-supported version boundary is exact: the behavior is present in the reviewed a65 pin and persists in d1a58. No release tag, shipped product build, later fixed commit, or affected-product range has been established; version/product mapping remains unknown.

Recommended repair: reject `targetOffset > targetLength` before subtraction, then reject `srcLen > targetLength - targetOffset`. Compute byte start/end using checked wide arithmetic, and ensure the write interval is within both the target view and backing buffer before dispatching the store. Add regression cases for the wrapped offset, a nonzero-byteOffset target, offset zero, exactly-at-end with zero length, and one-past ranges.

## Verification state and limits

| Evidence | Result |
|---|---|
| d1a58 exact source-object/hash/AST replay | passed; 4 complete and 3 partial translation units |
| Old-source vs subtraction-guard component harness | passed; candidate witness and fixed control reproduced |
| Node/V8 language exception control | passed; `RangeError`, no indexed reads or writes |
| Focused OHScanner array-like Set detector tests | 11 passed |
| Ark Runtime build and VM execution | `not_run`; RK3568 stopped during GN product dependency resolution and host profile stopped in HB `set`; no VM artifact produced |
| Product impact, severity score, release range | `unknown` / unscored |

Reproduce source/hash/AST replay with [the Python replay script](typedarray_set_d1a58_source_replay.py), component behavior with [the JavaScript harness](typedarray_set_boundary_harness_20261021.js), and inspect machine output in [the harness JSON](typedarray_set_boundary_harness_20261021.json). No Ark Runtime source was modified.

## Ark Runtime build attempt (2026-10-21)

An isolated Linux/ext4 source copy was used to avoid the Windows-mounted source tree and preserve the active C-line checkout. The source was verified as a65 (`a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`); `builtins_typedarray.cpp` SHA-256 was `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c`. The independent d1a58 review confirms the relevant TypedArray.set path is unchanged; it also confirms the witness crosses the target view but stays inside the 8192-byte backing allocation.

RK3568 GN generation naturally exited 255 after source loading, because the product graph required unrelated `weex-loader` at `//base/global/system_resources/systemres/BUILD.gn:28`; earlier progressively copied missing product components included `advanced_ui_component`, `netmanager_ext/vpn_dialog`, and `parse5`, but this was not a complete RK product source tree. The complete HB log, GN diagnostic, and exit marker are in [RK3568 evidence](runtime_evidence_20261021/README.md#rk3568-profile).

The attempt then tried to select/prepare the official `host_product@ohemu` profile. HB stopped while importing its `set` module, before profile selection or GN: `build/hb/services/menu.py` imports `run_application` from `prompt_toolkit.shortcuts`, producing `ImportError: cannot import name 'run_application'`. HB reports error code 0000; the captured script wrapper naturally exited 255. No host GN files, Ninja manifest, `ark_js_vm`, or `es2abc` were produced. The full error and exit marker are in the [host selection evidence](runtime_evidence_20261021/README.md#host-profile-selection). This is a concrete HB/tool compatibility blocker, not a runtime result.

Candidate and safe-control execution on Ark Runtime therefore remain **not_run**. The prior arithmetic model and Node/V8 control are not Ark Runtime PoCs. The [closeout package README](runtime_evidence_20261021/README.md) indexes the source review, component harness, 11-test output, both natural build blockers, reproduced commands, and SHA-256 manifest. Product impact remains unknown and severity unscored.
