# Float32Array negative-TDouble isolated runtime investigation

Date: 2026-10-20 (Asia/Shanghai)
Outcome: **not_run — no usable local Ark Runtime executable or build toolchain/profile was found.** The exact public source tree is available and matches the candidate source pins, so this is an evidence-based environment/build-feasibility result, not a conclusion that the source candidate is unreachable or safe. No production source, detector, shared service, task tree, or source checkout was modified.

## Scope and source identity

Inspected the local OHOS 5.0.0 / 5.0.1-era component checkout at `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`:

- repository HEAD: `a65a2853ccae13da167d9aa4720ab8b11ec16656` (`master...origin/master`)
- checkout status: clean (`git status --porcelain=v1` empty)
- `ecmascript/compiler/common_stubs.cpp`: blob `6267f2f27a98a298b1190e327abbfa2bd58203f8`
- `ecmascript/compiler/typed_hcr_lowering.cpp`: blob `1ad4e329a226fc9941db30fa7a10a6562f58f68d`
- `ecmascript/compiler/new_object_stub_builder.cpp`: blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`
- additional arithmetic/layout source inspected: `ecmascript/compiler/stub_builder-inl.h`, SHA-256 `1ad0f3b58c4e1f40920295464c76e9ea97bfc2f6853b57f798911b2ecf4dc04c`; `ecmascript/byte_array.h`, SHA-256 `c5499e4bd0d6c7b5b2f2aed1950d668f708caf34059577a698dd844476bb522f`.

These first three Git blob IDs exactly match the candidate's existing scout report. The exact source reconfirms both negative lower-bound gaps, `NewFloat32ArrayWithSize` forwarding signed `size` into `NewByteArray`, pointer-width zero-extension of element size and length, and storage of signed int32-derived view metadata.

## Build/runtime inventory

- Searched tracked workspace files and all of `D:\OpenHarmony807` for `ark_js_vm`, `ark_aot_compiler`, `libark_jsruntime.so/.dll/.dylib`, `build.ninja`, and `CMakeCache.txt`. No Ark executable/library or Ark build output was found. The few CMake/Ninja files found were third-party test fixtures.
- `D:\OpenHarmony807` is a collection of 787 component repositories plus manifests/logs; it has no top-level `.repo`, `build.sh`, or `out` directory. The Ark component repo has no `out` or `build` directory. Thus this is not a configured OHOS product build tree and no reusable Ark build profile is present.
- The source components include `arkcompiler_ets_runtime`, frontend, build scripts, and many third-party repositories, but no full compiler prebuilt/toolchain bundle was found; only `prebuilts_lite_sysroot` is present among the matching top-level component names.
- WSL2 Ubuntu is installed. Inside it, `gn`, `ninja`, `clang++`, `cmake`, `python3`, and `g++` are all missing from `PATH`. Windows also has no `gn`, `ninja`, or clang compiler command available. I did not install packages, generate build files, alter repositories, or start a full OHOS product build.
- Search and inventory transcript: `source_inventory.txt` in this directory.

## Source-derived arithmetic (not executed)

The pinned source computes `size = AlignUp(DATA_OFFSET + ZExtPtr(elementSize) * ZExtPtr(length), 8)`, where `DATA_OFFSET` is the empty ByteArray size and is 16 in the inspected source layout. For the candidate `length = int32(-1)` and `elementSize = 4`:

| Pointer width | Requested aligned allocation size | `end = TruncPtrToInt32(size)` | Initializer interval | Predicted metadata if allocation succeeds |
|---|---:|---:|---|---|
| 64-bit | `0x400000010` = 17,179,869,200 bytes | `16` | `[16,16)` (empty) | Float32Array `length=0xffffffff`, `byteLength=0xfffffffc`; ByteArray array length `0xffffffff`, byte length (element size) `4` |
| 32-bit | `0x10` = 16 bytes after pointer-width wrap/alignment | `16` | `[16,16)` (empty) | same wrapped int32/uint32 metadata |

`NewByteArray` calls the allocator before initialization. `InitializeWithSpeicalValue(start=DATA_OFFSET,end=TruncPtrToInt32(size))` therefore has an empty interval in these calculations; this is **not** an observed or predicted initialization overwrite. On 64-bit the allocator may reject/exception on the very large request. On 32-bit, if the 16-byte allocation succeeds, the stored length metadata would greatly exceed the backing payload. These are static calculations from the pinned source and C integer/pointer width semantics, not observations from a built runtime.

`ByteArray::GetData(index)` forms `this + DATA_OFFSET + index * GetByteLength()`, while `GetPointerLength` computes aligned payload slots from stored metadata. This suggests paths needing dispatch-specific analysis, but without a runtime cannot determine what a JS indexed read/write does after construction, whether fast access is selected, or whether object metadata remains observable. I did **not** infer an out-of-bounds access or claim a confirmed memory-safety issue.

## Requested test matrix status

| Case | Status | Why |
|---|---|---|
| `new Float32Array(Math.ceil(-1.1))` / negative integral TDouble | `not_run` | no Ark VM/frontend executable and no configured build environment |
| `new Float32Array(-1)` tagged-int negative control | `not_run` | same |
| `new Float32Array(Math.ceil(1.1))` positive integral TDouble control | `not_run` | same |
| `new Float32Array(Math.ceil(-0.1))` negative-zero normalization | `not_run` | same |
| Returned-object metadata, allocation outcome, and later indexed get/set | `not_run` | requires construction in the compiled runtime |
| 32-bit / 64-bit runtime behavior | `not_run` | neither architecture-specific binary/profile exists locally |

No JS-engine substitute was used; it would not identify the Ark representation/tag or stub selection. No PoC was launched and there are no runtime stdout/stderr logs because no executable was available.

## Executable next step

Create a Linux build host/container that has the complete matching OpenHarmony source root (including `.repo` manifest checkout and configured `out`), `gn`, Ninja, matching Clang prebuilts, Ark frontend, and required prebuilts; build the host `ark_js_vm`/frontend for this exact runtime SHA in a scratch output tree. Add temporary diagnostic logging (kept only in an isolated source copy or patch) at the CommonStub/TypedHCR branch, `NewFloat32ArrayWithSize`, `NewByteArray` immediately before/after allocation, and typed-array indexed access dispatch. Run the four-case matrix first on 64-bit, capture allocator result and language-visible metadata/get/set behavior; then repeat only if a 32-bit host build/toolchain is actually available. Keep the candidate conditional until those runtime observations exist.
