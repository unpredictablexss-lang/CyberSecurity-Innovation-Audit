# D50 — ability_ability_base `UserObject::value_` CR-0314 source-bound assessment

> Static candidate replay and source review only. This is not a product vulnerability confirmation or a safety verdict.

## Result

CR-0314 remains `not_testable / paused_pending_evidence`, **PARTIAL/BLOCK**. The current production `shared_ptr_race` detector (0.5.1) parsed the exact A0 target header completely and emitted no finding, including at A0 line 25. No concrete detector gap or unsynchronized same-member write/read pair was reproduced, so no rule change is justified.

`UserObject::value_` is initialized in the constructor and declared with a null in-class default initializer. In the pinned implementation, `GetValue`, `Equals`, and `ToString` read the member; there is no post-construction assignment to this member in `user_object_wrapper.cpp`. `GetValue` copies the shared pointer into its caller-provided output. The two null checks and the equality/string reads are also reads of the member. No mutex or atomic is present around the field, but this source does not show a write racing those reads. The wrapped `UserObjectBase` object's own mutable state and virtual methods are a separate question and are not established by this A0 holder-field candidate.

The pinned root `BUILD.gn` includes `user_object_wrapper.cpp` in `ohos_shared_library("base")`. Within this component, `PacMap::PutObject` acquires `mapLock_` while constructing/storing the wrapper, and `PacMap::GetObject` acquires the same lock while unboxing it. This establishes the lock scope for those `PacMap` paths only; it does not establish behavior for external `IUserObject` callers or use after `GetObject` returns. The pinned unit-test BUILD registers `user_object_wrapper_test` as an `ohos_unittest`; these tests do not establish product concurrency. Exact product profile/image inclusion, downstream calling topology, same-object cross-thread use, and runtime impact remain unknown. No trusted fixed source or target-derived concurrent harness is bound. A quiet detector result is not treated as a safe result.

## Source binding

| Item | Pinned identity |
|---|---|
| A0 row | CR-0314; `not_testable / paused_pending_evidence` |
| Repository | `openharmony/ability_ability_base` |
| Commit / tree | `eaeaa31a6d07cf74fdec1c4e48dfe19c64e25cae` / `678c1c3a52e810919cc591b010cde7f97ff4d23c` |
| A0 snapshot SHA-256 | `088feb3c9186b35dfc9dc3eb52732cd5bfe1df0786b83e63e529909111160886` |
| Target | `interfaces/inner_api/base/include/user_object_wrapper.h:25` |
| Target blob / SHA-256 | `95ffabb86645db1109526e4a388f206d310a138e` / `842a7ca8d07d419dff53521ab502cd5de8880c50052d48d9c8f1e679d47e91dc` |
| Implementation blob | `interfaces/inner_api/base/src/user_object_wrapper.cpp` / `716ea7ded87b8808ee5e4c03468e9b76e77a4bfc` |

The evidence script also binds the implementation, `PacMap` call context, root library BUILD, unit-test BUILD, and wrapper test source by blob and SHA-256. The full A0 candidate queue contains 345 rows; the original CR-0314 status fields were checked and left unchanged.

## Current scanner replay

| Detector | Version | Scope | Parse | Result |
|---|---:|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | 0.5.1 | Exact A0 header, one file | Complete | Completed, 0 findings |

The exact A0 line was a constructor initializer under the historical proposed rule `ohcpp-shared-ptr-race-candidate-001` (`0.2.0-proposed`). That historical syntax candidate is not reproduced by the current detector. The source review does not identify a root race the current detector should have reported: initialization precedes ordinary object publication, and the pinned implementation contains no subsequent assignment to the holder member.

## Remaining evidence

- Bind the product GN profile and image that include the `base` target.
- Identify downstream call sites and establish whether the same `UserObject` instance can be read concurrently and how its lifetime is synchronized.
- If a concrete concurrent mutable access is found, provide a target-derived reproduction and a trustworthy fixed/control source. None is currently available.
- Do not infer product safety, a false-positive adjudication, or CWE-362 from either the historical syntax line or the current zero-finding replay.

## Reproduction

From the scanner checkout, with the exact local source Git object store available:

```powershell
D:\openHarmonyScanner\.venv-c-line\Scripts\python.exe `
  research\evidence\cpp\d50_ability_user_object_wrapper_20261028.py `
  --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\ability_ability_base.git `
  --output research\evidence\cpp\d50_ability_user_object_wrapper_20261028.json
```

The replay script verifies the A0 row count and source identity, parses and runs the current detector on the exact target, checks the implementation/PacMap lock path/build/test bindings and confirms there is no implementation assignment to `value_`. See the [machine-readable replay](d50_ability_user_object_wrapper_20261028.json).
