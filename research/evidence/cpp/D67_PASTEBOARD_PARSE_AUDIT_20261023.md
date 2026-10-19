# D67 Pasteboard parse coverage audit

Status: `blocked_manifest` — no parser source change is justified by the available evidence.

## Scope and replay

The replay uses the exact Pasteboard source commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` and tree `e374a0d61c9ec664ddd29fc17002797828c480ee`. All 67 C++ source hashes match the frozen D50 evidence and the isolated source checkout. The declared scope has 68 files: 67 C++ units and the TypeScript declaration `interfaces/declaration/api/@ohos.pasteboard.d.ts`.

D50 records 57 C++ units complete, 10 partial, and the TypeScript unit not run. D68's replay under Python 3.13.9 records 59 complete, 8 partial, and one not run. Both parser environments report tree-sitter 0.26.0, tree-sitter-c 0.24.2, and tree-sitter-cpp 0.23.4; neither has a JavaScript or TypeScript grammar. D50 used Python 3.10.12. This machine has Python 3.10.11 but no tree-sitter packages, so the exact historical runtime cannot be reconstructed here.

The frozen D50 JSON contains only parser issue `kind` and start/end line, not parser error node type, column, message, or AST. The detailed node observations below are from the current runtime and must not be presented as historical D50 diagnostics. Under the current runtime, parsing all 67 files without the frozen D51 member-pointer normalizer reproduces every D50 per-file status and issue kind/line (`unnormalized_mismatches=[]`). That is direct evidence that the existing normalizer accounts for the two changed statuses in this replay; it does not prove the Python runtime had no effect.

## D50 partial units

| Source file | D50 issue(s) | Current replay | Current observation and disposition |
| --- | --- | --- | --- |
| `interfaces/kits/napi/src/napi_init.cpp` | ERROR 26, 42 | partial | Current ERROR nodes cover `napi_value` (line 26) and `_module` (line 42). Cause is unconfirmed; needs historical runtime and real N-API build flags. |
| `services/core/include/i_pasteboard_observer.h` | ERROR 30 | partial | Current ERROR covers the UTF-prefixed interface descriptor string in `DECLARE_INTERFACE_DESCRIPTOR`; macro expansion context is absent. |
| `services/core/include/i_pasteboard_service.h` | ERROR 43 | partial | Same descriptor macro shape; macro expansion context is absent. |
| `services/core/include/pasteboard_service.h` | MISSING 52, 53 | partial | Current MISSING `;` nodes follow `DECLARE_SYSTEM_ABILITY` and `DECLARE_DELAYED_SINGLETON`; resolve macros/preprocessed class body first. |
| `services/core/src/pasteboard_storage.cpp` | ERROR 88 | partial | Current ERROR covers `std::make_shared` in `std::make_shared PasteboardStorage(file)`; compile with project toolchain/config to establish whether source syntax or recovery is responsible. |
| `services/test/unittest/src/paste_service_test.cpp` | MISSING 60, 83, 94, 105, 117, 130, 152, 175, 198 | partial | Current MISSING `;` nodes follow `HWTEST_F` invocations; macro definition and test build flags are unavailable. |
| `services/zidl/include/pasteboard_observer_stub.h` | MISSING 34 | partial | Current MISSING `type_identifier` is within a pointer-to-member alias; requires a focused valid-declarator grammar fixture before considering normalization. |
| `services/zidl/include/pasteboard_service_stub.h` | MISSING 35 | partial | Same pointer-to-member alias shape; requires the same fixture and offset/line mapping validation. |
| `services/zidl/src/pasteboard_observer_stub.cpp` | ERROR 46 | complete | The D50 location is the `(this->*memberFunc)(...)` dispatch expression. Existing frozen offset-preserving D51 normalization parses it completely. No new repair proposed. |
| `services/zidl/src/pasteboard_service_stub.cpp` | ERROR 58 | complete | Same dispatch-expression shape; existing frozen D51 normalization parses it completely. No new repair proposed. |

The JSON evidence records current node type, column, parent, and bounded source excerpt for each currently partial unit, alongside the D50 issue record. Exact next dependencies are in its `blocked_manifest` entries.

## TypeScript boundary

`interfaces/declaration/api/@ohos.pasteboard.d.ts` is the one declared TypeScript unit. It is `not_run` in both reports because the TypeScript grammar/frontend is unavailable. It is not a C++ parse failure and is not included in the 67-unit C++ parser comparison. Re-run after installing and pinning a TypeScript frontend.

## Decision and limits

No new parser fix is made: the remaining eight current partials involve unavailable macro/build context, an unverified source construct, or a grammar form that needs an isolated fixture. The two zidl status differences are already explained by a frozen normalizer, and the current-runtime ablation reproduces the full D50 status signature. Without Python 3.10.12 and the original execution environment, this audit cannot establish the exact historical cause for every D50 diagnostic. `analysis_reason=detector_model_incomplete` in D50 is detector coverage metadata, not a parser error cause.

This is a parsing coverage audit only. It does not change or reinterpret D51/D52 candidate identities, anchors, hashes, D65 evidence obligations, or product conclusions. In particular, the existing Pasteboard CVE candidates remain source-only; CVE causality and product applicability are unknown. No coverage increase or historical D50 improvement is claimed.

Machine-readable evidence: [D67 JSON audit](D67_PASTEBOARD_PARSE_AUDIT_20261023.json), generated by [audit script](D67_pasteboard_parse_audit.py).
