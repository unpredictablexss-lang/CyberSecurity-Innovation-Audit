# T67 inventory of saved D50 parse coverage

## Saved D50 state

The saved artifact `research/data_sensitive/D50_COMPONENT_CVE_REPLAY/pasteboard.json` records 67 C++ parse rows: 57 `complete` and 10 `partial`. Its aggregate also records one TypeScript `not_run` status, for 68 selected source files overall. The detector's per-file coverage is `partial` for all 67 applicable C++ files; it reports zero fully analyzed files. This inventory reports parser states and artifact limitations, not security coverage.

| D50 partial file | Saved issue rows | Reported lines and issue kinds |
| --- | ---: | --- |
| `interfaces/kits/napi/src/napi_init.cpp` | 2 | 26 error; 42 error |
| `services/core/include/i_pasteboard_observer.h` | 1 | 30 error |
| `services/core/include/i_pasteboard_service.h` | 1 | 43 error |
| `services/core/include/pasteboard_service.h` | 2 | 52 missing; 53 missing |
| `services/core/src/pasteboard_storage.cpp` | 1 | 88 error |
| `services/test/unittest/src/paste_service_test.cpp` | 9 | 60, 83, 94, 105, 117, 130, 152, 175, 198 missing |
| `services/zidl/include/pasteboard_observer_stub.h` | 1 | 34 missing |
| `services/zidl/include/pasteboard_service_stub.h` | 1 | 35 missing |
| `services/zidl/src/pasteboard_observer_stub.cpp` | 1 | 46 error |
| `services/zidl/src/pasteboard_service_stub.cpp` | 1 | 58 error |

Every row is labeled `analysis_status=partial` and `analysis_reason=detector_model_incomplete`. The artifact stores only JSON strings with `kind`, `start_line`, and `end_line`; it has no parser diagnostic text, node type, columns, source excerpt, or recovery context. Therefore the saved evidence cannot establish the underlying syntax cause or whether a particular file is repairable. `error` versus `missing` is preserved as the artifact's issue kind only, not interpreted as root cause.

## The `not_run` boundary

D50 aggregates `cpp: 67`, `ts: 1`, and `not_run: 1`, but its `scope.declared_scope` is just `["."]`; the run has 67 parse rows and no `not_run` row or per-file TypeScript diagnostic. The exact TypeScript path is therefore not recoverable from the D50 artifact alone. The later D68 exact-source replay identifies the one TypeScript declaration as `interfaces/declaration/api/@ohos.pasteboard.d.ts`; that later evidence identifies the path in the pinned source tree but does not retroactively add a D50 per-file parser record.

D50 recorded tree-sitter 0.26.0, tree-sitter-c 0.24.2, and tree-sitter-cpp 0.23.4, with JavaScript and TypeScript grammars unavailable. Its declared Python runtime is 3.10.12. On this machine, Python 3.10.11 is available but has no `tree_sitter` module, so the exact Python 3.10.12 run cannot be recreated here. Python 3.13.9 has the same declared C/C++ tree-sitter package versions; its D68 replay reports 59 complete and 8 partial C++ files. Two D50 partial files become complete there: `services/zidl/src/pasteboard_observer_stub.cpp` and `services/zidl/src/pasteboard_service_stub.cpp`. This is a current-runtime status difference, not a historical D50 rerun or proof that parser/runtime version alone caused the difference.

## Assessment

The artifact is sufficient to reproduce the list of ten partial files, their saved line locations and issue-kind labels, aggregate parser counts, and the two candidate identities. It is insufficient to independently diagnose the parse failures, confirm their fixability, inspect the one D50 `not_run` file by its saved path, or reconstruct exact D50 Python 3.10.12 behavior. A richer historical artifact would need the per-file not-run row and parser diagnostics with columns/error text or syntax-node context. Until then, preserve D50 as 57 complete / 10 partial / 1 not_run and treat D68's 59 / 8 / 1 as a separate replay.
