# D80 integrated second-layer review: D52 GET_PASTE_DATA candidate

## Decision

**Retain D52 as a narrow source-only candidate, with an explicit historical parser-coverage blocker on the dispatch edge.** Do not downgrade the hash-pinned source observation merely because D50's AST is partial: the source text and blobs independently establish the literal route and the bounded absence of an in-component caller read-permission predicate. But do not describe the complete historical route as parser-derived: D50 `pasteboard_service_stub.cpp` has `ERROR:58` on the actual `(this->*memberFunc)(data, reply)` dispatch expression, and the interface and stub header are also partial. D68's later `complete` status cannot repair D50's historical evidence.

The safe candidate statement is: **in `openharmony/miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840` (tree `e374a0d61c9ec664ddd29fc17002797828c480ee`), hash-pinned component source text traces GET_PASTE_DATA from selector mapping through the stub handler to per-user core lookup/copy, with no explicit caller read-permission predicate visible in that component path before the data lookup/copy. The historical D50 parser does not establish the dispatch-to-handler AST edge.** Keep product authorization, reachability, vulnerability, and CVE causality **unknown**.

This is a source-candidate disposition, not a scanner-rule change, product verdict, or confirmation that a request can retrieve data without authorization.

## Evidence layers kept separate

### Source-text evidence: supported, hash-bound

D79/T79 independently bind the six route files to raw Git blob IDs and SHA-256 values at the D52 commit/tree. The source shows `GET_PASTE_DATA = 0`; client forwarding; proxy `SendRequest`; stub map entry to `OnGetPasteData`; the `OnRemoteRequest` member-pointer dispatch expression; handler call/reply serialization; and the core `GetPasteData` per-user lookup/copy. D52's candidate line 41 is the opening brace of `OnRemoteRequest`, a method-entry location rather than the selector map, guard, dispatch, or sink.

The bounded “no visible local read-permission predicate” claim is a direct source review of the pinned component route. Caller PID/UID logging, interface-token validation, per-user mapping, invalid-user handling, and absent-clip handling are not read-permission checks. The old helper/mock `true` implementations are real source facts, but the pinned route has no call site to them; they do not prove a reachable bypass. D74's later `distributeddatamgr_pasteboard` implementation is a distinct snapshot and cannot be projected backward onto D52.

### Parser-derived evidence: incomplete at material edge

| Route file | D50 historical | D68 later runtime | Review consequence |
|---|---|---|---|
| `services/core/include/i_pasteboard_service.h` | partial, ERROR 43 | partial, ERROR 43 | Error is on interface descriptor macro, not enum line 28 or method declaration line 37; the file still has no whole-file AST completeness guarantee. |
| `framework/innerkits/src/pasteboard_client.cpp` | complete | complete | Parser coverage supports this unit in those runs. |
| `services/zidl/src/pasteboard_service_proxy.cpp` | complete | complete | Parser coverage supports this unit in those runs. |
| `services/zidl/include/pasteboard_service_stub.h` | partial, MISSING 35 | partial, MISSING 35 | The missing node is in the pointer-to-member handler-map declaration. |
| `services/zidl/src/pasteboard_service_stub.cpp` | partial, ERROR 58 | complete | D50's error is exactly the member-pointer dispatch expression. The historical parser-derived dispatch-to-handler AST edge is not complete. D68 is a later Python 3.13.9/runtime-normalizer replay and cannot backfill D50. |
| `services/core/src/pasteboard_service.cpp` | complete | complete | Parser coverage supports this unit in those runs; it does not establish product behavior or semantic completeness. |

The D50 historical report retained 57 complete / 10 partial / 1 not run; D68 replay reports 59 complete / 8 partial / 1 not run. These are different runs and environments. D79's replay and T79's independent acceptance confirm that the diagnostic line and statuses are bound to the frozen inputs. The right representation is therefore **source-text route supported; historical parser-derived dispatch edge blocked/partial**, not “the source route is unknown” and not “the parser fully proves the route.”

## External policy review: D74–D78

D75 retains the narrow component observation and correctly leaves effective authorization unknown. D76/T76 distinguish SAMgr SA-profile parsing, `startup_init` service configuration, and AccessToken native-token construction. `permission` and `permission_acls` in init config feed the service process's own native token; they are not caller identities authorized to invoke Pasteboard. D52's XML profile is not input to the later SAMgr JSON parser. The component source does not prove how `profile/3701.xml` is installed as `/system/profile/pasteboard_service.xml`.

D77/T77 and D78/T78 add two conditional SAMgr acquisition/loading gates: `WITH_SELINUX`/`build_selinux` and `SUPPORT_PENGLAI_MODE`/`support_penglai_mode`, with PengLai runtime state and checker behavior. These gates apply to SAMgr get/check/load operations before returning/loading an SA; they do not automatically mediate each subsequent Binder method call on an already returned Pasteboard object. The PengLai helper is fail-open when its function pointer is null. T78 also confirms a material timing limit: `penglaiFunc_` static initialization and the stub constructor read `ohos.boot.minisys.mode` separately, and the source does not guarantee those reads are aligned or that the parameter is immutable.

These later framework sources increase the list of plausible external policy paths but are not bound to a D52 product. They neither disprove nor prove a D52 method-level authorization gap. Keep build flags, runtime parameter, loaded PengLai library/policy, SELinux policy, installed profile, and product identity unknown. D74/T74 and D75 also keep the later current Pasteboard snapshot separate from D52.

## D79/T79 integrity and replay

I reran the D79 replay against the frozen input paths. It passed all six route rows; checked the local SHA-256 and Git commit/tree bytes for D50, D67, D68, and D74; recomputed all six raw source blob IDs/SHA-256 values from the D52 Git objects; and rejected the whitespace-mutated D50 negative control. T79's accepted revision also records duplicate-JSON-key rejection and the initial D79 defect (a whitespace mutation had passed before input binding was added). The accepted revision is D79 `ab6bf538e81a06ef85a9353a8b8aa4ab9704d65a`, tree `24981ee9f31d2be1e244c422ebaacbffb8a74a9b`; T79 is `982c7c592f3716c0ffc942ec6cf289499cc6085f`, tree `77b46baedf5f12c97da551289415334714be640b`. Exact D79/T79 artifact SHA-256 values and all upstream pins are recorded in the companion JSON.

## Minimum missing evidence

1. To upgrade the **parser-derived** dispatch edge: the exact historical D50 runtime/parser output with AST evidence for the expression at stub.cpp:58, or a reproducible D50-era parser environment that demonstrates that node and its binding. D68 alone is not sufficient.
2. To resolve **effective authorization**: the exact target product fingerprint/build manifest and build args; final installed SA/init profiles plus the XML-to-installed-path mapping; matching SAMgr/init/AccessToken and generated IPC/framework sources; `build_selinux`, SELinux service-context/policy, `support_penglai_mode`, parameter lifecycle/value and checker library/policy; and the service-side Binder method authorization contract.
3. To establish **product impact**: on that exact image, an authorized/unauthorized caller matrix with caller identity and observed GET_PASTE_DATA result, correlated to the build and policy artifacts above.

Do not claim product vulnerability, product safety, attacker reachability, unrestricted/cross-user access, or CVE causality without those product-bound facts. No source scanner rules were modified in this review.

## Review status

D80 is a second-layer review pending independent T80 acceptance. T80 should independently verify the D79/T79 input artifact hashes and pinned source objects, the D50 line-58 intersection, the D68 chronology limit, and the D78 PengLai double-read/fail-open caveat. Any discrepancy should be returned for correction before this review is treated as frozen.
