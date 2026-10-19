# D79 D52 GET_PASTE_DATA parse coverage crosswalk

Source: `openharmony/miscservices_pasteboard@dd22c7cb5e5f207a6c38c50f45b7369ee8575840`; tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; snapshot SHA-256 `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.

Evidence inputs are pinned by commit, path and SHA-256 in the JSON. D50 is the historical run; D68 is a later current-runtime replay on the same source snapshot.

| Route unit | Source anchor | D50 historical | D68 current runtime | Source SHA-256 |
|---|---|---|---|---|
| `services/core/include/i_pasteboard_service.h`<br>interface enum and abstract method | GET_PASTE_DATA = 0 at 28; GetPasteData declaration at 37 | partial — error:43-43 | partial — error:43-43 | `ffef3626d4dcd2d0757381e64e652a8a023d352dd59bc9afa20deafb2fd8e3fc` |
| `framework/innerkits/src/pasteboard_client.cpp`<br>framework client forwarding | GetPasteData forwarding at 113-126 | complete | complete | `ace24f733b0f0590c8a3d2b723dc41fda8ea80dfd9cfdf99bcb7d9699c20598a` |
| `services/zidl/src/pasteboard_service_proxy.cpp`<br>Binder proxy transaction | GetPasteData and SendRequest(GET_PASTE_DATA) at 147-156 | complete | complete | `61f66fbbe53a1190ec31a8ff34b41a0d6b3ea28cdea72df8f0d3bc921d21f600` |
| `services/zidl/include/pasteboard_service_stub.h`<br>stub dispatch declaration | pointer-to-member handler map declaration; D50/D68 issue at 35 | partial — missing:35-35 | partial — missing:35-35 | `d949deeb769a8b96b88d0548b665039c6c3ec9c30d9dc6ff43eefec7ebc256ec` |
| `services/zidl/src/pasteboard_service_stub.cpp`<br>stub mapping, request dispatch and handler | map GET_PASTE_DATA to OnGetPasteData at 27; OnRemoteRequest at 39-57; handler at 73-78; D52 candidate anchor at 41 | partial — error:58-58 | complete | `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| `services/core/src/pasteboard_service.cpp`<br>core user mapping and paste read | GetPasteData entry at 155 onward; user id at 159; user/data lookup and copying in this method (D74 source trace) | complete | complete | `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |

## Critical partial intersections

- `i_pasteboard_service.h`: D50/D68 `partial`, `ERROR:43` is the interface-descriptor macro argument. It does not intersect `GET_PASTE_DATA = 0` at line 28 or `GetPasteData` declaration at line 37, but the file-level partial status still means no whole-file AST completeness claim.
- `pasteboard_service_stub.h`: D50/D68 `partial`, `MISSING:35` lies in the pointer-to-member map declaration. Treat dispatch declaration AST as partial.
- `pasteboard_service_stub.cpp`: D50 `partial`, `ERROR:58` is exactly `(this->*memberFunc)(data, reply)`, the actual member-pointer dispatch call. This is the material historical limitation: D50 parser-derived AST does not fully establish the dispatch-to-handler edge. D68 reports `complete` on current Python 3.13.9 runtime with frozen normalization; that result cannot be back-projected into D50.
- Client, proxy, and core implementation units are `complete` in both runs. This supports parser coverage of those translation units as reported, not semantic completeness or product behavior.

## Source evidence vs parser evidence

The source tree is pinned by commit/tree and each route file by SHA-256; D74 records source line excerpts and blob OIDs for all cross-layer route files except the stub header (whose SHA-256 is still pinned in D67). Direct source inspection can establish that the literal enum, forwarding call, transaction code, map assignment, dispatch expression, and handler call/body are present. The D50 partial parse specifically prevents claiming a fully parser-derived control-flow edge at the dispatch expression. A visible line is not proof of parser coverage. Conversely, a partial parse does not invalidate the hash-pinned source text.

## Limit of conclusion

This map is source-only. It does not establish a product vulnerability, caller reachability in a product, absence of external platform authorization, or CVE causality. Keep the D52 candidate narrow and preserve the D50 dispatch-AST caveat for downstream second-layer review.

## Replay

Run `python D79_d52_parse_coverage_replay.py --d50 <D50-pasteboard.json> --d67 <D67-audit.json> --d68 <D68-replay.json> --d74 <D74-source-trace.json> --expected D79_D52_GET_PASTE_DATA_PARSE_COVERAGE_20261026.json`. The script rejects duplicate JSON keys and fails on any bound source/status/issue mismatch.
