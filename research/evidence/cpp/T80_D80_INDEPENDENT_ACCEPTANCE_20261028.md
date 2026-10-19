# T80 independent acceptance — D80 integrated D52 candidate review

## Verdict

**ACCEPTED_WITH_LIMITATIONS.** D80 accurately keeps the D52 observation narrow and source-only while identifying the historical D50 dispatch AST edge as incomplete. No material source, parser, or scope mismatch was found after an independent replay and source-object rehash.

## Independent identity and replay checks

- D80 frozen revision: `717cefbe384b134f0c891e1a7c7cef28d359139b`, tree `f5c57d29fb9bc53580c5810c04299a7c25be7b75`.
- Strict JSON parsing with duplicate-key rejection passed for the D80 companion JSON. A duplicate-key negative control was rejected.
- Independently resolved every one of the 13 evidence artifact commit/tree pairs listed in D80 JSON and rehashed all 26 report JSON/Markdown Git blobs. All matched. D80's initial summary said 12/24; the accepted revision corrects this to 13/26.
- Cloned the source repository independently from `https://gitcode.com/openharmony/miscservices_pasteboard.git` into `D:/openHarmonyScanner/worktrees/t80-independent-miscservices-pasteboard.git`. The clone contains D52 commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` and tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Replayed `D79_d52_parse_coverage_replay.py` with the frozen D50/D67/D68/D74 JSON evidence and the independent source clone. Result: six route rows, four evidence input bindings, and six raw source blobs verified; appended-whitespace D50 negative control rejected. The output also confirms D50 stub.cpp ERROR:58 intersects the member-pointer dispatch expression.

The six independently recomputed D52 source identities match D79/T79 and D80:

| Path | Git blob | SHA-256 |
|---|---|---|
| `services/core/include/i_pasteboard_service.h` | `1a5b83f314d6188f0b3465a13ac1668cb9933839` | `ffef3626d4dcd2d0757381e64e652a8a023d352dd59bc9afa20deafb2fd8e3fc` |
| `framework/innerkits/src/pasteboard_client.cpp` | `c204c426cff25c7ee637068143ecaaccc98614ec` | `ace24f733b0f0590c8a3d2b723dc41fda8ea80dfd9cfdf99bcb7d9699c20598a` |
| `services/zidl/src/pasteboard_service_proxy.cpp` | `679117492f1207fc9aa424899daa143d4df07249` | `61f66fbbe53a1190ec31a8ff34b41a0d6b3ea28cdea72df8f0d3bc921d21f600` |
| `services/zidl/include/pasteboard_service_stub.h` | `67b267c6e68b8e3bd49c68958d46951c6be76929` | `d949deeb769a8b96b88d0548b665039c6c3ec9c30d9dc6ff43eefec7ebc256ec` |
| `services/zidl/src/pasteboard_service_stub.cpp` | `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` | `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| `services/core/src/pasteboard_service.cpp` | `c380ac266a85edd818caa811f11b99722d351788` | `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |

## Claim-boundary review

- D50 records `partial / ERROR:58` for `pasteboard_service_stub.cpp`; the independently fetched pinned bytes show line 58 is `(this->*memberFunc)(data, reply)`. This intersects the actual dispatch expression. D68 reports `complete` in a later runtime/normalizer replay and cannot repair D50's historical AST evidence.
- D50's interface header `ERROR:43` and stub header `MISSING:35` remain partial. The D79 route table preserves these issues and correctly separates parser coverage from source-text citations.
- The hash-pinned source text supports the bounded route observation from selector mapping through handler to per-user core lookup/copy. Candidate line 41 is the `OnRemoteRequest` method entry. No explicit caller read-permission predicate is visible in that pinned component path before lookup/copy. This does not establish system-wide absence of authorization.
- T78's accepted evidence supports the conditional SAMgr `WITH_SELINUX` and `SUPPORT_PENGLAI_MODE` acquisition/loading gates. The PengLai static `penglaiFunc_` initialization and stub-constructor `isPengLai_` each read `ohos.boot.minisys.mode`; source does not guarantee the reads align or the parameter is immutable. A null checker pointer fails open. These checks cover the described SAMgr get/check/load operations, not every later Binder call on an already returned Pasteboard object.
- Product binding remains unknown: exact product build, installed profile mapping, flags, runtime parameter/library/policy, SELinux policy, and service-side caller authorization are absent. No product vulnerability, safety, reachability, or CVE causality conclusion follows.

## Reproduction

```powershell
python 'D:\openHarmonyScanner\worktrees\d79-candidate-coverage-crosswalk-20261026esearch\evidence\cpp\D79_d52_parse_coverage_replay.py' --d50 'D:\openHarmonyScanner\worktrees\d79-candidate-coverage-crosswalk-20261026esearch\data_sensitive\D50_COMPONENT_CVE_REPLAY\pasteboard.json' --d67 'D:\openHarmonyScanner\worktrees\d67-pasteboard-parse-coverage-20261023esearch\evidence\cpp\D67_PASTEBOARD_PARSE_AUDIT_20261023.json' --d68 'D:\openHarmonyScanner\worktrees\d74-pasteboard-cross-layer-trace-20261023esearch\evidence\cpp\D68_PASTEBOARD_RAW67_REPLAY_20261023.json' --d74 'D:\openHarmonyScanner\worktrees\d74-pasteboard-cross-layer-trace-20261023esearch\evidence\cpp\D74_PASTEBOARD_SOURCE_TRACE_20261020.json' --expected 'D:\openHarmonyScanner\worktrees\d79-candidate-coverage-crosswalk-20261026esearch\evidence\cpp\D79_D52_GET_PASTE_DATA_PARSE_COVERAGE_20261026.json' --d52-git-dir 'D:\openHarmonyScanner\worktrees	80-independent-miscservices-pasteboard.git'
```

`git diff --check` passes for the D80 accepted revision. D80 changes no scanner/source code and retains the exact unknown product boundary.
