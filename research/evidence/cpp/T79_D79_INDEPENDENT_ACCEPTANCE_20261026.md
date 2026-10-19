# T79 independent acceptance of D79 parse coverage crosswalk

Status: **ACCEPTED** for the bounded source/parser coverage artifact.

## Frozen inputs and replay

- D79 base: `755c367cfe0c0bfab07d6c3d9cd90f6fd6c3fb5c`.
- D79 revision accepted: `ab6bf538e81a06ef85a9353a8b8aa4ab9704d65a` (tree `24981ee9f31d2be1e244c422ebaacbffb8a74a9b`).
- Pasteboard source: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- D50 evidence commit: `0f4560c4712dbf914d762948e2220942f16324ad`; D67: `ef215e737daee00c9fa659d14cd273974cf4fc2f`; D68: `3da049887999bd3cacb3d48da9ffa7baefa18ac5`; D74: `a29275f7a795da17171fd3df2c712ef3a8576cb7`.

The revised replay passed against those frozen inputs. It verified the local SHA-256 and Git commit/tree/blob bytes for all four evidence files, and verified six raw source blobs from the pinned Pasteboard commit. The independently recomputed route identities matched D79, D67, and D74:

| File | Blob | SHA-256 |
|---|---|---|
| `services/core/include/i_pasteboard_service.h` | `1a5b83f314d6188f0b3465a13ac1668cb9933839` | `ffef3626d4dcd2d0757381e64e652a8a023d352dd59bc9afa20deafb2fd8e3fc` |
| `framework/innerkits/src/pasteboard_client.cpp` | `c204c426cff25c7ee637068143ecaaccc98614ec` | `ace24f733b0f0590c8a3d2b723dc41fda8ea80dfd9cfdf99bcb7d9699c20598a` |
| `services/zidl/src/pasteboard_service_proxy.cpp` | `679117492f1207fc9aa424899daa143d4df07249` | `61f66fbbe53a1190ec31a8ff34b41a0d6b3ea28cdea72df8f0d3bc921d21f600` |
| `services/zidl/include/pasteboard_service_stub.h` | `67b267c6e68b8e3bd49c68958d46951c6be76929` | `d949deeb769a8b96b88d0548b665039c6c3ec9c30d9dc6ff43eefec7ebc256ec` |
| `services/zidl/src/pasteboard_service_stub.cpp` | `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b` | `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868` |
| `services/core/src/pasteboard_service.cpp` | `c380ac266a85edd818caa811f11b99722d351788` | `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52` |

The D50 and D68 per-file statuses and issue lines match the frozen parse reports. In particular, `i_pasteboard_service.h` is partial with ERROR 43 (the descriptor macro, away from enum line 28 and method declaration line 37); `pasteboard_service_stub.h` is partial with MISSING 35 in the pointer-to-member handler type; and `pasteboard_service_stub.cpp` is D50 partial with ERROR 58 exactly at `(this->*memberFunc)(data, reply)`, while D68 is complete. D68's newer runtime/normalizer result is not back-projected into D50.

## Source evidence and parser-derived coverage

The hash-pinned source text and D74 line trace show the GET_PASTE_DATA enum, forwarding/proxy transaction, map assignment, dispatch expression, handler, and core getter. D50's parse error is on the dispatch expression itself, so D50 parser-derived evidence does not establish a complete AST dispatch-to-handler edge. A partial diagnostic outside a specific source line also cannot establish whole-file AST completeness. The crosswalk keeps these claims separate and preserves the historical limitation.

## Negative controls and initial feedback

The initial D79 commit's replay accepted a D50 file with an appended whitespace byte because it did not enforce the listed evidence input hashes. T79 reported that concrete counterexample. D79 revision `ab6bf538e81a06ef85a9353a8b8aa4ab9704d65a` added local SHA and Git snapshot checks plus direct raw source blob checks. On the revised script, the exact replay passed and the independently repeated whitespace-mutated D50 input failed with `local input SHA-256 mismatch`. The script's duplicate-key loader also rejected a focused duplicate-key JSON control. `git diff --check HEAD^ HEAD` passed for the accepted revision; the T79 worktree was clean before this report was added.

## Conclusion boundary

Acceptance covers source identity and the parser coverage crosswalk only. It does not validate a product vulnerability, product reachability, external authorization policy, CVE causality, or the completeness of the historical D50 AST at the dispatch. D52 remains a narrow source-only candidate.

## Reproduction

Run `D79_d52_parse_coverage_replay.py` with the four evidence JSON paths and `--d52-git-dir` pointing to the pinned source repository's Git directory. The exact commands and paths are environment-specific; the replay output records the six raw source blobs and four evidence snapshot bindings.
