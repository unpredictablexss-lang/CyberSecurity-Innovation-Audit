# D58 — Pasteboard frozen-rule replay

Date: 2026-10-20 (Asia/Shanghai)

## Scope and result

Read-only replay of the exact D50 Pasteboard component snapshot against the D52 baseline rule `ohscanner.known_disclosed_cves@0.18.0` and D51 frozen rule `@0.19.3`. Also replayed the exact D52 Binder stub unit and local positive/negative boundary controls. Only this D58 Markdown and strict JSON evidence packet were added. No scanner source, detector, fixture, test, or prior report was changed.

The exact 0.18.0 and 0.19.3 full-component runs both return `blocked` with two candidates. D51's observer candidate anchor moves from the old method opening (line 222) to the set insertion (line 241, column 5). D52's candidate is unchanged: `CVE-2025-27247`, `services/zidl/src/pasteboard_service_stub.cpp:41:1`, with the same source SHA-256 and rule ID. The exact D52 stub-unit run also returns `blocked` in both versions and retains this candidate.

This establishes only rule replay behavior on the pinned component source. It does not establish CVE causality, product inclusion, a product vulnerability, or safety.

## Frozen identities

- Component: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, 94 tracked entries, D50 snapshot SHA-256 `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.
- D50 detector input: 67 C/C++ files; saved parser states for these units are 57 complete and 10 partial. The historical full scan reports detector status blocked and per-file detector analysis partial; the replay preserves those parser states. It does not claim improved parser or semantic coverage.
- Core source `services/core/src/pasteboard_service.cpp`: Git blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 stub `services/zidl/src/pasteboard_service_stub.cpp`: Git blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- 0.18.0 baseline checkout: `842948084660207fd64399cfd598ed93e5593dcc`; detector source blob `1a0a01624f7e6cf8abd1755c511ab26f149b6214`.
- D51 frozen rule checkout: `c8f83b82291e82b3272c73b943623336a3c836c3`; detector version `0.19.3`.

## Replay results

| Scope | Rule | Run | CVE-2025-25212 | CVE-2025-27247 | Identity / coverage |
|---|---|---|---|---|---|
| Full exact D50 C/C++ component (67 units) | 0.18.0 | blocked | `pasteboard_service.cpp:222:1` | `pasteboard_service_stub.cpp:41:1` | Both source hashes match; D50 detector coverage is partial |
| Full exact D50 C/C++ component (67 units) | 0.19.3 | blocked | `pasteboard_service.cpp:241:5` | `pasteboard_service_stub.cpp:41:1` | Same two rule IDs, symbols, file hashes; D52 location unchanged |
| Exact D52 stub unit (parse state partial) | 0.18.0 | blocked | — | `pasteboard_service_stub.cpp:41:1` | 1 unit analyzed; remaining coverage unknown |
| Exact D52 stub unit (parse state partial) | 0.19.3 | blocked | — | `pasteboard_service_stub.cpp:41:1` | Same rule/CVE/file/line/hash; remaining coverage unknown |
| Exact `OnRemoteRequest` body only | both | blocked | — | no finding | Focused body omits mapping and handler needed by this signature |
| Exact `OnGetPasteData` body only | both | blocked | — | no finding | Focused body omits request dispatch and mapping needed by this signature |

D52's existing 0.18.0 diagnostic packet gives the line-41 finding occurrence ID `ohocc:v1:7f174eb7bd5d4c7a0ccc07cd4e14601c972bdbb24e74499b253b18b2d3307336`. Its stable finding ID is unknown because the identity record is partial and has no AST fingerprint. D58 replays the detector findings themselves; it does not claim that this serialized occurrence ID was regenerated for 0.19.3.

## D52 rule-change and boundary review

The 0.19.3 delta changes the observer quota matcher and anchor. Inspection of the frozen 0.18.0 and 0.19.3 `CVE-2025-27247` matcher plus the paired exact replays shows no D52 rule delta: it still requires the `GET_PASTE_DATA` mapping, request routing, `OnGetPasteData` read-and-return shape, and no permission-like token in `OnRemoteRequest` or `OnGetPasteData`.

In the exact old snapshot, `OnRemoteRequest` validates the IPC interface descriptor, routes to `OnGetPasteData`, and that handler calls `GetPasteData` and writes the returned parcelable. The core getter `PasteboardService::GetPasteData` selects the caller's user clip and reads it without a visible permission decision in that function. However, the D52 rule does not inspect the core getter, helpers outside the two stub methods, inherited IPC/SystemAbility policy, or product ACL. The line-41 anchor is the opening brace of `OnRemoteRequest`, not the missing check or data-copy statement. D57's framework-boundary concern therefore remains valid: the candidate is a local heuristic, not proof that the complete authorization boundary permits an unauthorized read.

## Positive and negative controls

Controls were run in memory through each frozen detector implementation, without adding or executing tests:

- Positive: mapped/routed GET_PASTE_DATA calling `GetPasteData` and serializing without a local permission token — both versions emit CVE-2025-27247.
- Syntactic denial-branch control: the same route with `if (!VerifyCallingPermission(PERMISSION_READ_PASTEBOARD)) return ERR_NO_PERMISSION;` before `GetPasteData` — both versions suppress the candidate. The synthetic helper contract is not provided, so this verifies only the branch/exit shape, not real permission enforcement.
- Ignored-result risk: a bare `VerifyCallingPermission(PERMISSION_READ_PASTEBOARD);` before `GetPasteData` suppresses in both versions even though its result is ignored. The rule does not require a denying branch or early return.
- Ordering and reachability risks: a permission-like call after `GetPasteData`, after `WriteParcelable`, or inside `if (false) { ... }` each suppresses in both versions. These are not effective authorization guards; they show the matcher does not check order, branch reachability, or result use.
- Boundary gap: same unguarded stub route plus `CheckPastePermission()` only in core `GetPasteData` still emits CVE-2025-27247. A permission-like call in a separate helper also does not suppress unless the token occurs within the two checked methods. These controls show the local matcher’s lexical boundary; they do not establish the source authorization result.
- Unrelated: an unrelated method containing `GetPasteData` and `WriteParcelable` but no mapping/routing — both versions emit no CVE-2025-27247 candidate.

The controls establish only these lexical shapes; they do not prove completeness, framework authorization, caller reachability, or product impact. Both versions suppress on a bare ignored permission call before the read, on a permission token after the read or after serialization, and on a call inside an unreachable `if (false)` block. Only the explicit denial-branch pattern with an early return was used as a syntactic guard-shape control; no helper implementation or real permission contract was supplied. These results show the matcher does not establish result use, dominance, or branch reachability. D52’s exact pinned source has no such token in the checked methods, so these probes do not remove the reproduced source candidate; they mean the rule is under-guarded and must not be treated as a high-precision authorization verdict.

## Conclusion and limitations

- D52 line 41 is retained under 0.19.3 and is unaffected by the D51 rule change.
- Full component and focused-unit runs remain blocked; D50's detector coverage remains partial, and the focused stub parse input remains partial.
- Candidate identity is stable at the rule/CVE/file/source-hash/line level. The stable identity record remains unavailable; no 0.19.3 occurrence-ID continuity claim is made.
- The pinned source route and local omission support a narrow source-snapshot candidate only. The matcher is under-guarded by a demonstrated after-read suppression case. No CVE root-cause mapping, product status, fixed/vulnerable status, or runtime authorization result is inferred.
- No post-change full product scan, fixed-source replay, build fingerprint, product inclusion manifest, dynamic reproduction, or holdout-label result was produced.

## Reproduction commands

The first commands reproduce the immutable Git identities and hashes. The Python command replays D50's exact 67 C/C++ blobs with the saved D50 parser states against the baseline and frozen detector code; a second in-memory unit/control replay was run with the same API and exact stub file hash. Python did not write source, test, fixture, or report files during replay.

```powershell
git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects cat-file -p dd22c7cb5e5f207a6c38c50f45b7369ee8575840
git --git-dir=D:/openHarmonyScanner/tmp/d51-source-objects ls-tree dd22c7cb5e5f207a6c38c50f45b7369ee8575840 services/core/src/pasteboard_service.cpp services/zidl/src/pasteboard_service_stub.cpp
Get-FileHash D:/openHarmonyScanner/tmp/d51-pasteboard-service.cpp,D:/openHarmonyScanner/tmp/d51-service-stub.cpp -Algorithm SHA256
git -C D:/openHarmonyScanner/worktrees/d52-pasteboard-permission-20261020 show 842948084660207fd64399cfd598ed93e5593dcc:src/ohscanner/detectors/known_cves.py
git -C D:/openHarmonyScanner/worktrees/d51-pasteboard-quota-20261020 show c8f83b82291e82b3272c73b943623336a3c836c3:src/ohscanner/detectors/known_cves.py
```

No unit test suite was run for this read-only replay task. The control inputs were evaluated directly by both detector versions.
