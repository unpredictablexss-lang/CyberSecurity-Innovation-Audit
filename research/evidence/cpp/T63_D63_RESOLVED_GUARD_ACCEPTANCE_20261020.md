# T63 — Independent D63 resolved-guard acceptance

Date: 2026-10-20 (Asia/Shanghai)

## Frozen target and source identity

T63 reviewed D63 commit `c2447a0449ba90622ee77ddc5434e282f28fb7db`, detector `ohscanner.known_disclosed_cves@0.19.7`, in an independent worktree. The pinned D52 source is `openharmony/miscservices_pasteboard` commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, snapshot SHA-256 `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.

- Stub `services/zidl/src/pasteboard_service_stub.cpp`: blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, 6,288 bytes, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`, parse state partial.
- Observer core `services/core/src/pasteboard_service.cpp`: blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`, parse state partial.

## Independent guard matrix

All controls used a mapped/routed `GET_PASTE_DATA` stub shape. D51 `CVE-2025-25212` was retained in all 18 synthetic multi-finding cases.

| Shape | D52 result | Review |
|---|---|---|
| Top-level `CheckBluetoothPermission(PERMISSION_READ_PASTEBOARD)` denial | Candidate retained | Correctly rejects token passed to unrelated API |
| Same-name `CheckPastePermission` that always returns true | Candidate retained | Correctly rejects name-only lookalike |
| Same-name helper delegating to Bluetooth check with read token | Candidate retained | Correctly rejects argument token without read contract |
| Same-unit helper: `permissionMap[PERMISSION_READ_PASTEBOARD] != PERMISSION_GRANTED`, then `return false; return true;`; pre-read caller denial exit | Suppressed syntactically | Positive syntax control only |
| Same-unit helper using `SECURE_PASTE_PERMISSION` with denial return and true tail | Suppressed syntactically | Positive syntax control only |
| Same-unit helper using `untrustedState[PERMISSION_READ_PASTEBOARD]` | **Suppressed unexpectedly** | Actionable false suppression: inner state identity is arbitrary |
| Same-unit helper using `bluetoothResult[PERMISSION_READ_PASTEBOARD]` | **Suppressed unexpectedly** | Actionable false suppression: inner state identity is arbitrary |
| Same-unit `permissionMap[PERMISSION_NETWORK]` denial helper | Candidate retained | Unrelated key control |
| D61 direct inline `VerifyPermission(READ_PASTEBOARD)`, `SECURE_PASTE`, and `CheckPermission(READ_PASTEBOARD)` denial checks before read | Candidate retained | D63 changed D61's prior suppression behavior; now helper-only |
| Ignored result, post-read/post-write, dead nested, outer conditional, mixed condition | Candidate retained | D59/D61 ineffective-order/reachability controls preserved |
| Accepted helper under dead/outer branch or after parcel write | Candidate retained | Ordering and branch controls preserved |
| Immediate throw from an accepted helper denial branch | Suppressed syntactically | Exit shape only; catch/unwind not modeled |

The matcher recognizes only a narrow syntax. Its condition accepts **any** identifier followed by an index containing an allowlisted `READ_PASTEBOARD` or `SECURE_PASTE` spelling. It does not resolve that identifier's declaration or provenance. Therefore D63 correctly rejects helper-name and Bluetooth-call impostors but does not establish the inner map/state object's identity. The positive `permissionMap[...]` input is an in-memory same-unit shape, not evidence that this is a real framework permission API.

The report calls the direct-inline change out separately: D61 suppressed those token-bearing denial branches, while D63 retains them because it now requires a same-unit helper. The exact D52 source behavior and D51/D52 candidate identities are unchanged in full replay.

## Exact component replay and checks

I rebuilt the exact 67 C/C++ input units from the pinned Git object database and reused D50's recorded per-unit parser statuses. The independent D63 detector run is `blocked`, with 57 complete and 10 partial units. It emitted the same two findings as D61:

- D51 `CVE-2025-25212`, `pasteboard_service.cpp:241:5`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 `CVE-2025-27247`, `pasteboard_service_stub.cpp:41:1`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Strict duplicate-key check of D63's JSON evidence packet — **PASS**.
- `git diff --check c8..D63` — **PASS**. Twelve paths changed, 542 insertions and 12 deletions. The only implementation path is `src/ohscanner/detectors/known_cves.py`; the rest are focused tests/corpus, fixture binding, and D59/D61/D63 evidence packets.

## Verdict

- **fix-correctness: PARTIAL.** The helper-name and delegated-Bluetooth adversaries are fixed. Overall suppression is not acceptable beyond this syntax-only boundary: arbitrary map/state identifiers with an allowed token suppress the candidate, so inner API identity is not verified.
- **candidate-retention: PASS for the exact pinned D51/D52 candidates and the tested ineffective controls.** D61's direct-inline suppression behavior changed and is documented above.
- **coverage: PARTIAL.** Full exact replay remains blocked, with 10 partial units.
- **scope: PASS.** No unrelated detector implementation changed.

No framework authorization, product inclusion, runtime behavior, CVE causality, or product vulnerability conclusion is established. D52 remains a pinned-source candidate; product/framework/CVE conclusion is unknown.

