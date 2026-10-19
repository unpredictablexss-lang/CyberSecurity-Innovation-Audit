# T65 — Independent D65 guard-observation acceptance

Date: 2026-10-20 (Asia/Shanghai)

## Frozen target and source identity

T65 reviewed D65 commit `dd7881d81e49d333ac2bd52062706ed06c5694c5`, detector `ohscanner.known_disclosed_cves@0.19.9`, in an independent worktree. It is based on D64 `594abe600d731c72e760e730526dadb8931a9985`; detector blob is `818836c66390f30bb8dd778d019315b0085734dd`.

Pinned D52 source is `openharmony/miscservices_pasteboard` commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, snapshot SHA-256 `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.

- Stub `services/zidl/src/pasteboard_service_stub.cpp`: blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, 6,288 bytes, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`, parse state partial.
- Core `services/core/src/pasteboard_service.cpp`: blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`, parse state partial.

## Observation state and candidate matrix

Across 22 in-memory multi-finding cases, every input retained D51 `CVE-2025-25212` and D52 `CVE-2025-27247`; every D52 finding retained `permission_guard=unknown`. Observation states partitioned as:

| Observation case | State | Evidence emitted | D52 candidate |
|---|---|---|---|
| No permission-like call or token in `OnGetPasteData` | `absent` | Explicit absence scoped to handler body | Retained |
| Top-level matching read-permission denial, top-level unrelated network check, or post-read guard | `observed_unresolved` | Handler-body span, normalized call/token names, snippet | Retained |
| Guard nested under literal `if(false)` or `if(is_privileged)` | `unresolved_control_flow` | Nested handler-body span, normalized tokens, snippet | Retained |
| Same-unit helper call | `observed_unresolved` | Call-site span and helper name | Retained |

Other cases covered D62 `untrustedState[...]` and `bluetoothResult[...]`, Bluetooth receiving a read token, same-name and Bluetooth-delegating helper impostors, unrelated Bluetooth/network/generic permission checks, ignored result, post-serialization, mixed predicates, helper ordering controls, and immediate `throw`. All retained both candidate IDs with the permission guard obligation unknown.

I confirmed `observed_unresolved` is not treated as authorization: both the main `permission_guard` and the observation obligation remain status `unknown`. The text says only that permission-like syntax was seen. It does not say that a check is valid, that denial is effective, or that it dominates the read.

## Evidence payload limits

The three states are distinguishable in tested cases. The exact D52 pinned handler has no permission-like token in `OnGetPasteData`, so it is classified `absent`. For a visible direct guard, the observation description includes a handler-body-relative span and token/snippet, for example `span=handler_body[4:48]` and `VerifyPermission(PERMISSION_READ_PASTEBOARD)`. Nested guards are labeled `unresolved_control_flow` and also include their span/snippet.

The payload is serialized in the obligation description string rather than typed span/token fields. Spans are relative to the handler body, not absolute file offsets. A same-unit `CheckPastePermission()` helper call records the call name and span, but does not expand the helper body to include its inner permission token or provenance. These are bounded evidence-format limits, not authorization findings.

## Exact component replay and checks

I rebuilt D50's exact 67 C/C++ inputs from the raw Git object database and reused the recorded parser state for each file. D65 returned `blocked`, 57 units complete and 10 partial, with the same two findings as D64/D63/D61:

- D51 `CVE-2025-25212`, `services/core/src/pasteboard_service.cpp:241:5`, source SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 `CVE-2025-27247`, `services/zidl/src/pasteboard_service_stub.cpp:41:1`, source SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`; `permission_guard=unknown`, observation `absent` within the handler body.

Candidate rule IDs, symbols, file paths, anchors, and source hashes are unchanged. The new observation metadata does not suppress either route finding.

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Strict duplicate-key validation of D65's JSON packet — **PASS**.
- `git diff --check D64..D65` — **PASS**. Five paths changed: the known-CVE detector, focused tests/corpus binding, and D65 evidence packets. No unrelated detector implementation changed.

## Verdict

- **observation-state distinction: PASS** for tested absent, visible, and nested-control-flow cases; spans/tokens/snippets were emitted for visible cases.
- **candidate retention: PASS.** All 22 cases retain D51 and D52 identities, and D52 remains `permission_guard=unknown`.
- **authorization non-inference: PASS.** Observed syntax is not interpreted as authorization or effective dominance.
- **evidence completeness: PARTIAL.** Payload is a free-text description with handler-relative offsets; same-unit helper call observations do not include the helper body's permission token.
- **coverage: PARTIAL.** Exact source replay remains blocked with 10 partial parser inputs.
- **scope: PASS.** No unrelated detector implementation changed.

No framework authorization, product inclusion, runtime behavior, CVE causality, or product vulnerability is established. D52 remains a pinned-source candidate.
