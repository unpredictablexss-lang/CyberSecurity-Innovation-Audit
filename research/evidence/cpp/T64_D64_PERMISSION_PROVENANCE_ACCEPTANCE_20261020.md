# T64 — Independent D64 permission-provenance acceptance

Date: 2026-10-20 (Asia/Shanghai)

## Frozen target and pinned source

T64 independently reviewed D64 commit `594abe600d731c72e760e730526dadb8931a9985`, detector `ohscanner.known_disclosed_cves@0.19.8`, in a separate worktree. D64 is based on frozen D63 `c2447a0449ba90622ee77ddc5434e282f28fb7db`; detector blob is `0bb13b5e72f0bec3080212a0e506c87693a7c49d`.

The exact D52 source is `openharmony/miscservices_pasteboard` commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, snapshot SHA-256 `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`.

- Stub `services/zidl/src/pasteboard_service_stub.cpp`: Git blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, 6,288 bytes, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`, parser state partial.
- Observer core `services/core/src/pasteboard_service.cpp`: Git blob `c380ac266a85edd818caa811f11b99722d351788`, 17,335 bytes, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`, parser state partial.

## Independent guard matrix

I exercised 22 mapped/routed `GET_PASTE_DATA` source-local controls with D51's observer signature in the same test input. Every case emitted both D51 `CVE-2025-25212` and D52 `CVE-2025-27247`; every D52 finding carried `permission_guard` status `unknown`.

The matrix included:

- No guard; inline `READ_PASTEBOARD` and `SECURE_PASTE` denial checks; matching `CheckPermission` identity; D63's same-unit `permissionMap` helper controls.
- D62 adversaries: Bluetooth API given the read token, a same-name helper that always returns true, a helper delegating to Bluetooth, and arbitrary `untrustedState[...]` / `bluetoothResult[...]` state identifiers.
- Unrelated Bluetooth/network/generic checks and `permissionMap[PERMISSION_NETWORK]`.
- Ignored permission result, checks after read and parcel write, nested `if(false)`, outer conditional, mixed predicate, helper checks in those positions, and immediate `throw`.

D64 consistently retains the route candidate. It does not claim any guard suppresses the candidate. This removes D63's arbitrary-state false suppression and keeps the D52 finding identity stable.

## Evidence distinction review

D64 adds an explicit `permission_guard` obligation with status `unknown`, and its message says guard provenance is unknown. That is conservative, but the metadata is identical for an unguarded handler and a handler with a visible token-bearing denial branch. I found no field for guard presence, observed token, or guard source span. The finding therefore does not tell a downstream second-layer reviewer whether the scan saw no guard or saw a guard whose source/API and control-flow contract could not be resolved.

This is an evidence completeness issue, separate from candidate retention. It does not justify suppressing the route candidate. A minimal follow-up is a bounded observation such as `absent`, `observed_unresolved`, or `unresolved_control_flow`, with source span and normalized token spellings, while keeping authorization and dominance unknown.

## Exact component replay and checks

I independently rebuilt D50's exact 67 C/C++ units from raw Git blobs and reused the recorded per-unit parser states. D64 returned `blocked`, with 57 complete and 10 partial units, and the same two findings as D63/D61:

- D51 `CVE-2025-25212`, `services/core/src/pasteboard_service.cpp:241:5`, source SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 `CVE-2025-27247`, `services/zidl/src/pasteboard_service_stub.cpp:41:1`, source SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`, with `permission_guard=unknown`.

The D52 rule ID, symbol, file, line, column, and source hash remain unchanged from D63. The D51 sibling identity is also unchanged.

- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` — **PASS, 32/32**.
- Strict duplicate-key validation of D64's JSON packet — **PASS**.
- `git diff --check D63..D64` — **PASS**. Five paths changed: the known-CVE detector, focused tests/corpus fixture bindings, and D64 evidence packets. No unrelated detector implementation changed.

## Verdict

- **candidate retention: PASS.** D51 and D52 identities are preserved across all tested guard shapes.
- **guard-provenance conservatism: PASS.** Unresolved permission syntax no longer suppresses the source route candidate.
- **evidence completeness: PARTIAL.** `permission_guard=unknown` is present, but guard-present versus guard-absent is not recorded, and no token/source span is surfaced.
- **coverage: PARTIAL.** Exact source replay is blocked with 10 partial units.
- **scope: PASS.** No unrelated detector implementation changed.

D52 remains a pinned-source candidate. Product/framework inclusion, runtime authorization, CVE causality, and product vulnerability remain unknown.
