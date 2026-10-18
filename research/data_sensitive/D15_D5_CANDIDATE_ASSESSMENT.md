# D15 historical D5 candidate assessment

Date: 2026-10-18

## Source identity

- Repository: `openharmony/communication_dsoftbus`
- Before revision: `d33177135ec6c6aaf4a4c42de1f6878652b330e3`, tree `18e92bf9aaf515b182240309ed1a4a12dd2b2d03`
- Removal revision: `63efce3ff7f2708527eb29216decaf5fe2dc33d0`, tree `13fa948bd917684af7fd8e7b8c3f59b6943e1647`
- Candidate source: `core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c`, before line 671.
- The removal commit is titled `Remove unused sensitive prints` and deletes that logging call from this file. Its parent relation and per-file Git blob/SHA-256 identities are recorded in `D3_SOURCE_MANIFEST.json`.

## Source dataflow evidence

The pinned source evidence establishes a secret-bearing request path, not merely a variable name:

1. `StartVerifySession` generates `appInfo.sessionKey`, calls `PackRequest`, then transmits its result.
2. In `softbus_message_open_channel.c`, `PackRequest` Base64-encodes `appInfo->sessionKey` and adds it to the JSON field `SESSION_KEY` (lines 52-98). `UnpackRequest` reads that field and decodes it back into the session key (lines 100-125). The exact source objects and protocol field are independently documented in [D3_MODEL_EVIDENCE.md](D3_MODEL_EVIDENCE.md), [D3_SOURCE_MANIFEST.json](D3_SOURCE_MANIFEST.json), and the version-bound historical profile.
3. In the before revision, `ProcessReceivedData` decrypts into `crypInfo.out`; after successful decryption and JSON parsing it logs the complete output at error level, then dispatches `ProcessMessage`. The request branch reaches `OpenDataBusRequest`; the reply branch reaches `OpenDataBusReply`.

The exact historical source replay detects one candidate before and none after; both runs remain blocked because 4/10 files are complete and 6/10 are partial. The source-level detector delta is reproduced in [D15_D5_HISTORICAL_BEFORE.json](D15_D5_HISTORICAL_BEFORE.json) and [D15_D5_HISTORICAL_AFTER.json](D15_D5_HISTORICAL_AFTER.json).

## Component Harness evidence

The exact pinned `ProcessReceivedData` function bodies were compiled with deterministic decrypt/parser/processor/logger stubs and run in a rootless no-network namespace with a synthetic `SESSION_KEY` marker. The rerun is recorded in [D15_COMPONENT_HARNESS_RERUN.json](D15_COMPONENT_HARNESS_RERUN.json). In the old body, a valid synthetic request reached the stub logger with the marker; in the post-removal body, it did not. Ordinary reply and decrypt-failure controls behaved as expected. The existing test and limitations are described in [D5_COMPONENT_HARNESS.json](D5_COMPONENT_HARNESS.json) and [D5_PATCH_REVIEW.md](D5_PATCH_REVIEW.md).

This is meaningful component-level reproduction of the vulnerable logging behavior and regression after the upstream removal. The harness does not run the real cryptographic implementation, JSON packing function, log backend, product build, or product log service. It therefore does not establish persistent product logs, an unauthorized reader, release exposure, or concrete impact.

## Classification

Status: **candidate** for historical sensitive-information logging; product vulnerability and impact: **unknown**; `validated_vulnerability=0`.

The source trace plus component Harness support that a request containing the session key can flow into a public-operand log in the old component function. Remaining confirmation obligations include real build/configuration and log-level selection, formatter success/length behavior, deployed release mapping, log retention and reader authorization, and a concrete security impact. No CVE or confirmed product vulnerability is established.

## Remediation

Keep the upstream removal. Do not log decrypted request/reply bodies. If diagnostics are needed, emit bounded allowlisted metadata such as message direction/type and a result code; do not serialize opaque payloads. Add a regression around the real product integration boundary that sends a unique synthetic session-key marker and asserts it never reaches the configured log sink. Independently review log access and retention for any affected release before making a product impact claim.

A component Harness exists and passes; a product-level PoC, product build, and fix revalidation have not been performed.
