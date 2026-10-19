# D42 IPC detector owner review request

## Request
B owner: review `ipc.relay.descriptor-boundary` on the exact A0-bound `multimedia_player_framework` inputs below. Do not assume the current finding is either a vulnerability or a false positive based only on this report.

## Reproduction
- Integration baseline: `3ce72e3bcbd0bb534a4daab1bd16fa08bf30bc7e`
- Source repo/commit/tree: `openharmony/multimedia_player_framework` / `71ab1e0881e0a79f2b9528742677467e7bb8dde5` / `9cc6c53506a70424485885c4c10b29dfbfaa8d1b`
- Current CLI: `research/evidence/cpp/d42_player_framework_cli_20261025.json`
- Header-context CLI: `research/evidence/cpp/d42_player_framework_cli_with_headers_20261025.json`
- 23 A0 line locations are mapped in `research/evidence/cpp/d42_player_framework_ipc_source_audit_20261025.json`; CLI emitted 24 diagnostics (one extra media_source line 86).

## Review question
The finding message states that dispatch/callback reaches handlers without a matched interface descriptor guard. In the same 11 scanned Stub implementations, each `OnRemoteRequest` reads `data.ReadInterfaceToken()` and compares to its own `GetDescriptor()` before dispatch. Corresponding headers declare `IRemoteStub<IStandard...>`. Including those headers in the source scope did not change the 24 findings. Please determine if this is expected semantics (for example, descriptor validation does not cover the specific boundary being reported), a missing cross-file/interface identity model, or another modeling issue. Assess callback-object exposure and per-transaction authorization separately from descriptor validation.

## Evidence still needed for vulnerability assessment
No trusted fixed source, product SA/build configuration, actual external caller policy, target-derived harness, reachable attacker path, or concrete CIA consequence is bound. Recorder has explicit calling-token permission checks for audio request groups; findings at CR-0191/0192 point to those guard calls. Do not infer product exploitability from candidate recurrence.

## Boundary
This is an owner-review request only. No IPC detector, shared API/schema, Catalog, or owner state file was changed on the A line. Any code change needs owner approval plus matched descriptor positive/guarded negative controls and independent replay.
