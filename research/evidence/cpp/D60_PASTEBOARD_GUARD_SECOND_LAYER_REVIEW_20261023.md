# D60 — Second-layer review of D59/T59 Pasteboard guard result

Date: 2026-10-23 (Asia/Shanghai)

## Decision

**NARROW** (confidence 0.90 for the reviewed candidate-handling decision; 0.82 that the pinned snapshot supports a component-level read-permission candidate).

Keep the D52 result as a **source-only candidate** suitable for downstream second-layer model review. D59/T59 materially repair the demonstrated false suppressions: the exact old D52 candidate remains at the same identity and location, and the specified denial-guard control suppresses only for a narrow local syntax pattern. This acceptance does not validate the CVE attribution, a complete authorization failure, or any product vulnerability. Do not interpret a suppressed finding in another source as evidence of safety.

Product applicability, CVE causality, full runtime authorization, exploitability, and affected/fixed device status remain **UNKNOWN**. No product fingerprint or inclusion manifest is present in the reviewed packet.

## Frozen identity and evidence checked

- D59: `da0195610f2203ce97af1f43385f0091f040504e`, detector `ohscanner.known_disclosed_cves@0.19.5`, based on D51's frozen `c8f83b82291e82b3272c73b943623336a3c836c3` / rule 0.19.3.
- T59: `648fe48537cd2f226ef69a9a74006c586d9474f6`; detached independent acceptance worktree, no detector/test/fixture/expected-output edits.
- D52 pinned source: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; stub blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, raw SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- D52 route and limits were also reviewed in the D52/T52 packet and D57 second-layer report, commit `ca2020e7b6d838e05175dc9b541a7d63d79461f1`. `OnRemoteRequest` line 41 is the method opening brace. The source chain maps `GET_PASTE_DATA` to `OnGetPasteData`, then to core `GetPasteData` and parcel serialization, but the component snapshot does not establish framework/SystemAbility or product ACL behavior.

The T59 JSON ties its patch, base, exact-source replay, and focused matrix to the commits above. The cumulative `c8..da019` diff is reported as 8 files, 243 insertions, 12 deletions; the final follow-up commit itself is a small delta. Focused detector/corpus tests are reported PASS (32 tests). The 67-unit replay is reported blocked on both baseline and patch, with 57 complete and 10 partial units and identical candidate identities. The target stub identity quality and parse status remain partial. D59's broader test discovery is reported as 3 failures and 17 errors; T59 did not rerun it and does not claim a full-suite pass.

## What 0.19.5 actually suppresses

The inspected matcher requires all of the following in the checked method body:

1. A syntactically bounded `if` condition matching exactly one of: `!PermissionCheck(...)`, `PermissionCheck(...) != PERMISSION_GRANTED`, or `PermissionCheck(...) == PERMISSION_DENIED` (with the implementation allowing names matching the broad `Check*Permission`, `Verify*Permission`, `Enforce*Permission`, `PermissionManager`, or `CheckPermission` patterns).
2. The denial branch begins with `return` or `throw`.
3. The `if` starts at top level according to a local brace-count check.
4. The full parsed `if` statement ends before the first `GetPasteData` occurrence in `OnGetPasteData`, or before the first `it->second` route in `OnRemoteRequest`.
5. A candidate nested within a literal `if (false)` wrapper is not used to suppress.

This is a useful conservative syntax filter. It fixes the specific failures demonstrated in T58/T59: ignored permission results, checks after data read or parcel write, a denial branch nested under a bypassable outer conditional, and a denial branch hidden under literal false all retain the candidate. The exact unguarded pinned source still emits CVE-2025-27247 at line 41 with its original source hash. The 0.19.5 matrix also confirms that a direct pre-read `return`/`throw` denial shape is suppressed.

The suppression is not a semantic permission proof. A name such as `CheckOtherPermission` can match even if it is unrelated to pasteboard read access; the matcher does not bind the call to the read permission constant or validate its return contract. The T59 synthetic controls demonstrate parser behavior for selected names and forms, not that a real implementation enforces the required permission. This is the main remaining precision risk in the suppression path.

I independently confirmed this with an additional in-memory negative control against the frozen 0.19.5 detector. The mapped handler was:

```cpp
int OnGetPasteData() {
    if (!CheckBluetoothPermission(PERMISSION_NETWORK)) return ERR_NO_PERMISSION;
    GetPasteData();
    reply.WriteParcelable(data);
    return 0;
}
```

The detector returned no CVE-2025-27247 candidate (`pasteboard_candidate=False`, no findings). This is a concrete semantic false suppression: a check named for Bluetooth/network access does not establish Pasteboard read authorization, while the handler proceeds to read and serialize pasteboard data. The call satisfies the current generic permission-name pattern. This probe does not modify source, tests, or fixtures.

## Residual coverage and failure modes

- **Throw/catch and exception flow:** `throw` is accepted as an early exit based on branch text. The matcher is not a C++ exception-flow model and does not inspect function-try-block handlers or prove that exception handling cannot recover a data-return path. Standard nested `try` bodies will fail the top-level check and therefore tend to retain candidates, but that does not prove all catch/unwind shapes are handled. No catch/function-try-block adversarial test is reported.
- **Top-level approximation:** `_top_level_at` counts braces in a prefix; it is not an AST or CFG dominance check. The tested conditional-outer bypass is fixed, but macros, unusual syntax, function-try-block structure, preprocessor branches, aliases, and malformed/partial parses are outside the demonstrated proof. The syntactic top-level constraint also conservatively retains candidates behind valid guards in some nested-but-dominating shapes.
- **Guard semantics and identity:** permission-like naming, status constants, and immediate exit are assumed to represent denial of this specific read. No permission API contract, required permission ID, token identity, or method effect is bound.
- **Placement:** only `OnRemoteRequest` and `OnGetPasteData` are scanned for suppression. A real check in the core getter, a called helper, inherited IPC/SystemAbility machinery, service registration, or product ACL does not suppress this source-local candidate. Conversely, absence from these two bodies does not establish absence from the full request path.
- **D52 location and parse coverage:** line 41 remains a method-entry anchor, not the root statement. The exact target stub is partial; whole-source/unit replays are blocked. Stable findings across baseline and patch prove identity preservation for this replay, not complete analysis coverage.
- **Product/CVE boundary:** no exact CVE-to-source proof, product build fingerprint, component inclusion record, service ACL, attacker path, or fixed-product retest is in this packet. D57's `narrow` source-only conclusion remains appropriate.

## Minimal actionable feedback

1. Send the candidate downstream as: “pinned source snapshot contains a GET_PASTE_DATA route with no visible local read-permission decision in the inspected stub/handler/core getter; line 41 is only the method anchor; framework and product authorization unknown.”
2. Treat suppression as a triage hint only until the permission call is tied to the required pasteboard-read permission and its implementation contract is reviewed.
3. D59 is not ready to classify guarded source as safe: the additional unrelated-permission control produces a false suppression. Add adversarial controls for unrelated permission names and function-try-block/catch recovery before relying on suppression for candidate closure. Keep the current D59 guard-shape PASS limited to its stated matrix.
4. Keep product applicability, CVE causality, and vulnerability validation unknown pending exact source-to-product binding and independent runtime evidence.

## Downstream disposition

**Yes: send the D52 candidate to the downstream second-layer model**, with the source identity, route, line-41 caveat, partial parse/blocked replay status, and D57/D60 scope limits attached. Ask that model to assess source-level authorization and exact fix/advisory mapping. Its output must not be converted into a product vulnerability decision without product identity and runtime evidence.

