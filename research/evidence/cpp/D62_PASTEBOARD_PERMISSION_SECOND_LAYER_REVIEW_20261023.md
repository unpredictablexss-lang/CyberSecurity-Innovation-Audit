# D62 — Second-layer review of D61/T61 permission identity

Date: 2026-10-23 (Asia/Shanghai)

## Final disposition

**NARROW** the D52 finding to a pinned-source read-permission candidate. Confidence: **0.91** that the exact July 2022 source has the reported request-to-data path and no visible local read-permission decision in the inspected stub/core getter; **0.84** that this is suitable for downstream source-root-cause review; **no product-vulnerability confidence assigned**.

The D60 false suppression for `CheckBluetoothPermission(PERMISSION_NETWORK)` is fixed in D61: I independently reran that control against frozen D61 and the candidate is retained. D61/T61 do not establish that all accepted helper names or permission constants prove Pasteboard authorization. A second read-only control confirms that a helper named `CheckPastePermission` which unconditionally returns `true` still suppresses the finding. The source-backed helper name narrows vocabulary but does not bind the helper's implementation, arguments, call path, or grant semantics.

**D52 is appropriate to send to a downstream second-layer model for source-root-cause review**, with exact source identity and the limits below attached. The model may compare the old path to the later permission-gating change. No result may be promoted to a product vulnerability without a product fingerprint, component inclusion evidence, and product authorization/runtime evidence.

## Frozen artifacts checked

- D61 code commit: `b0ce27a3e3b08f085e46a22468e890ac8808d1c1`, based on `c8f83b82291e82b3272c73b943623336a3c836c3`, rule `ohscanner.known_disclosed_cves@0.19.6`.
- T61 independent acceptance: `395742abd129db59508aed6908b040a6463ba759`.
- D61/T61 packets: `research/evidence/cpp/D61_PASTEBOARD_PERMISSION_IDENTITY_20261023.md/.json` and `T61_D61_PERMISSION_IDENTITY_ACCEPTANCE_20261023.md/.json`.
- D60 prior second-layer finding: commit `a9105a4f65cddb0b856242dbdbcb4f76a3741ccf`.
- D52/T52 and D57/D60 history was consulted for the original source anchor, parse limits, source-only classification, and explicit product boundary.

T61 reports the focused detector/corpus suite passing 32 tests and a raw-source 67-unit replay against the baseline and D61 with identical D51/D52 findings. Both whole-component runs remain blocked, with 57 complete and 10 partial units. D52's target stub remains partial. These results support candidate identity and regression coverage for the listed matrix; they do not provide complete parse coverage. T61's D61 diff check and strict duplicate-key JSON checks are reported PASS. I inspected the frozen implementation and independently exercised the two additional controls below; this review did not modify scanner, tests, fixtures, or the earlier reports.

## D60 control: resolved

The D60 input shape was a top-level pre-read `CheckBluetoothPermission(PERMISSION_NETWORK)` denial return followed by unconditional `GetPasteData()` and `WriteParcelable(...)`. D61/T61 explicitly include this shape. I reran it in memory with the frozen 0.19.6 detector: status `completed`, `CVE-2025-27247` candidate present. This confirms the D60 example is no longer suppressed.

## Source-backed helpers: real history, limited proof

The exact helper names in D61 are supported by inspected official history:

- `CheckPastePermission` exists in commit `e13a4ad3b72be7650ccb75de560790c04fa84795`. Its body checks focus/default-IME eligibility and handles `ShareOption`; for `InApp`, it compares the current app ID with the stored app ID. In that later source, the core getter invokes the helper before reading/returning data.
- `HasPastePermission` exists in commit `cedbaeb9f55f524fb93c9d76ec06a4dc7b213ba7`. Its body derives caller app/token information, checks focus/default-IME eligibility for HAP callers, and applies the same app/share-option decision.
- Later `VerifyPermission` with READ/SECURE checks exists at `721fecac75d9c51b0b145469abc6c9c78c17753e`.

This history supports that the identifiers have been used for Pasteboard access policy in particular source revisions. It does **not** establish a general OS `READ_PASTEBOARD` grant contract for every similarly named function or source. The helper implementations differ over time and encode focus/IME, app identity, and share-option policy. T61's helper probes assembled helper definitions and the stub in one in-memory source unit; they are not a real cross-file integration replay. The D61 detector searches only the dispatch and handler bodies and does not resolve a call to the core getter helper.

### Concrete helper-name false suppression

I independently ran this in-memory shape against frozen D61:

```cpp
bool CheckPastePermission(int32_t userId, std::string &appId, ShareOption shareOption) {
    return true;
}
int OnGetPasteData() {
    if (!CheckPastePermission(userId, appId, shareOption)) return ERR_NO_PERMISSION;
    GetPasteData();
    reply.WriteParcelable(data);
    return 0;
}
```

Observed: detector status `completed`, no `CVE-2025-27247` candidate. Because the named helper always allows, the read remains unguarded. This proves that the exact helper name alone can suppress even when its implementation provides no denial. This is a synthetic adversarial example, not a claim that the upstream helper had this body.

A second control passed `PERMISSION_READ_PASTEBOARD` to `CheckBluetoothPermission`. D61 also suppressed that read candidate because the identifier regex searches the complete condition independently of the function's meaning. This confirms that the constant token and checking function are not bound to each other.

## Exact D52 source path and limits

The D52 packet binds source to `openharmony/miscservices_pasteboard` commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`:

- Stub `services/zidl/src/pasteboard_service_stub.cpp`, blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Core getter `services/core/src/pasteboard_service.cpp`, blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.

The stub maps `GET_PASTE_DATA` to `OnGetPasteData`; `OnRemoteRequest` validates the interface descriptor and dispatches the mapped transaction; `OnGetPasteData` calls `GetPasteData` and writes the returned object. The descriptor check is interface identity validation, not a Pasteboard read decision. The pinned core getter scopes lookup by caller OS user and copies the selected clip, with no visible permission decision in that function. The D52 rule anchor at line 41 is only the opening brace of `OnRemoteRequest`, not the root statement. D52/T52 identify the stub parse as partial and the full run as blocked. D61 preserves that exact source candidate and anchor in its reported replay.

The pinned July source predates the inspected August 2022 `CheckPastePermission` gate. That later gate is evidence of a subsequent code-level access-control path, not proof that it fixed the precise 2025 advisory root cause. The source report does not resolve inherited IPC/SystemAbility enforcement, service ACL, product policy, actual product source revision, or attacker reachability.

## Actionable conclusion

1. Keep D52 as **narrow / source-only candidate**, with the line-41 method-entry caveat and partial/blocked parser status.
2. Send it to a downstream second-layer model to review the old data path against the later historical gate and advisory evidence; do not ask that model to infer product status from this snapshot.
3. Do not use D61 suppression as a safe verdict based on helper name or token presence alone. D61 fixes the D60 unrelated-network control, but the `CheckPastePermission` always-allow and permission-token/function mismatch controls remain false suppressions.
4. Keep CVE causality, product applicability, runtime authorization, exploitability, and device fixed status **UNKNOWN** until exact product/build and policy evidence is supplied.

