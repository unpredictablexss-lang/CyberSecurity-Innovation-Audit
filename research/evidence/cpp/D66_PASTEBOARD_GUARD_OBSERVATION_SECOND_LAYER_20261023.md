# D66 — Second-layer review of D65 Pasteboard guard observation

Date: 2026-10-23 (Asia/Shanghai)

## Decision

**NARROW** the D52 result to a pinned-source candidate with `permission_guard=unknown`. The D52 candidate is suitable to send to a downstream second-layer model for source-root-cause review, provided the exact source identity, route, method-entry anchor, partial parse, and D65 metadata limits accompany it. The metadata is useful as a bounded-scope observation in intent; it is not an authorization result and does not discharge the guard obligation.

Confidence: **0.92** that the frozen D52 source supports the reported local route and that D65 preserves the candidate/unknown obligation; **0.88** that T65 supports the tested observation states and candidate identity; **PARTIAL** on metadata accuracy/boundedness outside those controls. No product-vulnerability confidence is assigned.

Product applicability, exact CVE causality, framework authorization, runtime reachability, exploitability, and device fixed status remain **UNKNOWN**. No target product fingerprint or component inclusion manifest was provided.

## Frozen evidence checked

- D65: `dd7881d81e49d333ac2bd52062706ed06c5694c5`, based on D64 `594abe600d731c72e760e730526dadb8931a9985`, detector `ohscanner.known_disclosed_cves@0.19.9`.
- T65: `64fc40db3b42bdca54d9dbeba4c4ac7efe48a3a3`, independent acceptance.
- D52 source: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Stub blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`; core getter blob `c380ac266a85edd818caa811f11b99722d351788`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.

T65 reports 32/32 focused tests passing, all 22 matrix cases retaining D51/D52, D52 `permission_guard` staying unknown, and the pinned-source replay retaining both exact identities. The 67-unit replay remains blocked with 57 complete and 10 partial units; the D52 stub and core file are both partial. T65 accepts state distinction and non-inference for the tested cases, while rating evidence completeness and coverage PARTIAL. Its JSON and D65 diff checks are reported PASS. I inspected the D65 implementation and independently called its observation helper with additional read-only edge inputs; no D65 files were changed.

## What the observation safely says

D65 adds `permission_guard_observation` alongside, not in place of, `permission_guard=unknown`. It looks only at the extracted, comment/literal-masked `OnGetPasteData` body. For recognized permission-name calls and identifier tokens, it records a body-relative character span, normalized identifiers, and a whitespace-normalized snippet. It keeps the D51/D52 route candidates and does not alter the old candidate identity, hash, or line-41 method-entry anchor.

T65 confirmed that `absent`, `observed_unresolved`, and `unresolved_control_flow` have `status=unknown`, and explicitly verifies that `observed_unresolved` is not treated as authorization. On the exact D52 snapshot, the handler-body observation is `absent`. This means only that D65's current regex recognized no matching call/token in this one handler body. It does not establish absence of permission enforcement in the core service, a called helper, the IPC/SystemAbility framework, service ACL, or product configuration. Nor does a visible token establish a valid check, denial behavior, or dominance.

## Additional metadata boundary probes

The following are read-only direct calls to D65's `_pasteboard_guard_observation`, not source-build or product tests:

1. **Unbraced nesting is not represented by the state name.** Input body: `if (is_privileged) if (!VerifyPermission(PERMISSION_READ_PASTEBOARD)) return denied; GetPasteData();`. Observed output: `state=observed_unresolved; ... span=handler_body[24:68] ...`. The permission call is nested under an unbraced outer `if`, but `_top_level_at` counts only braces, so the metadata does not label it `unresolved_control_flow`. This is consistent with a brace-depth observation, but consumers must not read the label as a control-flow classification.
2. **Nested call syntax truncates the call span.** Input body: `if (!CheckPermission(GetPermissionType(PERMISSION_READ_PASTEBOARD))) return denied; GetPasteData();`. The emitted call snippet ends at the inner close parenthesis: `CheckPermission(GetPermissionType(PERMISSION_READ_PASTEBOARD)`. The token is also observed, but the reported call span is not a balanced full invocation. This follows from the regex's `[^;{}]*?` argument scan, which does not match nested parentheses structurally.
3. **Token output has no per-record or total character cap.** Input one recognized call with 3,000 distinct identifier arguments. Observed description length was **23,110 characters**; the snippet remained 120 characters, while the `token=` field included the final `ARG2999`. D65 caps emitted match records at 8 and each snippet at 120 characters, but serializes all normalized identifiers from each selected match. `matches = list(...)` also materializes every match in the body before truncating emitted records. `MAX_UNIT_BYTES` is 1 MiB, an indirect input ceiling, not a small evidence-payload limit.

These results do not invalidate the exact source metadata or T65's tested matrix. They show that “bounded” currently applies to snippet length and emitted record count, not to total description size, and that state labels describe lexical brace depth rather than general control flow.

## D52 source and product boundary

The pinned stub maps `GET_PASTE_DATA` to `OnGetPasteData`; `OnRemoteRequest` validates the interface descriptor and dispatches; `OnGetPasteData` calls `GetPasteData` and serializes the result. The line 41 candidate anchor is the opening brace of `OnRemoteRequest`, not the specific authorization omission. In the pinned old core getter, the selected caller-user clip is copied with no visible permission decision in that method. This supports a component-source candidate while leaving the complete request authorization path unresolved.

The D65 observation scans only the stub handler, whereas a permission decision may be in the core getter or external framework path. `absent` must not be used to close the guard obligation. T65's exact 67-unit replay preserves the finding identity but is blocked/partial, so it is not proof of complete source coverage. No product build, ACL, attacker path, impact, CVE-to-exact-line mapping, or fixed-device status is established.

## Actionable feedback

1. Keep the candidate **narrow/source-only** and send it to a downstream model to review the old getter and full authorization boundary; keep `permission_guard=unknown` regardless of the observation state.
2. Define `absent` as “no currently recognized regex match in this handler body.” Define visible states as regex observations; avoid naming them as resolved control-flow classes.
3. Replace the free-text record with structured fields (`state`, body-relative `start/end`, matched kind, bounded token list, snippet, and truncation flags). Suggested hard limits: at most 8 records, **at most 16 normalized tokens per record**, **at most 512 characters for the token field**, and **at most 4,096 characters for the full observation description**; emit `tokens_truncated` / `payload_truncated` and the total match count.
4. Use balanced-delimiter scanning or an AST/tokenizer for full call spans; add tests for nested unbraced `if`, nested-call arguments, comments/strings, and oversized token lists. Keep all observation metadata at status `unknown` until semantic and cross-file analysis exists.
5. Do not infer product vulnerability, fixed status, or CVE causality from D65/T65. Require product fingerprint, component inclusion, policy/framework authorization, and independent runtime evidence for those decisions.

