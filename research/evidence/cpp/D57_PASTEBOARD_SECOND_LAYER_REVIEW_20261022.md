# D57 — Independent second-layer review of D51 / D52

Date: 2026-10-22 (Asia/Shanghai)

## Review scope and result

Read-only review of the frozen D51 and D52 developer packets, T51 and T52 acceptance reports, scanner rule implementations, exact pinned component objects, and available official source history. No detector, fixture, test, or original report was changed. This is a second-layer source-evidence review, not an independent holdout and not a product assessment.

| Candidate | Decision | Confidence | Allowed interpretation |
|---|---|---:|---|
| D51 / CVE-2025-25212 label | **NARROW** | 0.86 | Retain as a component-source candidate for an unbounded observer registration path in the pinned old source. Do not claim that the source statement is the advisory's confirmed root cause, a validated CVE, or a product vulnerability. |
| D52 / CVE-2025-27247 label | **NARROW** | 0.82 | Retain as a read-permission candidate for the pinned old component snapshot. The request-to-data route and missing local gate in the old getter are supported; full authorization failure and exact CVE causality are not established. |

No product build fingerprint, component inclusion manifest, or fixed-product retest was supplied. Product vulnerability status for both remains **UNKNOWN**.

## D51 — observer registration quota

### Evidence that supports retaining a narrow component candidate

- D51's source identity is reproducible in the official local Git mirror: commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; `services/core/src/pasteboard_service.cpp` is blob `c380ac266a85edd818caa811f11b99722d351788`. The source hash in D51/T51 is consistent with the packet.
- In that source, the registration path stores remote observer references in a user-keyed set. The insertion deduplicates the same remote object but does not bound distinct object references. The reported line 241 is the insertion sink, a materially better anchor than the method opening brace.
- T51 independently exercised the frozen 0.19.3 rule with direct and helper quota positives, seven negative quota-flow probes, and an unrelated-map control. Its PASS is explicitly limited to those exact shapes. The complete component run remains blocked/partial; target semantic analysis is incomplete, so this evidence does not establish broad parser coverage.
- The official 5.0.3 fix commit `836cf6990579451d6521e9177d749660b07ad34e` is present in the local official mirror and changes the admission mechanism: `GetAllObserversSize(userId, callPid)` is checked against `MAX_OBSERVER_COUNT` before insertion. This supports the general quota-risk mechanism. The fix refactors the API to `AddObserver`; the D51 rule's zero-hit on the changed function shape is correctly treated as non-diagnostic, not as a demonstrated fixed-source replay.

### Why the CVE attribution must be narrowed

The source/fix pair is strong evidence of a quota defect and a matching remedial mechanism, but the reports do not bind the exact old insertion blob/statement to the advisory's stated root cause. Treat the CVE identifier as a triage association only. The component's publication policy, caller reachability, observer-death cleanup, runtime resource impact, and the target product's source revision remain unverified. The rule also recognizes a deliberately small family of local guard forms; aliases, cross-function admission, complex control flow, and concurrency are outside its demonstrated coverage. T51's synthetic controls cannot substitute for independently labeled holdout cases.

### Minimum actionable feedback

1. Keep the finding text and downstream status at component-candidate level; record CVE causality as unknown unless an authoritative advisory/fix mapping explicitly identifies this path.
2. Before product escalation, bind the component commit/blob to a product image and verify caller reachability plus cleanup/impact on that build.
3. Keep T51's guard-shape PASS scoped to its listed probes; do not reuse it as general quota-flow or parser-coverage validation.

## D52 — Binder read-permission path

### Evidence that supports retaining a narrow source-snapshot candidate

- Independently verified from the official local Git mirror: the pinned commit is `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`; the stub is blob `3dbc3150ada27a765938f06ea6e8cfd0a2d7146b`, and the core service is blob `c380ac266a85edd818caa811f11b99722d351788`.
- The old stub maps `GET_PASTE_DATA` to `OnGetPasteData`; that handler calls `GetPasteData` and serializes a successful result. In the pinned core getter, the service chooses the caller's OS-user clip and copies it without a visible permission decision. The descriptor check in `OnRemoteRequest` checks interface identity; it is not a read permission decision.
- Available full official history shows the pinned commit dates to 2022-07-22. The earliest `CheckPastePermission` occurrence found in the inspected distributeddatamgr refs is commit `e13a4ad3b72be7650ccb75de560790c04fa84795` (2022-08-15); it adds a permission decision in the core getter. This chronology supports that the July snapshot predates that local gate, but by itself does not prove the later change is the CVE fix.
- T52 independently replayed the rule and demonstrated its specified synthetic guard/unrelated controls. It correctly marks the target parse partial, the full run blocked, and the component/product status unassessed/unknown.

### Why the detector finding and CVE attribution must be narrowed

The 0.18.0 rule checks for permission-like names only in `OnRemoteRequest` and `OnGetPasteData`; it does not inspect `PasteboardService::GetPasteData`, helpers called by those methods, inherited IPC/SystemAbility enforcement, or product ACLs. Thus its guard logic is a local lexical heuristic, not a proof of the complete authorization boundary. The emitted line 41 is the opening brace of `OnRemoteRequest`; it identifies the method scope, not the authorization omission or data-return statement. T52 is right to state that limitation, but the rule finding must not be presented as statement-level proof. The pinned source's read route and local omission are supported; unauthorized access through the complete framework path and exact CVE root-cause identity remain unresolved. Synthetic controls do not resolve these omissions, and no exact fixed-source detector replay was available in the acceptance packet.

### Minimum actionable feedback

1. Describe the result as a pinned-snapshot read-permission candidate and preserve the line-41 method-entry limitation wherever the finding is surfaced.
2. Bind the full framework/service authorization contract and compare the exact fix diff to this source route before assigning CVE causality.
3. Keep product applicability unknown until a build fingerprint, component manifest, policy/configuration, and fixed-product retest are available.

## Queue / acceptance status

T51 passes only the exact 0.19.3 regression shapes it lists. T52 passes only its signature-level synthetic controls. Both source cases remain partial or blocked at the whole-component parser/detector layer; neither has holdout labels, and `validated_vulnerability=0`. Scope evidence is limited to the reviewed reports and commits; no D lane exists in the frozen `ownership.json`, so the original reports' manual scope checks are not equivalent to an automated lane check. These constraints do not invalidate the reproduced local source facts, but they prevent promoting either result to a validated vulnerability.

## Reviewed artifacts

- D51 developer: commit `c8f83b82291e82b3272c73b943623336a3c836c3`, report `research/data_sensitive/D51_PASTEBOARD_OBSERVER_QUOTA.md` and `.json`.
- T51 acceptance: report `research/evidence/cpp/t51_pasteboard_quota_acceptance_0193_20261020.md` and `.json`.
- D52 developer: commit `9d3b1e653a6e56a3f2f6aea376e30ac9f61ef4e`, report `research/data_sensitive/D52_PASTEBOARD_PERMISSION_20261020.md` and `.json`.
- T52 acceptance: commit `184356d0f9863cf1e610c419452a0f3be6d62a1f`, report `research/evidence/cpp/t52_pasteboard_permission_acceptance_20261020.md` and `.json`.
- Rule revisions inspected: D51 `ohscanner.known_disclosed_cves@0.19.3`; D52 `@0.18.0`.

