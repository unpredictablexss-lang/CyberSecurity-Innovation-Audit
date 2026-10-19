# D69: independent second-layer review of D68/T68

## Decision

**D52 source candidate: `narrow` (high confidence for the source-level route; no confidence assigned to product applicability or CVE causality).** It is suitable for a downstream root-cause model review only as a source-only hypothesis with the guard obligation explicitly unknown. Do not phrase it as a confirmed permission bypass or product vulnerability.

The candidate is grounded in the pinned source identity and route: `GET_PASTE_DATA` dispatches through `PasteboardServiceStub::OnRemoteRequest` into `OnGetPasteData`, which calls the core getter and serializes the result. The D52 finding is anchored to the method entry at line 41, stub SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`; the core getter SHA-256 is `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`. The line-41 anchor is method-level context, not a proven vulnerable operation. The source shows no local read-permission decision in the reviewed getter path, while framework authorization, caller provenance, deployment configuration, and product identity remain unverified.

## D68 and T68 review

The frozen D68 implementation is `3da049887999bd3cacb3d48da9ffa7baefa18ac5`; T68 reviewed that exact commit, and its report is in commit `f2f0f560910897ffbe8115c26a481a32372fc194`. T68's bounded-metadata and candidate-retention results are reproducible and appropriately limited: 33 focused tests passed, the exact-source replay retained the D52 candidate, and every obligation status stayed `unknown`. T68 correctly records parser coverage as partial and the detector as blocked.

The serialization bounds themselves are concrete and non-misleading for emitted fields: at most 8 records, 16 tokens per record, 48 characters per token, 120-character snippets, and 4,096 serialized characters. Total and omitted observation counts and payload/token truncation indicators are emitted. The metadata does not claim that a permission-like call authorizes the caller or dominates the read. Parentheses in nested calls are balanced, and observations are lexical snippets with body-relative offsets; they are not source line numbers or a control-flow proof.

### Concrete residual state-classification gap

A read-only probe against the frozen D68 helper exposed a cap interaction not covered by T68: create eight top-level recognized calls, then a ninth recognized call inside a braced conditional. The helper returned `state="observed_unresolved"`, `total_matches=9`, `observations_truncated=true`, `observations_omitted_count=1`, while the omitted ninth match was not inspected for control-flow state. D68 checks `_top_level_at` / `_inside_unbraced_control` only when `total_matches <= 8`; this means the record cap also caps the state scan. The status remains `unknown`, so this does not suppress the candidate or assert authorization, but `observed_unresolved` can understate unresolved syntax among omitted observations.

Minimal feedback: continue scanning every recognized match for state classification while emitting only the first eight records; alternatively add an explicit state-completeness field that becomes false when uninspected matches could affect state. Add a regression with eight top-level calls followed by a nested ninth call and require `unresolved_control_flow` (or an explicitly incomplete aggregate state). Keep the candidate disposition and all permission semantics unknown.

## Parse and replay evidence quality

D67's parse audit is useful context, not a vulnerability result. It verifies all 67 C++ hashes against the pinned source and reports 68 declared paths (67 C/C++ plus one TypeScript declaration). D68 replay reports 59 complete and 8 partial C++ parse statuses, with the TypeScript file not run and detector status blocked. D50 recorded 57 complete and 10 partial under Python 3.10.12; D68 used Python 3.13.9. D67's current-runtime ablation without the frozen D51 member-pointer normalizer reproduces D50's per-file status and issue kind/line signature, and attributes the two changed statuses to the existing normalizer in the replay. This does not recreate D50's historical runtime and does not establish historical coverage improvement. Eight current partial units and the missing TypeScript grammar remain coverage limitations.

## Downstream use and bounded followups

Send the D52 candidate to the next model only with this framing: inspect the exact pinned stub-to-core route for a plausible missing local authorization check; treat `permission_guard_observation` as lexical metadata only; treat all authorization/provenance obligations as unknown; do not infer product applicability or CVE causality. The model should identify what framework or product evidence would be needed before changing those unknowns.

1. Correct the D68 aggregate state scan/cap interaction and add the ninth-match negative control described above.
2. Preserve a state-completeness indication whenever candidates are omitted; document offsets as handler-body-relative.
3. Resolve the D67 parse manifest only with the exact historical runtime or pinned comparable runtime, TypeScript grammar, and required build/macro context; do not treat parse-status deltas as coverage gains.
4. To move beyond source-candidate review, obtain product fingerprint/version and framework permission enforcement/caller identity evidence. Until then, product and CVE conclusions remain unknown.

## Evidence boundaries

Reviewed D68 report and raw replay SHA-256 `491c63b8a5cf68497722c0c3f8c444857678c28848c07d0a9133538faaf5e13d`, T68 independent acceptance, D67 parse audit, frozen D68 helper, and the pinned source identifiers carried in those reports. This review changes no detector, fixture, test, or prior report. The one new helper probe is a synthetic syntax control, not a product execution test.
