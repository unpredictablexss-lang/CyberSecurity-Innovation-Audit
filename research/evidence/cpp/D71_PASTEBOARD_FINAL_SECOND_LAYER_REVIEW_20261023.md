# D71: final second-layer review of D70/T70

## Decision

**D52 source candidate: `narrow`; suitable for downstream source-root-cause review with the residual observation-state gap below made explicit.** Source identity and route are stable. `permission_guard`, `permission_guard_observation.status`, product applicability, and CVE causality remain unknown. The evidence does not support a product vulnerability or permission-bypass conclusion.

D70 correctly closes D69's record-cap aggregate gap: matches beyond the first eight emitted records are scanned and can change aggregate state. T70 independently confirmed this for its two ninth-match cases, and D71 reproduced the brace-nested case. There is, however, a separate unbraced-control boundary case not included in T70's input matrix.

## Frozen identities and candidate

- D70: `f628c90901d71510e60869c027e4c7903d2d4de6`, detector version `0.19.11`.
- T70: `aa0559c25dd47bec83a9a22b30adf7c805eaa83e`, reviewed the exact D70 commit.
- Pinned source: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- D52 candidate: `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Core getter SHA-256: `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.

The line-41 method-entry anchor supports locating the route; it is not itself a demonstrated vulnerable operation. The stub dispatches `GET_PASTE_DATA` to `OnGetPasteData`, which reaches the core getter and serializes data. The reviewed core path does not show a local read-permission decision. Framework enforcement, caller provenance, product configuration, and product identity are not established by these sources.

T70 verifies that the layered stable identity and legacy diagnostic IDs remain unchanged. `occurrence_id` drift from D68 is expected because its basis changed only in `detector_version` and `rule_version`; this is version-bound identity drift, not candidate route drift.

## D70/T70 aggregate and bound review

The D70 code increments `total_matches` and evaluates `_top_level_at` / `_inside_unbraced_control` before deciding whether to append an observation record. Thus the eight-record cap no longer gates aggregate classification. It reports match count, omitted count, and truncation state. T70 checked 12 calls, 3,000 identifiers, balanced nested spans, payload truncation, and both brace-nested and nested-if ninth-match cases. D70/T70 report obligation status as `unknown`, and neither guard observations nor aggregation suppress the candidate.

The documented limits remain explicit: 8 records, 16 tokens per record, 48 characters per token, 120-character snippets, and 4,096 serialized characters. The D70 raw replay digest matches the report; T70 independently matched the pinned source files and blobs. Token and payload truncation metadata are present. The descriptions remain lexical observations with handler-body-relative offsets, not permission proof or dominance analysis.

## Concrete residual: single unbraced if body at the exact start position

The T70 ninth-match case is an unbraced nested `if` whose permission call occurs in the inner `if` condition. A direct single-if body case exposes another boundary:

```cpp
if (condition) CheckPermission(READ_PASTEBOARD);
```

Read-only D71 helper probe: eight top-level `CheckPermission(PERMISSION_Xn);` calls followed by the snippet above returns `total_matches=9`, eight records, one omitted, `observations_truncated=true`, and `state="observed_unresolved"`. The obligation status stays `unknown`. Directly, `_inside_unbraced_control` returns false for the permission call at the exact first character of the unbraced if-body: its `body_start >= position` check skips the control when both offsets are equal. For the same ninth call inside braces, aggregate state is `unresolved_control_flow`.

This does not create an authorization inference or candidate suppression. It means the more specific `unresolved_control_flow` label misses a real unbraced body shape, despite D68/D70 describing unbraced control bodies as unresolved. The aggregate cap fix is sound for matches it classifies; the syntax recognizer still has a start-boundary false negative.

Minimal actionable fix: distinguish a match that is the first token of an unbraced control body from a match inside the control condition, and cover the equality boundary. Add controls for a ninth match as the direct body of one unbraced `if`, a direct body of nested unbraced `if`, and a permission call in the condition. Keep all obligation statuses unknown and avoid changes to candidate disposition based on these shapes.

## D67 and replay coverage context

D67 verifies hashes for all 67 C++ units in the 68-path manifest; one TypeScript declaration remains `not_run`. D70 replay has 59 complete and 8 partial C++ parser statuses, TypeScript `not_run`, detector status `blocked`, 67 applicable units partially inspected, and zero validated vulnerabilities. D50's 57/10 parse status was from Python 3.10.12, while D68/D70 used Python 3.13.9. D67's current-runtime ablation without the frozen D51 normalizer reproduces D50's per-file status and issue-kind/line signature, but does not recreate the historical Python runtime. Treat the two status changes as replay/tooling context, not historical coverage improvement. Missing macro/build context and TypeScript grammar remain limits.

D69's first cap issue is closed by D70's all-match state scan. D71's single-if body case is a separate residual in the inherited control-flow classifier, not a recurrence of the cap bug.

## Downstream decision and next task-tree item

The D52 route candidate can be sent downstream now as a **narrow, source-only root-cause hypothesis**, with these constraints: inspect the pinned route, treat the guard metadata as lexical and incomplete, keep all permission/provenance obligations unknown, and do not infer product applicability or CVE causality. Include the single-if body false-negative as a metadata limitation so `observed_unresolved` is not mistaken for proof that no control-flow structure exists.

Recommended next item: **D72** — fix and independently accept the exact unbraced-body start-boundary classification, with negative controls for direct body, nested body, condition, and brace forms; preserve caps, candidate retention, unknown obligations, exact source replay and identity fields. A separate coverage task should resolve D67's pinned TypeScript parser and build/macro dependencies before making broader parser-coverage claims.

## Evidence boundaries

D71 is a source and static-observation review. The new control is a synthetic helper probe, not product execution. No source detector, test, fixture, or earlier report was modified in D71. Product identity, framework authorization, CVE causality, reachability, exploitability, and product safety remain unknown.
