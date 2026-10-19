# D73: second-layer review of D72/T72 and D52 candidate package

## Final decision

**GO for downstream root-cause review as a `narrow`, source-only candidate.** D72 fixes the D71 offset-zero false negative, and T72 independently validates that exact commit. The D52 candidate package includes enough source identity and route context for a downstream model to inspect the root-cause hypothesis, provided the model is told that all permission/provenance semantics remain unknown. D73 found no new actionable observation-state boundary in the tested control shapes.

This is not a product or CVE verdict. Product applicability, actual framework permission enforcement, caller identity/provenance, runtime reachability, exploitability, and CVE causality remain unknown.

## Frozen identities and candidate package

- D72 implementation: `dd76d776357a79021431ed92899960dbdb3cde10`.
- T72 independent acceptance: `2f34e5bc5af7cb9a9c39555a42d4fab403312bff`, reviewing the exact D72 commit.
- Pinned source: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- D52 candidate anchor: `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.
- Core getter source SHA-256: `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- The route package identifies `GET_PASTE_DATA` dispatch to `OnGetPasteData`, then the core getter and response serialization. Line 41 is the method-entry anchor, not a proven vulnerable operation. The core getter path contains no visible local read-permission decision, while framework authorization and caller provenance are unverified.
- Candidate signature, file, line, source hash, stable identity record, and legacy diagnostic ID remain stable. The `occurrence_id` change from D70 is expected version-bound drift from `detector_version` / `rule_version`; it does not indicate route identity drift.

This is a sufficient minimum for a downstream **source-only** model prompt: pinned commit/tree and file hashes; the stub-to-core route; line-41 anchor qualification; the lexical nature of guard observations; all obligations marked unknown; D67 coverage caveat; and an explicit instruction not to infer product applicability or CVE causality.

## D71 fix and observation-state review

D72 changes the `_inside_unbraced_control` boundary so a recognized match at exactly the first non-whitespace character of an unbraced control body is considered inside that body. T72 independently reproduced the former behavior and the fixed behavior at handler offset zero and after a prefix. T72's matrix also covered direct and nested ninth matches, nested and braced bodies, a permission call in the `if` condition, and top-level calls.

D73 independently called the frozen D72 helper and observed:

| Shape | Aggregate state | Obligation status |
| --- | --- | --- |
| Handler starts `if (condition) CheckPermission(...)` | `unresolved_control_flow` | `unknown` |
| Unbraced loop body starts with permission call | `unresolved_control_flow` | `unknown` |
| Switch statement body starts with permission call | `unresolved_control_flow` | `unknown` |
| Comment between `if` condition and body call | `unresolved_control_flow` | `unknown` |
| Nested unbraced `if` body | `unresolved_control_flow` | `unknown` |
| Braced control body | `unresolved_control_flow` | `unknown` |
| Permission call in a top-level `if` condition | `observed_unresolved` | `unknown` |
| Top-level permission call | `observed_unresolved` | `unknown` |
| Eight top-level matches plus a ninth direct unbraced-if body call | `unresolved_control_flow`, 9 matches / 8 records / 1 omitted | `unknown` |

The `observed_unresolved` condition-call result is an appropriate lexical observation state, not evidence that the call grants, denies, or dominates the data read. No obligation changes from `unknown`, and no candidate suppression occurs. T72 independently reports the same condition-call interpretation. Arbitrary C++ control-flow dominance and framework policy remain outside this lexical scanner's claim.

The D68 bounds remain explicit: at most 8 records, 16 tokens per record, 48 characters per token, 120-character snippets, and 4,096 serialized characters; omitted counts and token/payload truncation markers remain present. D70's all-match aggregate state scan is preserved. Balanced nested call spans remain covered.

## Replay and coverage boundary

T72 verified all 68 declared source entries against local bytes and Git blob IDs with zero mismatches. The exact-source D72 replay digest is `f36d5cf6032a2415af0e1296d51c12677fc576e566abf60ef8065a14ebd00cf8`; the detector remains blocked with two source-only findings and zero validated vulnerabilities. Parse statuses remain 59 complete, 8 partial, and 1 TypeScript `not_run`; all 67 applicable C/C++ units remain partial at detector-coverage level.

D67 explains that the current replay used Python 3.13.9 rather than the historical D50 Python 3.10.12 runtime; the current-runtime ablation reproduces D50's status and issue-kind/line signature without the frozen D51 normalizer, but does not recreate the historical environment. The TypeScript grammar, macros, and build configuration remain unavailable. Parse-status differences are not historical coverage improvement and do not change candidate confidence into a product finding.

## Concrete prerequisite for stronger claims

The next material evidence prerequisite is a product fingerprint/version tied to the reviewed source plus framework permission-enforcement and caller-identity/provenance evidence for this IPC route. Without those, downstream review may assess only whether the pinned source path plausibly lacks a local check; it must leave product applicability and CVE causality unknown.

D73 adds review evidence only. No scanner, test, fixture, or prior report was modified. The independent helper probes are syntax controls, not product execution tests.
