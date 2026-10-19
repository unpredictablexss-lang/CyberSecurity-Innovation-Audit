# D65: record unresolved Pasteboard guard observations

## Scope and lineage

D65 follows frozen D64 commit `594abe600d731c72e760e730526dadb8931a9985`. T64's initial matrix confirmed D64's conservative candidate-retention behavior and raised an evidence-completeness PARTIAL: the same `permission_guard=unknown` was attached when no guard-like syntax existed and when a permission-like expression was visible.

D65 preserves the D64 narrow Binder route candidate and the `permission_guard=unknown` obligation. It adds a second, backward-compatible `EvidenceObligation` kind, `permission_guard_observation`, whose description carries one of three bounded observations:

- `absent`: no permission-like call or token appears in the `OnGetPasteData` body.
- `observed_unresolved`: a permission-like call or token appears at the handler body's top syntactic level.
- `unresolved_control_flow`: a permission-like call or token appears inside a nested brace scope in the handler body.

For visible observations, the description records handler-body character spans, normalized uppercase identifiers, and a bounded source snippet. This is observation metadata only; it does not infer an authorization decision or denial dominance. No suppression was reintroduced and D51/D52 identity/source anchors/hashes were not changed.

## Validation

The focused suite passed: `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` (32 tests). Explicit controls verify absent, visible top-level permission-like syntax with token/span, and nested guard syntax classified as unresolved control flow. Existing untrusted-state, Bluetooth-result, D63 helper, D59/D61, candidate identity, and sibling CVE controls remain covered. `git diff --check` and strict duplicate-key JSON validation passed.

T64's D64 review was PARTIAL on evidence utility. This D65 report records the implementation and local tests; it does not claim T64 has accepted D65.

## Limits

The observation parser is intentionally shallow and scans the extracted handler body. Character spans are relative to that body. A token or function name is not an API contract. The matcher does not resolve helper bodies, variable provenance, aliases, macro expansion, CFG/dominance, exception behavior, or cross-file permission semantics. `permission_guard` remains unknown in every case. CVE causality, product identity, build inclusion, runtime reachability, and vulnerability status remain unknown.
