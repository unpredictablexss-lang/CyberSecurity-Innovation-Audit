# Catalog admission request: C/C++ path traversal candidate

Owner review requested for detector `ohscanner.cpp.path_traversal`, version `0.3.0`, implemented at `src/ohscanner/detectors/cpp/path_traversal_detector.py`.

## Proposed registration

- Factory: `src.ohscanner.detectors.cpp.path_traversal_detector:CppPathTraversalDetector`
- Languages: `c`, `cpp`
- Rule: `ohcpp-path-traversal-source-to-file-sink-candidate-001`
- Default: opt-in only; do not enable by default before review.
- Output: existing `DetectorRun` and `DetectorFinding` fields; no API/schema changes.

## Exact source and current replay

A0 Contacts source: repo `applications/standard/contacts_data`, `OpenHarmony-6.1-LTS` commit `b02aadfc2d801ee30573fcb2d13490298e146fea`, tree `ef183625ccbc842f47b076eb75e68b665d7c21c6`, path `dataBusiness/contacts/src/contacts_data_ability.cpp`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. The previous D1 draft wrongly paired this A0 identity with master commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`; that master has tree `2054824c04bb403eeea128a9262edfb3001efa4f`, but its target path is blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, 85,339 bytes, SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`.

The refreshed exact-object direct replay reports 3 source-to-file-sink candidates at lines 789, 790, 794; parser `light-ast` is complete with 0 issues. D5 now supplies a deterministic symbol scope and expression fingerprint, so `identity_quality=complete` describes these syntax observations only. It does not prove source trust, vulnerability, control flow, or filesystem behavior. The field validation inspected at A0 checks bucket presence/type and non-empty strings, not path separators or containment; line 790 remains a candidate with upstream semantics unknown. Raw output and command are in `research/evidence/cpp/contacts_path_traversal_20261019/contacts_61lts_exact_object_replay_20261019.json` and `CONTACTS_PATH_TRAVERSAL_REPLAY_20261019.md`. D5 revision 2 applies separator guards per sink, checks exact receiver and prior position, and adds late-guard, mixed-condition, and two-sink controls. Focused tests: 12 passed; full C++ detector suite: 153 passed; scope check: 0 violations; diff check passed.

D5 recognizes only direct slash/backslash rejection checks with positive found-separator polarity (`!= npos`) on the sink's exact argument and before that sink. Mixed conditions and caller/callee validation are not treated as proof. Basename and containment, explicit component rejection, presence-only, reversed-polarity, late-guard, mixed-receiver, multi-sink, unrelated field/API, no-sink and partial-parser controls are covered by focused synthetic tests. Catalog registration remains owner-controlled; this request is not production coverage evidence.

## Known limitations for review

- The prototype is a bounded lexical may-flow analysis, not full taint or path semantics.
- A local bare-object search covered 660 commits, 659 with the target path and 32 unique file blobs; all non-A0 versions checked retained the vulnerable path construction, and no descendants of the pinned 6.1-LTS source commit were available. No trusted fixed source was found, so fixed comparison remains `BLOCK`.
- The current CLI cannot select this unregistered detector. Do not claim production scanner integration until the owner approves Catalog admission and reruns CLI integration.
- Parser syntax completeness does not resolve runtime path behavior, macro configuration, product build inclusion, permissions, or impact.
