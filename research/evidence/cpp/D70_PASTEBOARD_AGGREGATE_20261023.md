# D70 Pasteboard observation aggregate

## Change

D70 starts from frozen D68 commit `3da049887999bd3cacb3d48da9ffa7baefa18ac5`. The observation scanner now evaluates the aggregate `state` across every permission-like match in the handler body. The eight-record output cap limits only serialized records; matches after record eight still affect `unresolved_control_flow`. Existing bounds, balanced call spans, token caps, snippet caps, payload truncation markers, and conservative `permission_guard=unknown` behavior remain in place. No permission inference or candidate suppression was added.

The constructive regression uses eight top-level permission calls followed by a ninth permission call inside a brace-less nested `if`. It verifies `total_matches=9`, at most eight emitted observations, `observations_omitted_count=1`, `state=unresolved_control_flow`, retained CVE-2025-27247 route candidate, and `permission_guard=unknown`.

## Validation

Focused tests passed: `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` (33/33). This includes the D68 cap, token, snippet, payload, balanced nested-call, and unbraced-control probes plus the D70 ninth-match adversary. `git diff --check` passed.

The exact source replay used repository `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`, and the pinned source checkout. The D70 raw replay report is `D70_PASTEBOARD_RAW67_REPLAY_20261023.json` (SHA-256 `CD6472D26E136B366AEC2BB6872FFD870694E60DBBF023CA411FB232AE4DB3C6`). It completed with limitations: 59 complete, 8 partial, 1 TypeScript not_run; detector blocked/partial with two source-only findings.

The replay retains both established candidates and source bindings:

- `CVE-2025-25212`, `services/core/src/pasteboard_service.cpp:241`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 `CVE-2025-27247`, `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.

Candidate identities and source hashes are unchanged from the D68 replay. The detector patch version is `0.19.11`; the source route, anchor, and candidate signatures were not modified. `validated_vulnerability=0`; CVE causality, product applicability, and actual permission semantics remain unknown. The replay does not claim product safety or complete parser coverage.

## Files

- `src/ohscanner/detectors/known_cves.py`: aggregate state over all matches; detector patch version incremented.
- `tests/detectors/test_known_disclosed_cves.py`: ninth-match hidden-control-flow regression.
- `tests/detectors/test_known_case_corpus.py`: expected detector version.
- `research/evidence/cpp/D70_PASTEBOARD_RAW67_REPLAY_20261023.json` and `.md`: exact-source replay evidence.
- `research/evidence/cpp/D70_PASTEBOARD_AGGREGATE_20261023.json`: compact task summary.
