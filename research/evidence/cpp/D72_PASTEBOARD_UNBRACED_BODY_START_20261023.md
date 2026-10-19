# D72 Pasteboard unbraced control at body start

## Change

D72 starts from frozen D70 commit `f628c90901d71510e60869c027e4c7903d2d4de6`. `_inside_unbraced_control` now treats a permission-like match at exactly the start of an unbraced control body as inside that body. Previously, `body_start == position` was skipped, so a handler body beginning `if (condition) CheckPermission(READ_PASTEBOARD);` was observed as top-level. The change preserves D70's all-match aggregate evaluation and D68's serialized record/token/snippet/payload caps and balanced call spans. `permission_guard` remains `unknown`; there is no candidate suppression or authorization inference.

## Constructive validation

The focused suite passed: `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus` (33/33). Added controls cover:

- a brace-less `if` whose body starts at handler offset zero;
- a brace-less `if` after a leading statement;
- eight top-level observations followed by a ninth direct brace-less `if` permission call;
- eight top-level observations followed by a ninth nested brace-less `if` permission call;
- nested `if` and braced control bodies;
- entirely top-level permission calls, which remain `observed_unresolved`.

The D70 ninth-record aggregation regression still checks 8 emitted records, 9 total matches, one omitted observation, and `unresolved_control_flow`. The D52 route integration check confirms candidate retention and `permission_guard=unknown`.

## Exact source replay

The replay used the pinned Pasteboard source commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` and tree `e374a0d61c9ec664ddd29fc17002797828c480ee`. The raw report is `D72_PASTEBOARD_RAW67_REPLAY_20261023.json` (SHA-256 `f36d5cf6032a2415af0e1296d51c12677fc576e566abf60ef8065a14ebd00cf8`). It completed with limitations: 59 complete, 8 partial, and 1 TypeScript unit not run; detector coverage remains blocked/partial with two findings.

Both existing candidates remain bound to the same source anchors and hashes:

- `CVE-2025-25212` at `services/core/src/pasteboard_service.cpp:241`, SHA-256 `73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52`.
- D52 `CVE-2025-27247` at `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`.

No vulnerability was validated. Permission semantics, CVE causality, and product applicability remain unknown. `git diff --check` and strict JSON parsing passed.
