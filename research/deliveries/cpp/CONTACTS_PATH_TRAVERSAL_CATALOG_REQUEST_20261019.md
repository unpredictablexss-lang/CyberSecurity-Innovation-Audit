# Catalog admission request: C/C++ path traversal candidate

Owner review requested for detector `ohscanner.cpp.path_traversal`, version `0.1.0`, implemented at `src/ohscanner/detectors/cpp/path_traversal_detector.py`.

## Proposed registration

- Factory: `src.ohscanner.detectors.cpp.path_traversal_detector:CppPathTraversalDetector`
- Languages: `c`, `cpp`
- Rule: `ohcpp-path-traversal-source-to-file-sink-candidate-001`
- Default: opt-in only; do not enable by default before review.
- Output: existing `DetectorRun` and `DetectorFinding` fields; no API/schema changes.

## Evidence and verification

Focused suite: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v` (6 tests passed on the D1 branch). The pinned local Contacts working copy emitted source-to-sink candidates at lines 792, 793 and 797, with parse coverage explicitly set to `partial`; its checkout SHA-256 differs from the A0 Git-object SHA due Windows line-ending conversion and is not represented as an exact A0 replay. The run record is `research/evidence/cpp/contacts_path_traversal_20261019/CONTACTS_PATH_TRAVERSAL_REPLAY_20261019.md`.

## Known limitations for review

- The prototype is a bounded lexical may-flow analysis, not full taint or path semantics.
- The exact A0 source object is identified in the T1 record as repo `applications/standard/contacts_data`, commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`, tree `2054824c04bb403eeea128a9262edfb3001efa4f`, blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, source SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`. This Windows checkout was not byte-identical, so the exact object remains un-replayed here.
- No trusted fixed Contacts source was available. Synthetic basename and containment controls do not satisfy a real fixed-version comparison; that evidence item is `BLOCK`.
- The current CLI cannot select this unregistered detector. Do not claim production scanner integration until the owner approves Catalog admission and reruns CLI integration.
