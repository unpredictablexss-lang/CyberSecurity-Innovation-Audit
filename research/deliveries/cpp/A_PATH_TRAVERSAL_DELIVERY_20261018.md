# A-line path traversal candidate delivery (2026-10-18)

- Lane: `cpp`; branch: `codex/a-path-source-sink-20261018`.
- Base: `1c21ac60890fca0ce6be5d50d82e4757dd5e4623` (`origin/main`, exact worktree base).
- Source selection: new bounded research implementation; no files cherry-picked from another branch. It is not registered in the production catalog and does not change shared contracts.
- Changed files: `src/ohscanner/detectors/cpp/path_traversal_detector.py`, `tests/detectors/test_cpp_path_traversal_detector.py`, and `tests/detectors/fixtures/cpp_path_traversal/*`.
- Behavior: models typed `DataShareValuesBucket` string accessors, simple same-translation-unit aliases and bounded same-file summaries to direct libc file sinks. Emits CWE-22 candidate evidence for uncontained paths; basename, canonical containment, and literal allowlist controls suppress candidates. Unresolved cross-function and partial-parse cases stay blocked/unknown.
- Verification: `python -m unittest tests.detectors.test_cpp_path_traversal_detector -v` — 6 passed; `python -m unittest discover -s tests/detectors -v` — 137 passed; `python -m scripts.check_change_scope --base 1c21ac60890fca0ce6be5d50d82e4757dd5e4623 --lane cpp` — 0 violations. One initial combined invocation reported two transient failures; isolated reruns and the full suite then passed without source changes.
- Evidence boundary: lexical candidate only; no production catalog registration, attacker reachability, filesystem race/symlink semantics, or CIA impact is established. No Precision/Recall claim is made.
- Public interface request: none.
