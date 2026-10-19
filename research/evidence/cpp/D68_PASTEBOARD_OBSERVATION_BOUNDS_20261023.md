# D68: bound Pasteboard guard observation metadata

## Change

D68 is based on frozen D65 commit `dd7881d81e49d333ac2bd52062706ed06c5694c5`. It keeps the narrow D52 route candidate and `permission_guard=unknown`, and never suppresses a candidate or infers authorization. It hardens only `permission_guard_observation`:

- at most 8 observation records, with total match count and omitted-record count;
- at most 16 normalized tokens per record, with omitted-token count and explicit `tokens_truncated`;
- each snippet is at most 120 characters;
- the serialized observation description is at most 4,096 characters, with explicit payload truncation fields;
- permission-call spans use balanced delimiter matching, including nested call arguments;
- unbraced nested `if`/loop/switch/catch bodies are classified `unresolved_control_flow`; uncertain or malformed delimiters conservatively use that state.

Observation state remains descriptive. Even `observed_unresolved` does not establish an effective guard. D51/D52 candidate identity, line-41 anchor, and source hash remain unchanged.

## Constructive tests

The focused suite passed 33/33 tests. New controls use 3,000 distinct identifiers in one guard call, 12 guard calls, a nested permission call, and an unbraced nested `if`. They verify the per-record and full-description bounds, omitted counts, explicit truncation markers, exact balanced call span, and conservative control-flow state. `git diff --check` passed.

## Raw source replay

The replay uses the exact D50 source commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, with tree `e374a0d61c9ec664ddd29fc17002797828c480ee`. The checkout was fetched from the repository mirror and independently checked against the D50 tree and the D52 stub/core blob IDs and SHA-256 values. The declared source set is 68 files: 67 C/C++ files plus one TypeScript declaration. The detector's applicable scope is 67 C/C++ files; the TypeScript file is the `not_run` boundary.

The D68 replay ran on Python 3.13.9 with tree-sitter 0.26.0, tree-sitter-c 0.24.2, and tree-sitter-cpp 0.23.4; JavaScript/TypeScript grammars were unavailable. It produced 59 complete, 8 partial, and 1 not_run source parse statuses; detector status remains blocked and there are two findings. All 67 C/C++ source SHA-256 values match the D50 artifact. Relative to D50's recorded 57 complete, 10 partial, and 1 not_run, the two files `services/zidl/src/pasteboard_observer_stub.cpp` and `services/zidl/src/pasteboard_service_stub.cpp` are complete in this replay. Their D50 error issues were respectively line 46 and line 58.

This is an exact-source replay under a different runtime and a newer detector revision, not a rerun of D50's Python 3.10.12 environment and not evidence that historical coverage improved. The current D68 runtime/parser version differs from D50's Python version; the two observed parse-status changes are recorded without attributing a root cause to Python, parser grammar, or scanner code. The raw report is `D68_PASTEBOARD_RAW67_REPLAY_20261023.json` (SHA-256 `491c63b8a5cf68497722c0c3f8c444857678c28848c07d0a9133538faaf5e13d`).

The D52 candidate remains `CVE-2025-27247` at `services/zidl/src/pasteboard_service_stub.cpp:41`, SHA-256 `d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868`. The sibling `CVE-2025-25212` identity and source hash also remain present; its current line is reported by the current detector revision and is not a D68 target anchor.

## Acceptance boundary

T68 independent acceptance is pending. This replay does not establish product applicability, CVE causality, framework permission behavior, runtime reachability, exploitability, or product safety. The exact D50 Python 3.10.12 runtime was not recreated.
