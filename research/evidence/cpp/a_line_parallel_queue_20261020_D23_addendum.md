# A-line parallel queue addendum — D23

### D23 — shared_ptr race candidate model assessment (development)

```text
Role: A-line C/C++ concurrency candidate detector developer.
Continuous goal: improve generic shared_ptr race candidate quality without treating container snapshots or shared ownership as proof of a data race.
Inputs: immutable A0 CR-0001–CR-0004 source object; current shared_ptr_race detector and existing regression controls.
Steps: verify exact commit/tree/blob/SHA; replay the target header and a bounded exact source set of related implementation files; trace each field operation to readers/writers and lock/thread protocols; change the detector only for a source-reproduced generic model gap with safe/unrelated/renamed/partial controls.
Done when: either a generic detector improvement passes focused controls and exact-source replay, or a no-change report identifies the supported semantic boundary and missing target scheduling facts; full scope and performance remain explicit.
Boundaries: no file/symbol/CVE-specific hardcoding, no shared parser/API/Catalog edits, no race or safety claim from zero candidates, no A0 queue status changes.
```

D23 completed as a no-change assessment. The header-only scan parsed 1 file completely and emitted no findings. The expanded exact-source scope parsed 2 files completely and 1 partially (the event-handler file has a line-72 parse error); it also emitted no findings with `ohscanner.cpp.shared_ptr_race` 0.5.1 / `ohcpp-shared-ptr-race-candidate-001` in 0.025 seconds. The candidate lines manipulate `shared_ptr` containers, but same-object cross-thread unsynchronized access was not established. Keep zero findings as inconclusive. See the [D23 report](d23_supervisor_shared_ptr_race_20261020.md) and raw [header-only](d23_supervisor_race_header_baseline_20261020.json) / [expanded-scope](d23_supervisor_race_fragment_20261020.json) CLI results.

### T23 — independent acceptance of D23 source replay (testing)

```text
Role: independent A-line C/C++ regression and provenance auditor.
Continuous goal: independently reproduce D23's exact source scopes and decide whether its no-change conclusion and limits are supported.
Inputs: frozen D23 commit/report/raw JSON; original A0 CR-0001–CR-0004 queue rows; exact project Git objects; current shared_ptr_race test suite.
Steps: rebind commit/tree/blob/SHA and candidate lines; rerun header-only and expanded-scope scans; inspect detector/rule version, parse coverage, candidate output and limitations; rerun the focused controls, A0 verifier, scope and diff checks.
Done when: source identity and both runs match, the partial parse and zero-finding boundary are explicit, and the four A0 states remain unchanged; file any discrepancy as a bounded D23 follow-up.
Boundaries: no detector/test/fixture changes; do not treat zero findings as safety or TSan confirmation; preserve `not_testable / paused_pending_evidence`.
```
