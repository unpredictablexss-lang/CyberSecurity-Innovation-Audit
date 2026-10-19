# A-line parallel queue addendum — T20

This additive entry belongs in `research/evidence/cpp/a_line_parallel_queue_20261020.md` when the independent acceptance commit is integrated. It records T20 without importing unrelated queue changes into the D1-base checkout.

### T20 — Contacts path traversal independent acceptance (testing/evidence)

```text
Role: independent A-line C/C++ source and regression acceptance reviewer.
Continuous goal: independently verify D1 Contacts path-traversal candidate behavior against the exact A0 source object and preserve all source, parser, fixed-source, and Catalog limitations.
Inputs: clean PR #30/D1 checkout; A0 pinned Contacts object; path-traversal method card; Catalog request; detector replay and dedicated controls.
Steps: verify repo/commit/tree/blob/SHA; replay the exact vulnerable object using the submitted pinned-object command; inspect candidate locations and source semantics; rerun basename, containment, field, no-sink, separator and partial controls; verify Catalog/CLI selection behavior; record rule regression separately from case disposition.
Done when: source identities, commands, rule version, locations, parse coverage, controls, blockers, and claim boundary are independently recorded; A0/source verification and cpp change-scope checks pass.
Boundaries: do not edit detector, tests, fixtures, or Catalog; do not call synthetic controls a trusted fix; do not promote PARTIAL/BLOCK or infer vulnerability from candidate presence.
```

T20 completed on D1 head `24b1140`; rule mechanism regression is PASS while Contacts case acceptance remains BLOCK because no trusted fixed source was found, Catalog admission is outstanding, and production CLI replay is unavailable. See [T20 acceptance report](a_t20_contacts_path_traversal_acceptance_20261020.md) and [structured result](a_t20_contacts_path_traversal_acceptance_20261020.json).
