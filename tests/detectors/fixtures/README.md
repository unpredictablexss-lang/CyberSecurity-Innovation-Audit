# Detector fixtures

These directories contain small, self-authored synthetic C++ fixtures for
detector development and contract-semantics tests. They are not public
OpenHarmony vulnerability samples and must not be used to compute benchmark
Precision/Recall.

Each `manifest.json` binds:

- repository-relative path;
- exact source SHA-256;
- fixture-set snapshot SHA-256;
- parse status and parse issues;
- fixture category;
- synthetic provenance.

The loader rejects source-hash, snapshot-hash, duplicate-path and cross-fixture
mixing errors before a detector runs. Fixture categories describe development
controls only; they are not vulnerability verdicts. `expected_observation` means
the expected candidate shape (`candidate_shape` or `no_candidate_shape`) for
complete synthetic controls, or `unknown_incomplete_analysis` for `partial` and
`failed` units. Empty findings and `completed` execution never establish safety,
and incomplete analysis is never a benchmark miss.
