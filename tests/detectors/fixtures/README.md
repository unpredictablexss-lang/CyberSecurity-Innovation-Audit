# Detector fixtures

These directories contain small, self-authored synthetic C++ fixtures for
detector development and contract-semantics tests. They are not public
OpenHarmony vulnerability samples and must not be used to compute benchmark
Precision/Recall.

Each `manifest.json` binds:

- repository-relative path;
- exact source SHA-256;
- parse status and parse issues;
- fixture category;
- synthetic provenance.

Expected diagnostic counts are development assertions only. `partial` and
`failed` fixtures verify that missing analysis stays unknown/failed rather than
becoming safe or benchmark miss.
