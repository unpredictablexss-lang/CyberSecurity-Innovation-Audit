# D36 — Preferences `dbpreferencesbasevalue_fuzzer.cpp`

**Purpose:** Reproduce CR-0041–CR-0065 on exact A0 source and distinguish harness candidates from production race evidence.

**Parallel boundary:** Development/evidence replay only. No detector, fixture, shared API, or Catalog changes. Independent test line should verify the pinned bindings and findings in a separate checkout before any acceptance.

**Status:** Source identity bound; current CLI replay complete; 25/25 line candidates; GN test-only fuzz target confirmed; case PARTIAL; A0 queue unchanged. Next work requires production target, call chain, and same-object concurrency/synchronization evidence.

**Reusable prompt:** See the structured vibe-coding prompt at the end of [D36 report](d36_preferences_basevalue_20261024.md).
