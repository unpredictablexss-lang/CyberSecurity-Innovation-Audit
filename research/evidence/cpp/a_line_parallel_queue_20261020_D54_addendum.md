# D54 development addendum — libpng lifecycle cases

- Scope: libpng CVE-2026-33416 and CVE-2026-46675, current `ohscanner.cpp.resource_lifetime` 0.4.2.
- Result: no detector change. Exact vulnerable and fixed Git identities were replayed with current production CLI. 33416 is 4/4 parser-partial on both variants; 46675 is 1/1 parser-partial on both. Each run is blocked with zero findings.
- Root assessment: both source-level lifetime relations are plausible, but the current parser does not provide the cross-file typed member identity and call/state order required to distinguish them generically. D34's six complete and one partial 46675 fragments do not establish that missing relation.
- Disposition: both remain PARTIAL/BLOCK. Fixed source identities are trusted, but partial zero-finding runs do not count as fixed passes or safety evidence. A0 rows unchanged.
- Evidence: [D54 assessment](d54_libpng_lifetime_assessment_20261030.md), [JSON](d54_libpng_lifetime_assessment_20261030.json), [verifier](verify_d54_libpng_lifetime_20261030.py).
- Next required input: usable parser-visible typed field/call context and source-bound safe/unrelated controls for each relation. Do not relax parser semantics or fabricate complete coverage by stitching fragments.
