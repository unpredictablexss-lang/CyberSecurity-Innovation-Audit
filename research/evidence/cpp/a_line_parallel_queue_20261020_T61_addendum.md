# T61 — Independent libpng acceptance for CVE-2026-33416 and CVE-2026-46675

**Disposition: both PARTIAL/BLOCK.** T61 independently checked vulnerable/fixed commit and tree identities, exact target-file blob IDs and hashes, current D54 production CLI artifact hashes, and fresh parser/function-fragment replay on the exact files. No detector/test/fixture/A0 changes were made.

- **33416:** vulnerable source is libpng commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, tree `e01f5780f93eaa6d74cca003bb39b427c8f1e910`; exact 1.6.56 fixed release is `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`, tree `a28bb962645843af84063c77f574f6d88da79f76`. Current CLI: 0 candidates on each side, all four target files partial. All eight extracted function slices also partial and zero. The fixed commit header names parent `5f9a0b1e5ed1f096107dfd76fd16217f94a29673`, but that object is absent from the local shallow mirror; it is not a tested control.
- **46675:** exact vulnerable and fixed commits/trees/file blobs match T11/T34 source binding. Current CLI: 0 candidates on each side, 72 parse issues each, both blocked/partial. The fixed parent `4eeb825ab26605ed34cd74495d4cce920939fe9f` is present and its tree/file hash was checked; it is pre-fix ancestry, not a safe control.
- The four-file OH/M2 33416 run is an extracted replay scope. Neither it nor generic detector fixtures count as source-bound safe/unrelated controls. No suitable CVE-specific safe/unrelated controls were found. Do not accept either zero/zero result as fixed PASS.
- The existing T23 A0 verifier record reports 345 unique rows and preserved statuses; T61 did not modify or independently rerun that external A0 verifier.

See [full acceptance report](t61_libpng_independent_acceptance_20261020.md), [machine audit](t61_libpng_independent_acceptance_20261020.json), [fresh parser/fragment replay](t61_libpng_current_replay_20261020.json), and [verifier](verify_t61_libpng_acceptance_20261020.py).
