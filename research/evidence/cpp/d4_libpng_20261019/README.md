# D4 libpng resource lifetime review

Date: 2026-10-19 (Asia/Shanghai)
Scanner base: `940409d3670dafd036b0e8afcbdbe479d815230c` (contains D3 `0.3.0`)
Detector: `ohscanner.cpp.resource_lifetime` `0.3.0`
Disposition: both cases remain `PARTIAL/BLOCK`; no detector change is justified by the current parse coverage.

## Frozen evidence reviewed

Read T1's `research/evidence/cpp/a_static_baseline_20261019/README.md` and `matrix.json`, the T3 first/second-wave acceptance report at commit `6f91589`, and D3's `research/evidence/cpp/D3_RECURSIVE_CLEANUP_20261019.md`. T3 explicitly leaves both libpng cases partial and calls for parser/context coverage before stronger claims. D3 records the earlier 0.3.0 parser blockers and the absence of product build/call-path proof.

## D3 frozen detector replay

The production CLI was rerun on exact locally pinned Git objects with profile `light-ast` and the T1 scopes. Raw JSON/Markdown reports are in this directory.

| Case/input | Commit | Tree | Scope | Parse | Detector | Findings | Time |
|---|---|---|---|---|---|---:|---:|
| CVE-2026-33416 vulnerable v1.6.55 | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` | `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `pngset.c`, `png.c`, `pngread.c`, `pngrtran.c` | 4/4 partial | 0.3.0 blocked | 0 | 0.383268 s |
| CVE-2026-33416 fixed v1.6.56 | `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` | `a28bb962645843af84063c77f574f6d88da79f76` | same four files | 4/4 partial | 0.3.0 blocked | 0 | 0.388361 s |
| CVE-2026-33416 OH source snapshot | `f3ef808f45af32fabed16e1796ee82598c17e9f7` | `47d092e8fc7e5c94a03bea1bd50fcfd10defe23d` | same four files | 4/4 partial | 0.3.0 blocked | 0 | 0.388031 s |
| CVE-2026-46675 vulnerable-byte snapshot | `e283ed5d3a74c0112f092ddb1003c97e0e9a4717` | `c78da20c3ffe37b09653eaa3b49c5213745ac4bd` | `vulnerable-1.6.55/pngrutil.c` | 1/1 partial | 0.3.0 blocked | 0 | 0.095550 s |
| CVE-2026-46675 fixed-byte snapshot | same synthetic commit | same synthetic tree | `fixed/pngrutil.c` | 1/1 partial | 0.3.0 blocked | 0 | 0.094592 s |

The 46675 variants are separate byte-bound snapshots under one synthetic repository identity; the source bytes are distinct. Vulnerable `pngrutil.c` SHA-256 is `b328fb05352226866b1e44c8cddd3e03df35413f1f38f4d81ba51afe4f2333a5e`; fixed SHA-256 is `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`. Upstream source identities recorded by T1 are v1.6.55 commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`; fixed commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`, blob `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`. Upstream trees were not available for this case.

For 33416, T1 binds upstream v1.6.55 and v1.6.56 trees above. Vulnerable selected-file SHA-256 values: `pngset.c` `9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0`, `png.c` `0d8e45e9039cf04088764a09dcda7b24695f199288a44e11dba54ebfaca1c730`, `pngread.c` `feee8bdd4c553cc4f01bb288a868d4b83e1ce0f75014a96163a49eb32119cba6`, `pngrtran.c` `4df05c2e5db00911817d7f125c862524205895f34a65106e016d351f7e6edb53`. The OH archive identity is commit `e57b1079564a02a50321ec528aa6e41884979d32`, tree `02b17492f4490ff2e4d17ba74e2080358a500059`, archive SHA-256 `71a2c5b1218f60c4c6d2f1954c7eb20132156cae90bdb90b566c24db002782a6`.

## Root-cause review and decision

### CVE-2026-33416

The source mechanism is concrete: `png_set_PLTE` and `png_set_tRNS` store the same allocation in `png_info` and `png_struct`; cleanup/replacement through `png_info` frees and clears only that owner's field, leaving the `png_struct` alias available to later transforms. `pngrtran.c` reads or writes `png_ptr->trans_alpha` and `png_ptr->palette`. T1's later uncommitted scanner snapshot at `9b99f10` reported 2 vulnerable candidates versus 0 fixed candidates, but all four files were partial; those findings were not complete-parser acceptance and that detector state is not present in frozen D3. The frozen D3 CLI replay above gives 0/0 with all files partial. The component ASan evidence summarized in T1's ledger reproduced tRNS and palette sequences on pinned libpng 1.6.55 and quieted them on 1.6.56/controls, while product linkage and exact application call sequence remain unknown.

This is not a sound static pass or a classifiable complete-parse miss. Implementing a new cross-function alias/owner rule now would depend on structure identity, ownership invalidation, and call ordering across four parser-partial files; a narrow name/field heuristic would overstate coverage and risk unrelated pointer aliases. Keep BLOCK until a parser profile can produce usable declarations/field identity and the candidate can be independently exercised on source-bound safe/unrelated controls under that profile.

### CVE-2026-46675

The official root cause is a released zstream retaining `next_in`/`avail_in` into transient chunk or stack storage after failed/incomplete text/profile decompression. A later `png_read_info` then `png_read_end` sequence without row reads may let IDAT processing inflate from the stale pointer. The official fix adds buffer detachment and clears zstream pointers/counters. The source copies bind the exact vulnerable/fixed `pngrutil.c` bytes. T1's case record reports component-level ASan UAF evidence for the corrected malformed-zTXt trigger and suppression by the official fix/read-rows control; product API sequence remains unknown.

There is no existing D3 rule for this zstream state transition, and the exact affected TU is partial in both byte variants. The case requires state tracking across acquisition/release and later IDAT consumption, not generic recursive resource lifetime detection. A detector change without complete parsing and a stable caller/state model would be a guessed signature. Keep BLOCK/PARTIAL and request complete parse context plus a source-bound call sequence before implementation.

## Minimum missing evidence

- A source-bound parser configuration/profile with the relevant headers, feature macros and declarations so the selected target functions and struct fields are represented and parser status can be complete or have a documented safe partial-candidate contract.
- For 33416, complete field/type identity and release/use call sequence over `pngset.c`, `png.c`, `pngread.c`, `pngrtran.c`, with pinned vulnerable/fixed/safe/unrelated controls.
- For 46675, parser-visible zstream ownership transitions and caller order through text/profile decompression, `png_read_info`, and `png_read_end`, with the corrected malformed chunk and fixed/read-rows controls.
- Product build/link selection and application PNG call path before making a product claim. These are not prerequisites for component-level static candidates but remain required for product conclusions.

No `resource_lifetime` detector code or fixtures were changed in D4. The raw CLI reports retain source commit/tree/snapshot, selected scope, parser coverage, detector/rule version, finding count, and elapsed time. `BLOCK/PARTIAL` is preserved; zero findings on partial source are not interpreted as fixed or safe.
