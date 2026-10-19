# D29: libpng ARM NEON palette expansion (CVE-2026-33636)

Date: 2026-10-19
Detector: `ohscanner.known_disclosed_cves` 0.9.0
Conclusion: upstream component vulnerability confirmed by the maintainer advisory; D rule retains source candidates; OpenHarmony product applicability unknown.

## Confirmed component behavior

The libpng maintainer advisory identifies versions 1.6.36–1.6.55 as affected when built with ARM/AArch64 NEON, and 1.6.56 as patched. The root cause is in `arm/palette_neon_intrinsics.c`: both palette expansion functions iterate in fixed 4-pixel (RGBA) or 8-pixel (RGB) chunks while allowing the last partial chunk. The backward-reading code can read before the row buffer and the vector store can write before the output row. The pre-adjusted destination pointer also has to be restored before the scalar tail handoff; fixing only the loop bound is incomplete.

The advisory lists these input conditions: palette PNG (color type 3), palette expansion enabled, ARM NEON enabled; RGBA additionally requires tRNS and a row width at least 5 not divisible by 4; RGB requires no tRNS and a row width greater than 8 not divisible by 8. The advisory reports reliable process crashes and describes information disclosure/heap corruption as plausible. It does not demonstrate arbitrary code execution.

## Fixed-source provenance and detector replay

The test fixtures are full upstream files with the upstream license header, fetched from the official tags and checked against Git blob IDs returned by GitHub:

| Version | Commit | Git blob SHA-1 | File SHA-256 | Expected D29 finding count |
|---|---|---|---|---:|
| libpng 1.6.55, affected | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` | `3068e9b6e62be16bee2a8f1ff8271a02f32be97f` | `d58734a03a91df0f2c11e3558354281d7613888d85c83887586560a270bffa41` | 2 |
| libpng 1.6.56, fixed | `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33` | `0967ea1aebd718907fda1e767957deeddbe676b3` | `a844760f611829df29ca583f1b08832cac1440c74a2a22b35bc35a464ddf6b5e` | 0 |

The detector checks each named function independently. It retains a candidate if either the partial vector-tail loop remains or the pre-adjusted output pointer is not restored before returning to the scalar tail. The negative control contains similarly named scalar-only functions without the NEON load/store sequence. The actual fixed file clears both conditions.

Reproduce three deterministic offline passes from the repository root:

```bash
.venv-web/bin/python research/data_sensitive/d29_libpng_neon_cve_2026_33636_replay.py
.venv-web/bin/python -m unittest \
  tests.detectors.test_known_disclosed_cves.KnownDisclosedCveTests.test_libpng_neon_palette_cve_2026_33636_exact_upstream_pair -v
.venv-web/bin/python -m unittest \
  tests.test_workbench.WorkbenchTests.test_libpng_neon_cve_candidate_and_fix_run_through_api_worker_report -v
```

The replay script makes no network requests and verifies both SHA-1 Git blob IDs and SHA-256 values before scanning. It uses `parse_status=not_run`, so both detector runs are `blocked`; the vulnerable source still yields two candidate records and the fixed source yields none. Candidate identity and coverage stay byte-for-byte stable across three rounds. The Workbench regression also checks that the old-source candidate and source hash survive the API → Worker → report → source viewer path, and that the fixed source produces no CVE-2026-33636 candidate. `validated_vulnerability` remains 0 in both reports. Full machine-readable output is in `D29_LIBPNG_NEON_CVE_2026_33636_REPLAY.json`.

This is a source-bound detector regression and source-level before/after reproduction. It is **not a runtime exploit PoC**: no ARM NEON device/emulator or product build was used in this run, and no crafted PNG was executed.

## Repair guidance and product boundary

For an application that embeds an affected libpng and reaches this optimized path, upgrade to libpng 1.6.56 or later, or review/apply the upstream fix commit [`aba9f18eba870d14fb52c5ba5d73451349e339c3`](https://github.com/pnggroup/libpng/commit/aba9f18eba870d14fb52c5ba5d73451349e339c3). That patch restricts NEON loops to complete chunks, removes the stale post-loop adjustment, and restores the pre-adjusted destination pointer before scalar processing. The upstream advisory describes disabling ARM NEON optimizations as a workaround, with a performance cost. A downstream patch should also test both functions at the advisory's boundary widths and include divisible-width controls.

The G-drive OpenHarmony source review says the corresponding libpng patch is already present in the current snapshot. This is evidence about that mirror snapshot only. The product's exact libpng source/build, ARM optimization flags, palette input reachability, and affected deployed versions remain unknown here. Do not report an OpenHarmony product vulnerability or claim product remediation based on this component replay. Product status remains `candidate/unknown`; `validated_vulnerability=0`.

## Primary references

- [libpng maintainer advisory GHSA-wjr5-c57x-95m2 / CVE-2026-33636](https://github.com/pnggroup/libpng/security/advisories/GHSA-wjr5-c57x-95m2)
- [upstream fix commit aba9f18](https://github.com/pnggroup/libpng/commit/aba9f18eba870d14fb52c5ba5d73451349e339c3)
- [affected source v1.6.55](https://github.com/pnggroup/libpng/blob/v1.6.55/arm/palette_neon_intrinsics.c)
- [fixed source v1.6.56](https://github.com/pnggroup/libpng/blob/v1.6.56/arm/palette_neon_intrinsics.c)
