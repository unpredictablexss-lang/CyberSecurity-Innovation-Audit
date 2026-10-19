# Detector / PoC coverage matrix

Current family-level controlled evidence. A PoC is required before a candidate
family is described as dynamically reproduced; it does not automatically promote
the candidate to confirmed/reportable.

| Detector family | Detector version | PoC | Dynamic result | Remaining gate |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `0.5.0` | `src/ohscanner/poc/cpp_shared_ptr_race.py` | v0.5 rerun: vulnerable/upstream-fix TSan `3/3`; fully-atomic patch clean `3/3` | Git-object provenance and product reachability unknown |
| `ohscanner.cpp.lifetime` | `0.4.0` | `src/ohscanner/poc/cpp_lifetime_uaf.py` | v0.4 rerun: four ASan invalidation variants `3/3`; two controls clean `3/3` | self-authored workload; product reachability unknown |
| `ohscanner.interface.ipc` | family-specific | `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/` + `outputs/poc-loop/auth01-20261014/run-003/` (local evidence; harness source is committed) | AUTH-01 vulnerable attack `3/3`, fixed rejection and patch revalidation; reachability remains partial | unprivileged handle acquisition, identity and CIA impact unknown |

Rules for this matrix:

- `candidate/unassessed` remains the default even after dynamic reproduction.
- A clean control or patch revalidation is not a global safety claim.
- Missing PoC, partial reachability or unresolved provenance stays explicit.
- Historical reports, candidate IDs and review records are not rewritten.
## Four-class control matrix (2026-10-15)

`research/tests/cpp_detector_controls/` is the repeatable A-line development
control package for both detectors. It contains 20 self-authored sources:
7 vulnerable, 6 patch-bound fixed, 5 safe and 2 unrelated. Each item records
source/blob hashes, build arguments, sanitizer, expected root cause and expected
Detector result. The final run executed 20 detector controls and 60 native
sanitizer runs: 21 vulnerable runs triggered and 39 negative-control runs were
clean. Six fixed controls applied zero-fuzz patch artifacts and were stably
rejected by the Detector matrix.

Evidence: `research/evidence/cpp/four_class_controls/run-005/`.
This package is synthetic development evidence, not a holdout or accuracy
dataset. Safe/unrelated zero findings are not safety claims and are not counted
as misses.
## Implementation-bound rerun (2026-10-15)

`research/tests/cpp_detector_controls/manifest.json` is preserved as the historical baseline
(`0.4.0` shared_ptr / `0.3.0` lifetime; SHA-256
`8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`). The current rerun
uses the separate implementation-bound package
`research/tests/cpp_detector_controls_impl_20261015/manifest.json` (SHA-256
`b12711b567fa59c2b562fa1f353fd1bd1ee31d2780ad6f6cb597e4e9cb70eb3a`), so the observed
implementation versions remain explicit: `ohscanner.cpp.shared_ptr_race` `0.5.0` and
`ohscanner.cpp.lifetime` `0.4.0`.

| slice | controls | vulnerable | fixed | safe | unrelated | detector result | native result |
|---|---:|---:|---:|---:|---:|---|---|
| shared_ptr | 8 | 3 | 2 | 2 | 1 | 8/8 passed | 24/24 runs; vulnerable 9 triggered, negatives 15 clean |
| lifetime | 12 | 4 | 4 | 3 | 1 | 12/12 passed | 36/36 runs; vulnerable 12 triggered, negatives 24 clean |

Six fixed controls applied `patch -p1 --fuzz=0 --batch`; all six patched bytes matched the
fixed source hashes. DelayedSingleton family PoC: vulnerable and upstream-fix race modes
3/3 TSan-triggered, fully-atomic patch 3/3 clean, single-thread controls clean. unique_ptr/raw-alias
family PoC: four invalidation variants 3/3 ASan-triggered and two controls 3/3 clean.
The full replay, raw command logs, exact argv/environment, hashes and pass/fail/skip counts are
under `research/evidence/cpp/implementation_bound_controls_20261015/run-002/`.
Per-control exact argv, compiler, sanitizer, repeat count, source/binary/log hashes
and observed results are indexed by
`research/evidence/cpp/implementation_bound_controls_20261015/EVIDENCE_CHECKLIST.md`.

This is synthetic development evidence, not an independent holdout. Safe/unrelated zero
findings are narrow negative controls only; no zero-FP/FN, Precision/Recall or global safety
claim is made.
