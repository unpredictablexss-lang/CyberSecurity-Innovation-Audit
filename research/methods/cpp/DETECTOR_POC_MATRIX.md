# Detector / PoC coverage matrix

Current family-level controlled evidence. A PoC is required before a candidate
family is described as dynamically reproduced; it does not automatically promote
the candidate to confirmed/reportable.

| Detector family | Detector version | PoC | Dynamic result | Remaining gate |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `0.4.0` | `src/ohscanner/poc/cpp_shared_ptr_race.py` | historical vulnerable/upstream-fix TSan `3/3`; fully-atomic patch clean `3/3` | Git-object provenance and product reachability unknown |
| `ohscanner.cpp.lifetime` | `0.3.0` | `src/ohscanner/poc/cpp_lifetime_uaf.py` | four ASan invalidation variants `3/3`; two controls clean `3/3` | self-authored workload; product reachability unknown |
| `ohscanner.interface.ipc` | family-specific | `src/ohscanner/poc/harnesses/auth01_descriptor_bypass/` + `outputs/poc-loop/auth01-20261014/run-003/` (local evidence; harness source is committed) | AUTH-01 vulnerable attack `3/3`, fixed rejection and patch revalidation; reachability remains partial | unprivileged handle acquisition, identity and CIA impact unknown |

Rules for this matrix:

- `candidate/unassessed` remains the default even after dynamic reproduction.
- A clean control or patch revalidation is not a global safety claim.
- Missing PoC, partial reachability or unresolved provenance stays explicit.
- Historical reports, candidate IDs and review records are not rewritten.