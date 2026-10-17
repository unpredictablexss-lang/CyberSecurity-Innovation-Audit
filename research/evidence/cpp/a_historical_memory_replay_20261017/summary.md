# A memory-safety historical replay

> Capability signal only; no new vulnerability claim.

| Sample | CVE | Vulnerable | Fixed | Detector |
|---|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `None` | possible_hit (2) | possible_hit (3) | `ohscanner.cpp.shared_ptr_race` |
| `communication_dsoftbus_null_deref_001` | `CVE-2025-26690` | possible_hit (5) | miss (0) | `ohscanner.cpp.null_dereference` |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `CVE-2025-23420` | possible_hit (5) | miss (0) | `ohscanner.cpp.bounds` |
| `kernel_liteos_a-getgroups-oob-2025-03` | `CVE-2025-20042` | not_applicable (0) | not_applicable (0) | `ohscanner.cpp.bounds` |
| `kernel_liteos_a-os-copy-user-param-bypass-2025-03` | `CVE-2025-21098` | not_applicable (None) | not_applicable (None) | `not_applicable` |

## Historical capability counts

- Applicable historical cases: 3
- Vulnerable possible_hit: 3
- Fixed miss: 2; fixed residual candidate: 1
- Not-applicable cases: 2

These counts are not product Precision/Recall or global Recall.

## Boundaries

- Historical replay is a capability signal, not a new vulnerability claim.
- A possible_hit is not a confirmed product vulnerability; a miss is not a global detector recall claim.
- Kernel race and user/kernel boundary cases are not_applicable to the current bounds/integer lexical rules.
