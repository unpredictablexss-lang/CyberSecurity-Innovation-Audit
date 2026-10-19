# C10-LATEST-KNOWN-CVE-MIGRATION 17 CVE disposition summary

All public-CVE rule hits remain `candidate/unassessed`. Local fixed/safe/unrelated zero results are controls, not component or product safety conclusions.

| CVE | Review disposition | Detector disposition | Vulnerable | Fixed | Safe | Unrelated | Unknown |
|---|---|---|---|---|---|---|---|
| CVE-2026-46675 | component reproduction confirmed; product unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered |
| CVE-2025-9900 | component reproduction confirmed; product unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |
| CVE-2026-92391 | local source path supported; product call chain unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |
| CVE-2026-67216 | local source shape supported; product unknown | candidate/unassessed | covered | not_applicable | covered | covered | covered_by_shared_gate |
| CVE-2026-67215 | local source shape supported; product unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |
| CVE-2026-27648 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | covered | covered |
| CVE-2025-25212 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |
| CVE-2022-45877 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | covered | covered |
| CVE-2026-58313 | public disclosure; local lock is only a protection sign; root mapping unknown | candidate/unassessed | covered | covered | covered | covered | covered |
| CVE-2026-28733 | public disclosure; current protection signs do not close release applicability | candidate/unassessed | covered | covered | covered | covered | covered_by_shared_gate |
| CVE-2026-25850 | public disclosure; current source seems fixed; release mapping unknown | candidate/unassessed | covered | covered | covered | covered | covered_by_shared_gate |
| CVE-2026-28751 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | covered | covered_by_shared_gate |
| CVE-2025-27247 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |
| CVE-2025-57052 | public disclosure; product applicability unknown | candidate/unassessed | covered | covered | covered | covered | covered_by_shared_gate |
| CVE-2026-33636 | main libpng patch present; Flutter/product pin unknown | candidate/unassessed | covered | covered | covered | covered | covered_by_shared_gate |
| CVE-2026-92392 | reviewed local curl 8.8.0 is outside affected range; other builds still require version binding | candidate/unassessed when applicable; not-applicable to reviewed 8.8.0 | covered | covered | covered | not_applicable | covered |
| CVE-2026-9079 | public disclosure; local status unknown/suspected fixed | candidate/unassessed | covered | covered | covered | not_applicable | covered_by_shared_gate |

Special boundaries:
- CVE-2026-92392: reviewed local curl 8.8.0 is explicitly `not-affected` by version; other builds remain version-bound unknowns/candidates.
- CVE-2026-9079: local status remains `unknown/疑似 fixed`; no report is issued from version text alone.
- CVE-2026-58313: LRU mutex is only a protection signal; the disclosed root cause is not yet bound to this exact hunk.
- CVE-2026-33636: main libpng patch evidence exists; Flutter/product pin and build applicability remain unknown.
