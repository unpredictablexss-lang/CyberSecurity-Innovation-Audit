# C11 Performance and Competition Admission Report

Baseline: `ab30df6a01797af455d2abbbc9533ab15964ee68`.
Decision: **NOT ADMITTED**. Do not mark Draft Ready or merge.

## Performance and bounded-scope results

- All invariance checks pass: `True`.
- `batch`, `shard/aggregate`, cold/warm file AST cache and exact limit boundaries were executed against the same source identities and coverage sets.
- Candidate diagnostic identity is used only to detect verdict drift. It is not a safe/miss or validated-vulnerability verdict.
- Partial/unknown changes and failure boundaries are recorded in `performance_results.json`; no partial state is promoted to complete.

| Case | Runs | Wall median / tail (s) | Peak RSS median / tail (bytes) |
|---|---:|---:|---:|
| `batch_real` | 5/5 | 0.038279600004898384 / 0.041153700003633276 | 29130752 / 29200384 |
| `cache_cold` | 5/5 | 5.3178258999978425 / 5.502174599998398 | 52944896 / 53088256 |
| `cache_warm` | 5/5 | 1.3427156999969156 / 1.387077400002454 | 55414784 / 55656448 |
| `cli_detector_full` | 3/3 | 0.7100639999989653 / 0.7489300999950501 | 28450816 / 28585984 |
| `cli_index_full` | 3/3 | 0.6359685999996145 / 0.6363472000011825 | 29327360 / 29409280 |
| `cli_index_shards` | 3/3 | 4.512468399996578 / 4.686808200000087 | 31145984 / 31219712 |
| `full_no_cache` | 5/5 | 0.5715446999965934 / 0.5727372999972431 | 51752960 / 52178944 |
| `limit_1999` | 3/3 | 0.03211149999697227 / 0.03288419999444159 | 33730560 / 33816576 |
| `limit_2000` | 3/3 | 0.03178620000107912 / 0.03183089999947697 | 33939456 / 34050048 |
| `limit_2001` | 3/3 | 0.03278149999823654 / 0.0331886999993003 | 33902592 / 33992704 |
| `limit_blob_exact` | 3/3 | 0.0023498000009567477 / 0.0024741000015637837 | 31354880 / 31477760 |
| `limit_blob_plus_1` | 3/3 | 0.0021943999963696115 / 0.002247799995529931 | 31326208 / 31350784 |
| `limit_total_32mib` | 3/3 | 0.06975940000120318 / 0.07618279999587685 | 64053248 / 64094208 |
| `limit_total_32mib_plus_1` | 3/3 | 0.0686786999940523 / 0.07097449999855598 | 63787008 / 64012288 |
| `shard_no_cache` | 5/5 | 0.9045750000004773 / 0.9185964999996941 | 52252672 / 52379648 |
| `unbatch_real` | 5/5 | 0.5920361000025878 / 0.6043101999966893 | 29171712 / 29241344 |

## Admission matrix

| Deliverable | Status | Minimum remediation |
|---|---|---|
| `accurate_complete_analysis` | **BLOCKED** | Freeze rules first, then create a leakage-ledger-controlled holdout with two independent blind labels, adjudication and family-level TP/FP/FN/unknown reporting. |
| `cwe_cve_support` | **PARTIAL** | Create one evidence table per delivered finding binding CVE/CWE, exact source/fix objects, detector rule/version, applicability and unresolved obligations; remove unsupported mappings. |
| `reproducible_poc` | **BLOCKED** | Package deterministic vulnerable/fixed component fixtures, exact build command, sanitizer/runtime output and replay script for every claimed case; product PoC remains separate until entry/impact are proven. |
| `affected_modules_versions_branches` | **PARTIAL** | Add a machine-readable applicability matrix with repository, full commit/tree/blob, product manifest/build, affected/fixed branch and version range for every case. |
| `fix_and_revalidation` | **BLOCKED** | For each admitted case, record patch, patched source identity, same-environment rerun, regression controls and product/component impact retest. |
| `performance_and_innovation` | **PARTIAL** | Add preregistered baseline comparisons for scan architecture/caching/evidence gating on the same identity/coverage set, plus ablation and failure-boundary analysis; never use throughput as correctness evidence. |
| `complete_report` | **PARTIAL** | Produce a final indexed report bundle linking every claim to machine artifacts, commands, hashes, PoC, fix/retest and limitations; keep candidate counts out of security conclusions. |

## Blockers

- `accurate_complete_analysis`: Freeze rules first, then create a leakage-ledger-controlled holdout with two independent blind labels, adjudication and family-level TP/FP/FN/unknown reporting.
- `reproducible_poc`: Package deterministic vulnerable/fixed component fixtures, exact build command, sanitizer/runtime output and replay script for every claimed case; product PoC remains separate until entry/impact are proven.
- `fix_and_revalidation`: For each admitted case, record patch, patched source identity, same-environment rerun, regression controls and product/component impact retest.

## Partial items

- `cwe_cve_support`: Create one evidence table per delivered finding binding CVE/CWE, exact source/fix objects, detector rule/version, applicability and unresolved obligations; remove unsupported mappings.
- `affected_modules_versions_branches`: Add a machine-readable applicability matrix with repository, full commit/tree/blob, product manifest/build, affected/fixed branch and version range for every case.
- `performance_and_innovation`: Add preregistered baseline comparisons for scan architecture/caching/evidence gating on the same identity/coverage set, plus ablation and failure-boundary analysis; never use throughput as correctness evidence.
- `complete_report`: Produce a final indexed report bundle linking every claim to machine artifacts, commands, hashes, PoC, fix/retest and limitations; keep candidate counts out of security conclusions.

## Evidence boundary

- The audit record was imported byte-for-byte and is bound by source blob/SHA-256 in its import manifest.
- Known CVE/CWE mappings describe detector rules and historical/component evidence. They do not confirm current product vulnerabilities.
- 2000-file/32MiB/1MiB boundaries are verified exactly; exceeding them remains a coverage limitation, never a safe verdict.
- Performance is platform cost on fixed inputs. It is not accuracy, recall or security evidence.
- Real batch/index cases use the pinned Git commit/tree/blob path. Cache and exact-limit cases use deterministic in-memory fixture identities to isolate frontend/runner behavior; they are not product-source evidence.
