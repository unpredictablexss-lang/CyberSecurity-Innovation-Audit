# T3 independent acceptance — PR #35 queue, scope, and date provenance

Date: 2026-10-20 (Asia/Shanghai)

Independent checkout: `codex/t3-queue-scope-audit-20261020`, based on integration HEAD `abd7d55fb0f38215d879d427664ad6a4531170be`
PR: #35, base `codex/contacts-path-traversal-pr-20261020` at `2db47f7fc0860f036c53dc12bccd63d62bcc23d8`, current remote head observed through GitHub API: `abd7d55fb0f38215d879d427664ad6a4531170be` (open, Draft, mergeable).

## Acceptance summary

- **T3 scope / queue identity: PASS.** The A0 verifier reran from `research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: 345 source candidates, 345 queue rows and unique IDs; all 97 source hash manifest entries match; no missing source materials, hash mismatches, source-key mismatches, or duplicate IDs. Original states remain 336 `not_testable` and 9 `not_reproduced`; queue states remain 331 `paused_pending_evidence`, 5 `queued_first_batch`, and 9 `queued_not_reproduced`.
- **D54/T61/T62 source-evidence replay: PASS with PARTIAL/BLOCK dispositions.** The D54 and T61 source/replay verifiers and T62 source/queue verifier all pass after the date-path correction. No conclusion label was promoted. D54/T61 libpng results remain partial/blocked and controls are incomplete; T62 dSoftBus remains partial/blocked because detector semantic coverage is partial and safe/unrelated source controls are missing.
- **Scope: BLOCK/authorized exception.** `scripts/check_change_scope.py --base aadf02b13c5e9c9ed439b04c18d3c993c18ec16a --lane cpp` returns 1 because it reports the separately authorized owner-only `docs/项目现状与下一步.md` path. No detector, fixture, or evidence path violation is reported. The scope check uses the integration base recorded for PR #35's C++ scope review, rather than the PR merge base, which includes the inherited Contacts owner change.
- **Overall: PARTIAL/BLOCK.** All actionable hashes, rows, and the three latest source-bound verifier suites pass. Date provenance remains unresolved for other future-dated evidence items listed below; this prevents a clean evidence-integrity acceptance of all inherited records.

## Independent commit membership and remote state

The checked head contains the submitted evidence commits in its ancestry:

| Line | Commit | Result |
| --- | --- | --- |
| D54 libpng replay | `141b5e4cb1aaabb23aa8caf9a36e1a1cb75e4987` | ancestor of checked head |
| T61 libpng acceptance | `997345c58b5feab37dbb5f952e2a57715517ecf6` | ancestor of checked head |
| T62 dSoftBus acceptance | `21503699a0bf78512b0767dc50cae906b6bd4eb7` | ancestor of checked head |
| D54/T61/T62 status integration | `abd7d55fb0f38215d879d427664ad6a4531170be` | current checked head |

GitHub API confirmed PR #35 currently targets the Contacts owner PR branch, is still open and Draft, and points to the same `abd7d55...` head at audit time. `gh` CLI was unavailable; the read used the connected GitHub API. No remote ref was changed by T3.

## Future-dated evidence inventory

The PR #35 additions present before this T3 correction contain **284** `research/evidence/cpp` paths whose filename date suffix is between 2026-10-21 and 2026-10-30. Distribution at the start of this audit:

| Filename date | Files |
| --- | ---: |
| 2026-10-21 | 8 |
| 2026-10-22 | 11 |
| 2026-10-23 | 24 |
| 2026-10-24 | 62 |
| 2026-10-25 | 24 |
| 2026-10-26 | 12 |
| 2026-10-27 | 38 |
| 2026-10-28 | 47 |
| 2026-10-29 | 36 |
| 2026-10-30 | 22 |

Git introduction metadata for all 284 paths reports author dates on 2026-10-20. This is a repository timestamp and does **not** by itself prove when the underlying analysis or CLI run occurred. The independent checkout normalized filesystem times for old files to checkout time, so those OS mtimes cannot be used as per-file run provenance. The date-field scan found 7 JSON top-level `date` values and 12 Markdown `Date:` fields later than 2026-10-20 among the inventoried paths; most files have no such top-level field. The remaining future filename/date records are retained unchanged and marked **BLOCK: insufficient run-date provenance**. No status, CVE finding label, source hash, or commit/tree/blob identity was altered to address this.

Three latest work products had direct same-day process evidence in the originating workstation: D54, T61, and T62 source/report/CLI files were created or last written between 07:11 and 07:14 on 2026-10-20, matching their commit timestamps, while their filenames and report date fields incorrectly claimed 2026-10-30. Only these are corrected to 2026-10-20. The recorded OS times are local workstation evidence, not a signed immutable execution log; they support correcting those just-created artifacts but do not generalize to the other 271 inherited future-dated items. Source commits, trees, blob IDs and hashes remain unchanged.

Corrected 13 files (the two reports, their machine records and raw CLI outputs, and the D54/T61 verifier scripts):

- `d54_libpng_lifetime_assessment_20261020.md`
- `d54_libpng_lifetime_assessment_20261020.json`
- `d54_libpng33416_vulnerable_cli_20261020.json`
- `d54_libpng33416_fixed_cli_20261020.json`
- `d54_libpng46675_vulnerable_cli_20261020.json`
- `d54_libpng46675_fixed_cli_20261020.json`
- `verify_d54_libpng_lifetime_20261020.py`
- `t61_libpng_independent_acceptance_20261020.md`
- `t61_libpng_independent_acceptance_20261020.json`
- `t61_libpng_current_replay_20261020.json`
- `verify_t61_libpng_acceptance_20261020.py`
- `t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.md`
- `t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.json`

All references to these 13 paths and their D54/T61/T62 run-date fields were updated. A recursive reference scan found no remaining old D54/T61/T62 `20261030` path or verifier references. PR #35 still contains other 20261030 artifacts (including D53/T59) and 20261021–20261029 artifacts; their names/dates are **not** silently changed because this T3 audit lacks direct per-run provenance for them.

## D3 cJSON upstream control review

The upstream public records do not provide a trustworthy fixed control for either cJSON case at audit time:

- [Issue #1073](https://github.com/DaveGamble/cJSON/issues/1073) is open and requests remediation for CVE-2026-67215 and CVE-2026-67216.
- [PR #1064](https://github.com/DaveGamble/cJSON/pull/1064) describes a depth check in `cJSON_Utils` for the distinct #995 MergePatch recursion issue; it does not fix the two reported root causes.
- [PR #1078](https://github.com/DaveGamble/cJSON/pull/1078) proposes a comparison recursion depth guard at head `d18fad4` / tree `495bef40`; this limits nesting depth, not the CVE-67216 exponential comparison cost, and does not address CVE-67215 JSON Patch tree amplification/deletion.

These remain experimental or unrelated changes, not fixed-source controls. Keep both cJSON cases PARTIAL/BLOCK and do not infer a safe release.

## Reproduction

```powershell
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python research/evidence/cpp/verify_d54_libpng_lifetime_20261020.py --libpng-git-dir D:\openHarmonyScanner\tmp\libpng-gitlab-mirror-pins-20261019.git --46675-git-dir D:\openHarmonyScanner\tmp\t34-libpng46675-source-20261023.git
python research/evidence/cpp/verify_t61_libpng_acceptance_20261020.py
python research/evidence/cpp/verify_t62_dsoftbus_cve_2025_26690.py
python scripts/check_change_scope.py --base aadf02b13c5e9c9ed439b04c18d3c993c18ec16a --lane cpp
```
