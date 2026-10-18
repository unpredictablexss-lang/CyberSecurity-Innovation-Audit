# A line: sample30 sandbox follow-up

Status: `0 confirmed / 0 dedicated PoC`; no product vulnerability claim.

## Imported sandbox evidence

- Remote branch: `codex/a-line-scanner-regression-20261018`
- Imported commit: `3278a884a13a15c0fe67f3ad2364837411c57cbe`
- Imported path: `research/deliveries/a-line-sample30/20261018/**`
- Not imported: parent `0d9357e` C/D full-scan runner, shared scripts, or status docs.

The sandbox delivery reports:

- 30 deterministic sample reports from 378 valid reports.
- 345 diagnostics: 283 high-priority, 62 normal-priority.
- `confirmed=0`, `dedicated_pocs=0`.
- `not_reproduced=9`, `not_testable=336`.
- 263 `ohcpp-shared-ptr-race-candidate-001` candidates, all `not_testable`.
- 1 `ipc.parcel.copy-range` `not_reproduced`; the visible `cfgLen <= 0` and
  `cfgLen > MAX_LEN` guards were not normalized.
- 8 SAMGR capability candidates `not_reproduced` against visible permission
  predicates; this is B/platform guard modeling, not an A-line trusted-name fix.

## A-line changes since the sandbox baseline

- `shared_ptr_race 0.5.3`: constructor-body writes are initialization; function
  parameters shadow same-named members; stable-owner and parameter-shadow
  controls added.
- `bounds 0.2.6`: `<= 0`, `< 0`, `>= MAX`, `> MAX` and `nullptr` early-return
  guards narrow intervals; constant offsets such as `n - 1` are evaluated;
  `memcpy_s/memmove_s(dst, dstsz, src, count)` checks both size arguments; the
  secure string-copy family (`strcpy_s`, `strcat_s`, `strncpy_s`, `sprintf_s`,
  `snprintf_s`) checks the destination size and, where applicable, the count.
  The fixed five-component rerun stays at 33 candidates / 22 groups with every
  component unchanged (`a_line_scan_20261018_v11_comparison.json`).
- `integer_bounds 0.2.1`: `calloc`/`new[]` element multiplication.
- `resource_lifetime 0.1.3`: conditional release paths and one-hop release wrappers.
- `unsafe_memory_call 0.1.2`: correct `fprintf/vfprintf/syslog` format argument.

## Triage before/after

The fixed five-component triage is not the sample30 corpus, but gives a
controlled precision regression:

| Detector version | Candidates | File/symbol groups |
|---|---:|---:|
| 0.5.1 | 778 | 137 |
| 0.5.2 | 534 | 110 |
| 0.5.3 | 504 | 108 |

The reduction is explained by constructor-body initialization and parameter
shadowing, not by a coverage drop. Evidence:
`research/evidence/cpp/shared_ptr_triage_20261018/comparison.json`.

The current 0.5.3 triage also classifies member access points: 375 reads and
112 writes, with the remaining points unclassified. The raw candidate count is
unchanged by this classification; it is an audit aid, not a new verdict.

The 2026-10-18 method-level triage (`shared_ptr_triage_20261018_v5`) keeps the
same 504 candidates / 108 file-symbol groups and re-groups them by qualified
class/member into 212 groups: 45 `stable_owner` and 53 `constructor_only` are
quiet, 24 `mutable_owner` (42 candidates), 82 `cross_function_unknown`
(451 candidates) and 8 `write_only` (9 candidates). Two findings remain
ambiguous between `OHOS::AbilityContext::abilityInfo_` and
`OHOS::ExtensionContext::abilityInfo_` because both classes share one header.
This grouping changes no verdict and is not a Precision/Recall measurement.

## Pending

The 30 sample source repositories are not present locally, so the sample30
candidate counts were not rerun on this checkout. When the pinned source roots
are available, replay the same 30 commits/trees/snapshots and compare the 345
diagnostics, 263 shared_ptr candidates and 9 `not_reproduced` records. Until
then, no sample30 before/after or Precision/Recall claim is made.

## Boundary

The sandbox method controls remain method evidence only: copy-range model 3/3
clean, unsafe control 3/3 ASan, safe control 3/3 clean, TSan unsafe 3/3 race,
TSan atomic 3/3 clean. None is a product PoC. All findings remain
`candidate/unassessed`; `validated_vulnerability=0`.
