# T5 D51/D52 fresh source-bound replay

**Independent execution date:** 2026-10-20 (Asia/Shanghai). Current-run window was bracketed by the task clock at 2026-10-20 02:10:12–02:12:35 UTC.
**Scanner baseline:** `81dd4aea9bb51522ac912b33504ef0d2ddb79089` (checked out in a separate clean scanner worktree).
**Evidence integration base:** PR #35 HEAD `6286eabd7b1da2ab83d7b2b03cf26ce5a331846d`.
**Disposition:** PARTIAL/BLOCK. This replay does not update A0 status and does not establish safety.

## Scope and result

| A0 ID | Source | Exact commit / tree | File scope | Blob / source SHA-256 | Parse | `shared_ptr_race` 0.5.1 |
|---|---|---|---|---|---:|---:|
| CR-0341 | `openharmony/security_huks` | `4ae4e0db461f137672719d43ffc6c5b1b6c05be8` / `9c922a60d815a34eb96c060274ed863fd3a6fea8` | `services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h` | `2c12eef68c03b83e27c805b651bf99c981efac45` / `f189d4fbcb83e989ed3367fa8cb656e39a62f9aeddeb22b39c8d82352b435f45` | complete 1/1 | 0 |
| CR-0255 | `openharmony/global_i18n` | `d13c698ebb238fa416a711bd3befe871e85721b6` / `d667c4f54ca12ef664b3bab9ec80b93653c5a7b7` | `interfaces/ets/ani/i18n/include/simple_number_format_addon.h` | `23803c9108c4e4c6b88a92ad366b600108a16317` / `588f5783b8be2b3c1b49874e43464dce8c750cb340437f334053b57a665d4289` | complete 2/2 | 0 |
| CR-0256 | same as CR-0255 | same as CR-0255 | `interfaces/ets/ani/intl/include/number_format_addon.h` | `216b68e9e1ba22c1c478b5966ebc713fe00e5bfe` / `a2548ed27d5e424132a1ed16cde48fdedb1e85dc89f504ab86f7267f57a20389` | complete 2/2 | 0 |

The D51 and D52 source commits were resolved from `openharmony/.repo/project-objects/{security_huks,global_i18n}.git`; temporary source checkouts were detached at those exact commits. The source commit/tree/blob and file hashes match the frozen T4 A0 binding and queue rows. The CLI-produced `snapshot_sha256` values are preserved in the raw outputs; they are run artifacts and are distinct from the frozen queue snapshot identities.

The A0 queue is read-only: 345 unique IDs, SHA-256 `687d773986910a600e558833515137160ed50037889a2b6cc31c024433c3b45b`; these three rows remain `original_final_status=not_testable`. The replay reports no finding for any row, so it does not reproduce the stored candidate. Zero findings on complete parsing do not prove safety or falsify the underlying report. No detector, tests, fixtures, or A0 status were changed.

## Commands

Executed from scanner checkout `D:\openHarmonyScanner\worktrees\a-d36-libpng33416-latest-20261020` at the stated baseline. Outputs are preserved as `d51_cli.*` and `d52_cli.*`.

```powershell
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\t5-d51-d52-source-20261020\security_huks --repository openharmony/security_huks --commit 4ae4e0db461f137672719d43ffc6c5b1b6c05be8 --include services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h --detector ohscanner.cpp.shared_ptr_race --json-out <evidence-dir>\d51_cli.json --md-out <evidence-dir>\d51_cli.md
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\t5-d51-d52-source-20261020\global_i18n --repository openharmony/global_i18n --commit d13c698ebb238fa416a711bd3befe871e85721b6 --include interfaces/ets/ani/i18n/include/simple_number_format_addon.h --include interfaces/ets/ani/intl/include/number_format_addon.h --detector ohscanner.cpp.shared_ptr_race --json-out <evidence-dir>\d52_cli.json --md-out <evidence-dir>\d52_cli.md
python <evidence-dir>\verify.py --object-db-root D:\openHarmonyScanner\openharmony\.repo\project-objects --a0-queue D:\openHarmonyScanner\worktrees\a-triage-t2-20261019\research\deliveries\a-line-triage\20261019\candidate_triage_queue.csv --scanner-root D:\openHarmonyScanner\worktrees\a-d36-libpng33416-latest-20261020
```

## Limitations and next action

This is a fresh dated replay, so it replaces the *date provenance gap for this replay only*. It does not authenticate the historical 2026-10-29 execution claims; old artifacts remain unchanged and their dates remain BLOCK. No trusted fixed source or same-root negative control was run in this task. These cases remain PARTIAL/BLOCK pending independent root-cause validation and controls. A0 status was not upgraded.

The queue has no `queue_status` column; this replay can verify only the frozen `original_final_status` values. Source origin names are declared metadata; local Git object identity alone does not authenticate upstream ownership.
