# A-line independent acceptance addendum — T4 D51/D52

Run date: 2026-10-20 (Asia/Shanghai; current T4 executions only)
Integration target: `91747d4cad7503e58c466402e905088153f1deb4`
Disposition: **PARTIAL/BLOCK**. No detector or A0 queue changes.

## Frozen A0 binding and independent replay

T4 checked the original 345-row A0 candidate queue in the read-only T2 checkout at `research/deliveries/a-line-triage/20261019/candidate_triage_queue.csv` (SHA-256 `687d773986910a600e558833515137160ed50037889a2b6cc31c024433c3b45b`). It contains 345 unique review IDs and original statuses: 336 `not_testable`, 9 `not_reproduced`. The queue schema has no `queue_status` column, so it cannot independently prove the separate `paused_pending_evidence` state. T4 did not edit this file or any A0 status.

| A0 row | Frozen source identity | Component file identity | Current CLI replay on frozen A0 source |
|---|---|---|---|
| D51 `CR-0341` | `openharmony/security_huks`, commit `4ae4e0db461f137672719d43ffc6c5b1b6c05be8`, tree `9c922a60d815a34eb96c060274ed863fd3a6fea8`, snapshot `9fc6f1440f14899a71e9d4b99bd343782ad97eae5d1fa66b44c7fe23f4d3992c` | `services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h`; blob `2c12eef68c03b83e27c805b651bf99c981efac45`; SHA-256 `f189d4fbcb83e989ed3367fa8cb656e39a62f9aeddeb22b39c8d82352b435f45` | `ohscanner.cpp.shared_ptr_race` 0.5.1; 1/1 parse complete; 0 diagnostics. CLI tree matches frozen source. |
| D52 `CR-0255` | `openharmony/global_i18n`, commit `d13c698ebb238fa416a711bd3befe871e85721b6`, tree `d667c4f54ca12ef664b3bab9ec80b93653c5a7b7`, snapshot `533c3b8e09bbe318349ff90d92d07e2ea5d13fb2730f5fad2b102f6a0a7c54f8` | `interfaces/ets/ani/i18n/include/simple_number_format_addon.h`; blob `23803c9108c4e4c6b88a92ad366b600108a16317`; SHA-256 `588f5783b8be2b3c1b49874e43464dce8c750cb340437f334053b57a665d4289` | `ohscanner.cpp.shared_ptr_race` 0.5.1; 2/2 parse complete; 0 diagnostics. CLI tree matches frozen source. |
| D52 `CR-0256` | Same frozen D52 commit/tree/snapshot | `interfaces/ets/ani/intl/include/number_format_addon.h`; blob `216b68e9e1ba22c1c478b5966ebc713fe00e5bfe`; SHA-256 `a2548ed27d5e424132a1ed16cde48fdedb1e85dc89f504ab86f7267f57a20389` | Included in the same 2-file CLI replay above. |

The D51 commit/tree/blob were verified directly in the local bare `security_huks.git` object database. The frozen D52 A0 commit `d13c698…` is **absent** from the local bare `global_i18n.git` database (`git cat-file -e` returns “Not a valid object name”); the exact-source checkout Git context resolves its commit/tree/blob and the CLI replay completed there. Thus D52 content identity is reproducible from the pinned checkout, while the requested local-bare-object proof remains BLOCK. Both source records match the original A0 CSV rows. The new CLI JSON/Markdown are preserved in this directory as `d51_cli.*` and `d52_a0_pin_cli.*`.

## Historical D52 binding discrepancy

The existing D52 assessment and its 2026-10-29-named CLI artifacts bind to `5e1210b17e720af2748685ee65bd480709c08a52` / `80d9a2200344cf348f3dd582c74e8c4aa7ed2969`, while frozen A0 rows `CR-0255` and `CR-0256` bind to `d13c698…` / `d667c4…`. The component file blobs and bytes are identical across these commits, but the commit/tree identity is not. Therefore the historical artifacts are **STALE/MISMATCH as exact-A0 bindings**; their outcome is not discarded, but it does not substitute for the new exact-A0 replay. Historical files were not rewritten.

## Date provenance review

The historical artifact names and prose claim 2026-10-29, which is later than the current date 2026-10-20 (Asia/Shanghai). The stored CLI JSON has no execution timestamp, and the Markdown only repeats the claimed date and command. No original execution log or machine run record proving 2026-10-29 was found in the available worktrees. Checkout file timestamps show the files were materialized on 2026-10-20 and do not establish when the CLI ran. Commit author/committer dates are not execution evidence. Thus the historical run date is **BLOCK / unverified**; the old files remain unchanged. The date on this addendum records only the independently run T4 commands.

The exact A0 runs establish scanner behavior on the selected pinned source files. Zero findings do not prove safety or a fixed state. D51/D52 remain PARTIAL/BLOCK because concurrency, product selection, trigger, and impact evidence remain unresolved; D52's prior exact-A0 provenance statement also needs correction by a future owner-side erratum.
