# T8 Samgr queue replay delta — CR-0219–CR-0223

Date: 2026-10-20 (Asia/Shanghai)
Scanner base: `73d5c356b1b1dbc081727948d89d6502c862f3af`
Purpose: fresh current-base CLI replay and source-identity verification, independently of the earlier T30 audit.

## Source identity and execution

The exact source came from the local Repo object mirror `D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git`; public network retrieval was unnecessary. The pinned chain verified as commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff` → tree `b7a89e95be788f2f2372258e341f7be842c7826d` → `services/samgr/native/source/system_ability_manager_stub.cpp` blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`. The raw Git blob is 78,212 bytes with SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`.

The current `ohscanner.interface.ipc` CLI (`0.12.12`, `light-ast`) emitted 10 diagnostics and reproduced the same five `ipc.capability.export` source locations recorded by T30. Parse and detector analysis remain `partial`; this replay adds no coverage improvement and no detector change is indicated by these five rows. Raw output: [CLI JSON](a_t8_samgr_cli_20261020.json) and [CLI Markdown](a_t8_samgr_cli_20261020.md).

| A0 ID | Source line | Current finding ID | Original A0 state |
|---|---:|---|---|
| CR-0219 | 464 | `ohscanner.interface.ipc:2af8fbf91642cbbf` | `not_reproduced / queued_not_reproduced` |
| CR-0220 | 551 | `ohscanner.interface.ipc:e6305216fc6e7a94` | `not_reproduced / queued_not_reproduced` |
| CR-0221 | 668 | `ohscanner.interface.ipc:b810e0670174d80e` | `not_reproduced / queued_not_reproduced` |
| CR-0222 | 706 | `ohscanner.interface.ipc:c50c9e08852ab64f` | `not_reproduced / queued_not_reproduced` |
| CR-0223 | 1485 | `ohscanner.interface.ipc:d21108b21819c7b8` | `not_reproduced / queued_not_reproduced` |

The source paths return `IRemoteObject` capabilities through IPC replies; no FD operation appears in these five locations. The broader per-ID transaction, permission, and input-flow review is already recorded in [T30](a_t30_samgr_ipc_audit_20261020.md); this T8 delta does not restate it.

## Disposition

The exact source identity and five candidate mappings are verified. All five original IDs and statuses are unchanged. This is a fresh replay consistent with T30, not new vulnerability confirmation. Partial parsing, unresolved product build and caller policy, and lack of a trusted fixed-source comparison keep the security disposition **PARTIAL**.

## Reproduction

```powershell
git clone --shared --no-checkout 'D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git' research/evidence/cpp/.t8_samgr_repo
git -C research/evidence/cpp/.t8_samgr_repo checkout --detach 08e2a552b839ea7727251cb9b749a5c1dd9cfeff
git --git-dir='D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git' rev-parse '08e2a552b839ea7727251cb9b749a5c1dd9cfeff^{tree}'
git --git-dir='D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git' rev-parse '08e2a552b839ea7727251cb9b749a5c1dd9cfeff:services/samgr/native/source/system_ability_manager_stub.cpp'
python research/evidence/cpp/verify_t8_samgr_queue_evidence_20261020.py --source-git-dir 'D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git'
python research/evidence/cpp/verify_t30_samgr_ipc_audit.py
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
```
