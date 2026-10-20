# B线 IPC 八仓固定提交复测：v0.12.3

日期：2026-10-19；分支：work/ipc-20261017；规则模型：oh-ipc-2026.10-v23。
所有结果都是静态候选，validated_vulnerability=0。固定提交与完整报告见本目录 JSON/Markdown。

| 仓库 | 固定 commit | 文件 | complete / partial / not_run | LOC | 候选 |
|---|---|---:|---:|---:|---:|
| openharmony/aafwk_standard | 834a566b | 1771 | 1222 / 531 / 18 | 398751 | 15 |
| openharmony/applications_contacts_data | 341cc3bf | 360 | 199 / 19 / 142 | 61024 | 4 |
| openharmony/communication_netmanager_ext | 8c35917b | 654 | 434 / 198 / 22 | 152107 | 0 |
| openharmony/distributeddatamgr_relational_store | 42f13ea8 | 1350 | 789 / 376 / 185 | 285468 | 0 |
| openharmony/graphic_standard | a73af6bd | 1192 | 965 / 223 / 4 | 166232 | 8 |
| openharmony/miscservices_pasteboard | dd22c7cb | 68 | 57 / 10 / 1 | 7104 | 2 |
| openharmony/multimedia_histreamer | 847aafa3 | 576 | 345 / 231 / 0 | 93453 | 0 |
| openharmony/security_deviceauth | 2cf21e46 | 436 | 291 / 145 / 0 | 69106 | 1 |

规则计数： ipc.auth.missing 12, ipc.capability.export 11, ipc.relay.descriptor-boundary 7.
端到端路径覆盖按候选文件与 entry-source 文件状态取较弱值： complete 9 / partial 21 / unknown 0。
完整候选 inventory 在 candidate_inventory.csv；原始 JSON/Markdown 报告已按仓库分开保存。
