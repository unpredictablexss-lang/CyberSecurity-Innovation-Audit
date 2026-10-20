# B 线 IPC 收尾交付（2026-10-20）

## 代码与版本

本交付分支：`codex/b-ipc-closeout-20261020`。本轮生产扫描使用分支代码提交 `4a8806acaa456120c496f185c8a424e0fca1671a`；扫描器 `ohscanner.interface.ipc` 为 `0.12.13`，模型 `oh-ipc-2026.10-v33`。本轮没有改动检测器源代码，最终交付提交会只包含报告与证据整理。DATA-06 规则 `ipc.parcel.array-allocation-width@0.1.0`、测试、控制样例和共享保护均已在主线；主线比旧 B 分支保留了更严格的守卫、来源绑定和 partial 传播。B 集成源码来源 `40e3d79f38629b273214f1efee0f22b7443849f1` 的必要部分已集成，未将旧分支整批覆盖主线。

完整原始固定清单和历史输出已随包保存于 `research/evidence/interface/ipc/bline_closeout_20261020/historical_inputs/`。这使旧 `0.12.12` 结果保持为历史基线，不冒充本次 `0.12.13` 实测。

## 固定八仓回放

使用历史八仓 manifest 固定的 commit/tree/scope，逐仓经统一 M2 CLI `ohscan-run` 执行 `0.12.13`。八仓均完成，状态均为 `completed_with_limitations`：

| 仓库 | 固定 commit | 候选观察 | complete / partial / not_run |
|---|---|---:|---:|
| `aafwk_standard` | `834a566b1372268c7bbb0c40362322f812ca6efc` | 15 | 1246 / 507 / 18 |
| `applications_contacts_data` | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | 4 | 199 / 19 / 142 |
| `communication_netmanager_ext` | `8c35917b7e2f152813b13a20530a8452cf73d938` | 0 | 441 / 191 / 22 |
| `distributeddatamgr_relational_store` | `42f13ea84e2f90ed511a2bd4aa5be14c5996eba8` | 0 | 790 / 375 / 185 |
| `graphic_standard` | `a73af6bd3bac599b9359cba10ca7b5f82a02d5d9` | 8 | 969 / 219 / 4 |
| `miscservices_pasteboard` | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | 2 | 59 / 8 / 1 |
| `multimedia_histreamer` | `847aafa3dc32bcf92eb8a2d2277b8d34bff98362` | 0 | 346 / 230 / 0 |
| `security_deviceauth` | `2cf21e46f43c63857c40a79b004eda14f79b04c2` | 1 | 291 / 145 / 0 |
| **合计** | — | **30** | **4341 / 1694 / 372** |

与固定 `0.12.12` 基线相比，候选观察为 **30 → 30**：30 retained、0 added、0 removed；规则分布未变。解析 complete 增加 39、partial 减少 39、not_run 保持 372。使用历史 triage 的同一 `root_cluster` 映射，观察仍为 **28 个候选复核锚点簇**；该聚类只是复核组织方式，不等同于已确认漏洞根因。Contacts 的两个旧 partial 观察仍保持 partial/unknown。逐仓身份和覆盖差异见 `eight_repo_candidate_comparison.json`，八份原始 JSON/Markdown 与日志见 `eight_repo_0.12.13/`。

## 已披露 CVE 精确版本回放

已按旧 B 线冻结的 14 项清单、固定 vulnerable/fixed commit/tree 与原定 scope，通过当前统一 CLI 完成 **14 个 CVE、28 个版本端点回放**。本轮不是新仓库全量扫描；没有将历史 `0.12.12` 报告计成本次运行。

| CVE | vulnerable / fixed 候选观察 |
|---|---:|
| CVE-2024-12082 | 7 / 4 |
| CVE-2024-38382 | 7 / 5 |
| CVE-2024-39775 | 2 / 0 |
| CVE-2023-25176 | 1 / 0 |
| CVE-2022-42463 | 1 / 1 |
| CVE-2025-27247 | 4 / 3 |
| CVE-2025-25212 | 3 / 2 |
| CVE-2025-27563 | 3 / 0 |
| CVE-2023-0035 | 1 / 0 |
| CVE-2023-0036 | 1 / 0 |
| CVE-2024-39612 | 2 / 0 |
| CVE-2025-26691 | 9 / 0 |
| CVE-2024-21816 | 2 / 0 |
| CVE-2025-26693 | 10 / 7 |
| **合计** | **53 / 22（75 条观察）** |

28 个端点中 6 个 `completed`、22 个 `completed_with_limitations`。与历史 `0.12.12` 对照，候选观察数量均为 75，稳定来源/规则/符号锚点为 75 个；没有候选锚点新增或消失。发现原全仓 fixed 报告存在定位元数据异常：`CVE-2022-42463` 的固定来源 SHA 与 `byte_start=10154` 映射到第 275 行，但原报告序列化为字符串 `frozenlist`。已在相同固定 commit 上通过统一 CLI 对该精确源码文件复放，输出整数行号 `275`，来源 SHA 和 byte offset 一致；产物为 `disclosed_cve_0.12.13/cve-2022-42463/fixed_locator_replay.json/.md/.log`。候选锚点仍保留，不记为新增或消失。全仓重跑在 Python 3.13 Tree-sitter 对象清理时于 immutable-source 二次读取发生原生 access violation，原始全范围报告与日志保留，完整范围重新生成列为环境限制。没有据此升级或撤销安全结论。逐 CVE/逐端点差异见 `cve_candidate_comparison.json`，全部报告、日志和固定 SHA 见 `disclosed_cve_0.12.13/`。

这些是披露版本控制和设计回归，不是独立 holdout。命中不证明产品入口、攻击者可达性、权限影响或漏洞有效性；所有候选保持 `candidate/unknown`，`validated_vulnerability=0`。

## DATA-06 与 Contacts 解析控制

DATA-06 固定源码挑战经 M2 CLI 回放：两个固定 vulnerable 修订各 1 条 `ipc.parcel.array-allocation-width@0.1.0` 候选，官方修复 `de3a68cc8b7d6f18017fd261060def0e38dce54a` 为 0 条。报告绑定各自固定 commit 和源码 SHA；两处 vulnerable 修订归为同一候选根因。它是设计控制和已披露 CVE 回归，不是 holdout。复现参数与原始报告见本目录 `data06-*.json/.md`。

本轮纠正了先前写错的 Contacts 路径。真实 IPC Parser 问题位于固定 `applications_contacts_data@341cc3bf` 的 `dataBusiness/poster/src/poster_call_stub.cpp`，Git blob `7cf9459f8f3b360dd85ba1587afc2a792e8a79fa`，源码 SHA `da61331914d7d1f92afea3b58eff862d0b1b2f98ec102258d7807cf8798a7f50`。第 21 行 `#include "contacts_common_event.h" ` 在右引号和 LF 间有一个空格：共享 parser 原始状态为 partial，私有 IPC 解析副本为 complete；字节长度、LF 偏移与原始 source SHA 不变。M2 继续将该源码单元报告为 partial，并为第 44、46 行两个候选保留 `parse_completeness_impact` 义务。固定八仓 CLI 报告与针对性归一化控制均复现此行为。详细精确源记录见 `contacts_parser_replay.json`。这是 IPC 适配器内的窄恢复，不是共享 Parser 的全局修复；无需据此扩大成 Parser 重构。

## 验证与剩余交付项

- 针对 DATA-06、IPC 家族、规则版本与 holdout 契约：**44 passed**。
- IPC 相关回归：**377 passed, 47 skipped**。跳过项仍保留测试报告自己的状态，不折算为通过。
- 已披露 CVE 单测：**21 passed**；该套件不替代上文 14 个精确版本回放。
- `communication_ipc` 固定 commit `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` 同源对照：`0.12.12` 与 `0.12.13` 均为 697 个源文件、同一 tree/snapshot，14 retained、0 added、0 removed；解析为 442 complete / 218 partial / 37 not_run。证据见 `communication-ipc-5903fd5-ipc-0.12.13.json/.md` 与 `candidate_comparison.json`。
- 逐规则适用文件数/实际评估文件数尚未形成共享 Runner 协议。建议作为明确的跨线小交付：每个 `detector_id + rule_id + rule_version` 记录 `applicable / evaluated_complete / evaluated_partial / not_run / candidate_count` 和不适用/未评估原因；来源 SHA 继续绑定观察。该协议落地前，零候选规则覆盖保持 unknown；不启动平台重构。
- 当前回放发现的 DSoftBus fixed 定位序列化异常需要修复并针对性重跑，是本交付明确未关闭的代码回归。
- 独立准确率评估 `not_run`；产品 build、部署、入口、权限、影响和修复验证均 `unknown/not_run`。未提供 Precision/Recall，也没有将候选命中升级成已验证漏洞。
- 对 CVE-2022-42463 fixed 报告做针对性再运行时，Windows Python 3.13 的 CLI 在 `dataclasses.asdict(ToolDiagnostic)` 处报 `TypeError: unhashable type: 'list'`，未生成新的报告。此前固定 28 端点原始产物保留；这项 Python 3.13 运行/身份侧车序列化回归需要定位修复后重跑受影响端点。
- 隔离平台环境未连接，候选详情页和报告导出接线验收 `not_run`。

## 状态

| 层级 | 状态 |
|---|---|
| B 线检测器工程 | DATA-06 与 IPC 0.12.13/model v33 已集成；本轮固定范围代码回放完成 |
| 本轮证据包 | 本提交包含固定八仓、14 CVE/28 端点、DATA-06、Contacts 解析、差异索引和 SHA 清单 |
| 主线代码合入 | 已合入；本轮新增证据包是否合入主线单独跟踪，不宣称已合入 |
| 分支推送 | `codex/b-ipc-closeout-20261020` 已推送至 origin；证据包尚未合入 main |
| 部署 | 未验证，unknown |
| 漏洞验证 | 产品漏洞未验证；validated_vulnerability=0 |
| 独立准确率评估 | not_run |
| 产品验证/平台接线 | not_run；产品证据与隔离平台环境未提供 |

## 复现

Windows PowerShell（Python 环境使用当前工作区安装依赖）：

```powershell
python -m pytest -q tests/test_ipc_t74_cj_array_bounds_integration_challenge.py tests/test_ipc_family_depth.py tests/test_ipc_family_matrix.py tests/test_ipc_rule_versions.py tests/test_ipc_holdout_contract.py
$ipcFiles = @(Get-ChildItem tests -File -Filter 'test_ipc*.py' | ForEach-Object { $_.FullName })
$ipcFiles += @(Get-ChildItem tests/detectors -File -Filter 'test_ipc*.py' | ForEach-Object { $_.FullName })
python -m pytest -q @ipcFiles
python -m pytest -q tests/detectors/test_known_disclosed_cves.py
```

逐仓与逐 CVE 的统一 CLI 参数、固定提交、source SHA、JSON/Markdown 哈希和日志均记录在 `eight_repo_0.12.13/summary.json`、`disclosed_cve_0.12.13/summary.json` 与相邻产物。固定历史输入在 `historical_inputs/`。运行环境保留于原工作区的 `D:\openHarmonyScanner\tmp\`，不应把临时 checkout 当作证据；复跑请依据 summary 固定的 commit/tree 并核验 tree。

代码未修改；上述八仓与 28 个 CVE 端点原始回放绑定于扫描器源码提交 `4a8806acaa456120c496f185c8a424e0fca1671a`，回放提交与当前交付 SHA 不同；经逐文件比较，IPC family、Runner、Git source loader 和报告序列化代码在两者间无差异，测试代码另有变化。最终交付提交只增加证据复核和定位回放补充。完整全仓 fixed 端点重跑受 Python 3.13 Tree-sitter 清理崩溃限制；成功的精确文件回放已绑定同一 pinned commit，不能替代原全仓范围报告。
