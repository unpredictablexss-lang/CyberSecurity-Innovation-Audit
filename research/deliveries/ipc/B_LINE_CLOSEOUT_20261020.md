# B 线 IPC 收尾交付（2026-10-20）

本交付以主线 `dd8b12b9f0fcf3d8bc96a2d7fbb3d679809d2e35` 为起点，检测器 `ohscanner.interface.ipc` 为 `0.12.13`，模型为 `oh-ipc-2026.10-v33`。DATA-06 已在主线注册，规则 `ipc.parcel.array-allocation-width` 为 `0.1.0`。B 集成来源 `40e3d79f38629b273214f1efee0f22b7443849f1` 的 DATA-06 实现、控制夹具和解析修复均已进入主线；与 B 分支相比，主线还保留了更严格的 IPC 防护与来源绑定。B 分支上其余差异主要是删除既有安全/固定夹具或修改测试期望，未迁入。

## 已执行的复验

- IPC 回归：`python -m pytest -q <从 tests/ 选择的 test_ipc*.py 文件>`，结果 **377 passed, 47 skipped**。跳过项仍按测试自身的环境/覆盖条件标记；没有折算成通过。
- DATA-06 针对性套件：`python -m pytest -q tests/test_ipc_t74_cj_array_bounds_integration_challenge.py tests/test_ipc_family_depth.py tests/test_ipc_family_matrix.py tests/test_ipc_rule_versions.py tests/test_ipc_holdout_contract.py`，**44 passed**。套件核对两个 vulnerable Git 修订、官方 fixed 修订、仓库身份、源 SHA、正例去重、错误仓库、CheckReadLength-only、无关方法、短输入、安全控制及注释回归。
- 统一 CLI 固定源码回放：见 [bline_closeout_20261020](../../evidence/interface/ipc/bline_closeout_20261020/)。DATA-06 两个 vulnerable 修订分别得到 1 条 `ipc.parcel.array-allocation-width` candidate；官方修复 `de3a68cc8b7d6f18017fd261060def0e38dce54a` 得到 0 条。三者均由 M2 `ohscan-run` 在单文件固定范围报告，运行状态 completed，文件 SHA 与测试 manifest 一致。两个历史修订属于同一 CVE/函数根因，按 1 个根因计，不按 2 个漏洞计。
- IPC 同源基线比较：在固定 `communication_ipc` commit `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` 上，从 0.12.12 升至 0.12.13 重跑 M2 CLI。两次均为 697 个源文件、同一 tree、同一 snapshot，解析覆盖均为 complete 442 / partial 218 / not_run 37，candidate observations **14 → 14**。逐项比较结果：14 retained、0 added、0 removed，身份均按 file/line/rule/symbol/source SHA 对齐；14 条观察合为 12 个 file/rule/symbol 分组。当前结果仍有 partial 源，任务状态 `completed_with_limitations`；14 条是观察数，不是 14 个已确认漏洞，也不是 14 个独立根因。原 0.12.12 JSON 保存在原工作区 `D:\openHarmonyScanner\tmp\b-ipc-replay-20261020\integrated.json`，本次 0.12.13 JSON 和 Markdown 随本交付保存。
- Contacts 解析复核：对固定 Contacts Git 对象 `b02aadfc2d801ee30573fcb2d13490298e146fea:dataBusiness/contacts/src/contacts_data_ability.cpp` 直接调用当前 `src.parser.ast.parse_source`。原始字节 80,944，SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`，状态 `complete`，`parse_issues=[]`。本轮没有重现 IPC Parser 回归；Contacts 的既有路径候选属 C++ 路径规则，与 IPC 家族分开记录。
- 已披露 CVE 回归：`python -m pytest -q tests/detectors/test_known_disclosed_cves.py`，**21 passed**，覆盖当前测试文件中的 17 个 CVE 标识。此结果是测试套件回归，不能充当“14 个固定披露 CVE 的精确 vulnerable/fixed Git 版本回放”；该 14 项清单在当前 B 交付材料/可用缓存中没有找到，因此精确版本回放记为 `not_run`，没有用 0.12.12 的历史报告代替。

## 候选复核索引与范围差异

结构化的 14 条候选观察对照、各自规则和源码 SHA 位于本目录证据索引 `candidate_comparison.json`。所有观察在固定同一源码树上保持身份不变；本轮没有增删候选。已有 2026-10-17 B 线真实组件测量和 2026-10-20 `communication_ipc` 旧回放是不同范围，不将其 30 个历史观察/28 个根因聚类基线与本轮 14 个 observation 混算。

用户给出的“八仓固定范围、30 observations、28 roots”作为比较基线保留。当前仓库内未找到对应八仓 manifest、逐仓 Git SHA/树身份和历史 30 条 observation 的逐项导出；只有单仓 `communication_ipc` 固定回放材料可复用。因此八仓全量同范围复跑与逐条身份变化解释为 `not_run / missing exact scope manifest`，没有换用最新 HEAD 或扩大到其他仓库扫描。后续补齐原八仓精确仓库/提交清单后，可按同一 Runner 比较。

## 数据与结论边界

- DATA-06 的 CVE-2025-26474 挑战把两个 vulnerable 修订回放识别为同一个源码根因，官方 fixed 修订无命中。它是设计控制和已披露漏洞的源码回归，不是独立 holdout 评估。
- DATA-06 当前测量声明仍是 `measurement_status=not_run`、空 holdout；本轮没有生成 Precision/Recall，也没有把设计控制计作准确率证据。
- 源码命中和修复对照不能单独证明产品构建纳入、部署、攻击者可达性、权限边界或 CIA 影响。候选继续保持 candidate/unknown；`validated_vulnerability=0`。
- 当前规则适用/实际评估逐规则统计尚未成为共享 Runner 协议。零候选规则的覆盖保持 unknown，不解读为安全。
- 具备本地 CLI 验收；未连接隔离平台环境，本轮没有做候选详情页面与报告导出接线验收。

## 状态

| 层级 | 状态 |
|---|---|
| B 线工程实现 | DATA-06 与主线 IPC 0.12.13/model v33 代码已集成；回归通过 |
| 本轮证据交付 | 本分支新增，提交后可审查；与证据报告 SHA 清单绑定 |
| 主线合入 | 检测器代码已在主线；本轮新增的收尾报告/回放材料是否单独合入按交付分支记录 |
| 部署 | 未验证；产品部署状态 unknown |
| 漏洞验证 | 未验证产品漏洞；源码回归与修复对照完成，validated_vulnerability=0 |
| 独立准确率评估 | not_run；DATA-06 holdout 未冻结 |
| 产品验证 | not_run；产品 build、入口/权限与影响证据缺失 |

复现命令：

```powershell
$env:T74_IPC_GIT = '<包含 manifest 固定提交的 communication_ipc Git checkout>'
python -m pytest -q tests/test_ipc_t74_cj_array_bounds_integration_challenge.py tests/test_ipc_family_depth.py tests/test_ipc_family_matrix.py tests/test_ipc_rule_versions.py tests/test_ipc_holdout_contract.py
$ipcFiles = @(Get-ChildItem tests -File -Filter 'test_ipc*.py' | ForEach-Object { $_.FullName })
$ipcFiles += @(Get-ChildItem tests/detectors -File -Filter 'test_ipc*.py' | ForEach-Object { $_.FullName })
python -m pytest -q @ipcFiles
python -m pytest -q tests/detectors/test_known_disclosed_cves.py
python -m src.cli ohscan-run --repo-dir '<communication_ipc checkout>' --repository openharmony/communication_ipc --commit 84d681288793785e8f39f71c824f211edaed8f1e --include interfaces/innerkits/cj/src/message_sequence_impl.cpp --detector ohscanner.interface.ipc --json-out '<out>/data06-old-cve-parent.json' --md-out '<out>/data06-old-cve-parent.md'
python -m src.cli ohscan-run --repo-dir '<communication_ipc checkout>' --repository openharmony/communication_ipc --commit 67cd9d3e8e08971ba614a19f99b5f6b7ec4ea039 --include interfaces/innerkits/cj/src/message_sequence_impl.cpp --detector ohscanner.interface.ipc --json-out '<out>/data06-old-umbrella-issue-revision.json' --md-out '<out>/data06-old-umbrella-issue-revision.md'
python -m src.cli ohscan-run --repo-dir '<communication_ipc checkout>' --repository openharmony/communication_ipc --commit de3a68cc8b7d6f18017fd261060def0e38dce54a --include interfaces/innerkits/cj/src/message_sequence_impl.cpp --detector ohscanner.interface.ipc --json-out '<out>/data06-official-security-fix.json' --md-out '<out>/data06-official-security-fix.md'
```

要重放 697 个文件的版本对照，`--repo-dir` 必须是包含旧扫描提交 `5903fd5f7332a427cb3f6915b0202ee5c76c63b5` 对象的本地 `communication_ipc` Git 数据库，并省略 `--include`：

```powershell
python -m src.cli ohscan-run --repo-dir '<communication_ipc Git checkout>' --repository openharmony/communication_ipc --commit 5903fd5f7332a427cb3f6915b0202ee5c76c63b5 --detector ohscanner.interface.ipc --json-out '<out>/communication-ipc-5903fd5-ipc-0.12.13.json' --md-out '<out>/communication-ipc-5903fd5-ipc-0.12.13.md'
```

精确源对象可先从已有本地 bare Git 缓存读取，或从已授权公开 upstream 获取；不得把缺失对象替换成 HEAD。报告 SHA-256、固定源版本和最终提交绑定由本目录 `delivery_inventory.json` 与 `candidate_comparison.json` 提供。新扫描边界仅为已固定的 DATA-06 三个源码版本和一项既有 `communication_ipc` 对照回放；没有启动全量仓库扫描。
