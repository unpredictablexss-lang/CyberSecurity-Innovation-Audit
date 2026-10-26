# C 线独立留出集评估简报

日期：2026-10-18（Asia/Shanghai）  
状态：**本清单不是该冻结 Detector 的有效性能 holdout。**源码清单和冻结版本已有记录，但 9/9 样本均 `not_applicable`；独立双人标签、盲态声明和分歧裁决均缺失，指标不可估计。

## 冻结版本

冻结 OHScanner Ark Runtime Detector `ohscanner.ark.runtime.type_safety` **0.6.2**，规则为 `ark.runtime.typedarray-store-type-origin` 与 `ark.runtime.typedarray-allocation-exception-guard`，模型 SHA-256 `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`。冻结基线 scanner commit `5cceb70e3b00b5e4938bfcee378863a8232931a9`、tree `33df67ffd1529d098bcbabbba63ac4c9199b01c9`；文件 SHA-256、Git blob SHA-1、18 个模型输入路径和 parser 哈希见 `frozen_detector.json`。版本来自 HEAD 的干净归档；当前原工作树有其他未提交变更，未纳入冻结版。

盲跑使用该冻结归档和下列源码身份清单。没有针对留出结果修改规则或模型。

## 样本和来源

`holdout_source_manifest.csv` 包含 9 个源码单元的 commit、tree、path、blob、源 SHA-256、字节数和冻结 parser 状态。对象身份在隔离的 Ark Runtime Git 对象库中验证。来源是公开 Ark Runtime 仓库；交付不包含源码正文。旧 `sample_manifest.csv` 是历史开发样本记录，不属于本次 9 行清单。

样本为预先分层的目的性选择：两组 Array species 修复前后版本，以及 TypedArray、宏/继承头文件、shared TypedArray、分配器和 TLAB 结构探针。它们覆盖同名符号、模板/继承、宏、species 包装/调用路径、分配器和 parser partial。9 个源码单元并非 9 个独立漏洞案例；实际只有两个补丁家族，且是相邻 Array species 行为的控制案例，不能代表目标 TypedArray 规则的正例集合。选择不是概率抽样。

本轮已知的早期规则开发绑定路径不在 9 个选中路径内；对已知 C1-C6 实验材料的本地搜索未发现这些路径。这不构成根因/补丁家族级的完整泄漏审计，family_leakage_audit.csv 已记录对当前可用本地 C1-C6 材料的精确补丁提交、family ID 和 JSStableArray 目标方法搜索，未发现命中；未跟踪或外部调参材料仍未验证。也没有审查者声明，无法证明审查独立性。

## 独立标注状态

`blind_review_packet.csv` 是不给出机制分层或预测的审阅包；`annotation_template.csv` 为两位审查者分别记录标签、证据、理由、时间戳、分歧和裁决。标签应为 `vulnerable`、`fixed`、`safe`、`unrelated`、`unknown`。截至本简报生成，尚无独立审查者提交标签，标签快照未冻结，也无分歧裁决记录。不能由 Detector 开发者代填真值。

## 冻结盲跑结果

`blind_run_summary.json` 记录汇总及原始预测 escrow 的路径/摘要哈希；该 escrow 文件在当前工作区缺失，复核时未读取。没有审查者收到材料，也没有标签冻结或预测揭盲。历史摘要中的 0 候选仅作运行记录，不能计作性能结果。

- 样本数：9；冻结 parser：8 complete、1 partial（解析覆盖按源码单元计为 8/9 complete，1/9 partial）。
- Detector 报告状态：9 blocked；Detector 覆盖状态：9 not_applicable；候选数：0。所有样本路径均在冻结模型适用输入路径之外，因此本轮未获得可计分的 Detector 目标覆盖。
- 这些 0 候选不能解读为安全、漏报或命中结果；blocked/not_applicable 也不算漏报。
- TP、FP、FN、precision、recall、准确率以及按机制/版本的检测指标均为 **不可估计**：没有独立冻结标签，且没有目标规则覆盖的样本。

| 切片 | 样本单元 | Parser complete / partial | 盲跑覆盖 | 指标状态 |
|---|---:|---:|---|---|
| Map species 修复前后 | 2 | 2 / 0 | 2 blocked / not_applicable | 不可估计 |
| Filter species 修复前后 | 2 | 2 / 0 | 2 blocked / not_applicable | 不可估计 |
| TypedArray 标准 builtin | 1 | 1 / 0 | 1 blocked / not_applicable | 不可估计 |
| TypedArray 宏/继承头文件 | 1 | 0 / 1 | 1 blocked / not_applicable | 不可估计 |
| Shared TypedArray | 1 | 1 / 0 | 1 blocked / not_applicable | 不可估计 |
| Allocator | 1 | 1 / 0 | 1 blocked / not_applicable | 不可估计 |
| TLAB allocator | 1 | 1 / 0 | 1 blocked / not_applicable | 不可估计 |

此分层只描述来源样本及覆盖状态，不是按漏洞机制计算出的准确率切片。

### 另一个历史未建模观察（不计入本轮 9 个样本）

历史 C 线重放记录另含 commit `95554c2ee75b35d556640eb6f2591d429796f60e` 的同目标文件样本：tree `65728158c365a0100db906bfca1cedf3ee3f5ebf`、blob `e652d5e5ef1cec7176527f4d04023a8060abb5e9`、source SHA-256 `db7856c17f46d4a6c9ac1e5114e72504c5487ace4cc92d70eacb8deaeb190fb4`。历史报告给出的状态是 out-of-model / not_analyzed / blocked、候选 0、标签 unknown。它不是独立标注，也不能视为安全或漏报。那次重放虽然使用相同模型 digest 和 Detector 版本，parser、indexing、runner 的实现 SHA 与本次干净冻结归档不同（见 `C-line-historical-replay.json`）；因此该观察只作为历史上下文，不并入当前盲跑样本数、切片或指标。

## 限制和后续

1. 目的性探针、9 个源码单元、两个相邻补丁家族，不足以支持总体或分层准确率估计。
2. 目标 Detector 对全部所选路径均报告 blocked/not_applicable；这批来源不能评估 Detector 的实际命中或误报。
3. 没有独立标注资源、双人标签、证据与分歧裁决。请由未参与规则开发且未接触这些案例的两名审查者填写模板，并冻结标签文件哈希；若无法做到，应明确报告标签缺失，不能发布准确率。
4. 盲审包提供来源定位以便复核，公开 commit 可能暴露补丁上下文；审查者的既往接触情况需登记，不能仅凭 ID 盲化证明盲态。
5. 冻结规则绑定精确源码版本，而当前清单又要求样本路径避开全部模型输入路径；这两项约束使当前清单没有可证明的目标规则覆盖。不能把当前历史版本扩展绑定后仍称为同一冻结模型。若要评估更新后的 detector，先冻结新版本和其适用范围，再从未参与开发/调参的根因家族抽新 holdout。
6. 未复制源码到输出交付；未推送、未合并。

## 复现

需准备同一组固定 Git 对象和冻结 scanner 归档：

```powershell
python .\outputs\build_holdout_artifacts.py --runtime-repo .\work\holdout-repo --scanner-root .\work\frozen-scanner-5cceb70 --output-dir .\outputs
python .\outputs\blind_replay.py --runtime-repo .\work\holdout-repo --scanner-root .\work\frozen-scanner-5cceb70 --escrow-output .\work\prediction-escrow\holdout_run.json --summary-output .\outputs\blind_run_summary.json
```

构建脚本验证来源对象和 parser 状态并生成 metadata-only 清单/审阅表；重放脚本校验冻结模型、来源哈希和标签尚未填写后运行 Detector。原始预测仅写入 work escrow。最终输出 SHA-256 见 `artifact_hashes.json`。
