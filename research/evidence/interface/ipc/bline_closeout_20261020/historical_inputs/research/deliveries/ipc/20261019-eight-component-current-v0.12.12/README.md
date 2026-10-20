# B 线八仓当前版同集回归

日期：2026-10-19

- 代码：`2fee193dd2d8a1849ac31e0683baef8c9a59d9c3`（分支 `work/ipc-20261017`；工作树另有未提交改动，结果绑定本次工作树，不代表该 HEAD 单独可复现）。
- 检测器：`ohscanner.interface.ipc 0.12.12`；模型：`oh-ipc-2026.10-v32`。
- 方法：生产 CLI `ohscan-run` 对八个固定 OpenHarmony 仓库快照重跑，范围沿用 v0.12.3 包的 `.include .`；按 `(file, line, rule_id, symbol, source_sha256)` 比较诊断身份。逐仓 commit、tree、snapshot SHA、scope、解析数、候选指纹和耗时见 `manifest.json`。

## 汇总

- 选入源文件：6,407；范围 LOC：1,233,245；源文件字节：50,553,618。
- 解析：complete 4,302，partial 1,733，not_run 372。
- 候选：30 条；规则分布：ipc.auth.missing=12, ipc.capability.export=11, ipc.relay.descriptor-boundary=7。
- 八仓均与 v0.12.3 同一仓库、commit、tree、snapshot 和 declared scope；每仓候选身份集合完全一致，identity delta=0。
- 所有运行器状态为 `completed`，外层报告为 `completed_with_limitations`；`validated_vulnerability=0`。

## 分仓结果

| 仓库 | Commit | 源文件 | complete / partial / not_run | 候选 | 运行耗时（秒） |
|---|---|---:|---:|---:|---:|
| `aafwk_standard` | `834a566b1372` | 1771 | 1222 / 531 / 18 | 15 | 29.59 |
| `applications_contacts_data` | `341cc3bf41b4` | 360 | 199 / 19 / 142 | 4 | 4.17 |
| `communication_netmanager_ext` | `8c35917b7e2f` | 654 | 434 / 198 / 22 | 0 | 9.09 |
| `distributeddatamgr_relational_store` | `42f13ea84e2f` | 1350 | 789 / 376 / 185 | 0 | 20.85 |
| `graphic_standard` | `a73af6bd3bac` | 1192 | 965 / 223 / 4 | 8 | 8.63 |
| `miscservices_pasteboard` | `dd22c7cb5e5f` | 68 | 57 / 10 / 1 | 2 | 0.35 |
| `multimedia_histreamer` | `847aafa3dc32` | 576 | 345 / 231 / 0 | 0 | 6.50 |
| `security_deviceauth` | `2cf21e46f43c` | 436 | 291 / 145 / 0 | 1 | 5.48 |

## 结论边界

这次结果证明当前版本在这八个固定输入上能稳定完成扫描，并且相对 v0.12.3 没有改变候选身份集合；它不证明这 30 条候选都是真问题，也不证明扫描器的 Precision/Recall 或对新仓库的泛化能力。八仓样本曾用于开发/调试，不是独立 holdout。解析仍有 1,733 个 partial 和 372 个 not_run 文件；未进行产品构建、运行时验证或影响确认。峰值内存未测量。

## 复现与完整性

当前版逐仓 JSON/Markdown 是本目录的 `*_standard.json/.md` 等文件；v0.12.3 对照位于 `../20261019-eight-component-retest-v0.12.3/`。`manifest.json` 记录完整来源与候选身份摘要；`SHA256SUMS` 保护本包所有报告、manifest 和本 README。
