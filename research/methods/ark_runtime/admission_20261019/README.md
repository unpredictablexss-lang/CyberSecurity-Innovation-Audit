# C7 exact identity 与 partial AST evidence admission RFC 切片

日期：2026-10-19。状态：负责人评审草案；本轮只提供可执行协议、兼容矩阵、验收条件和后续实现切片，不修改公共代码、docs、数据库、API、UI 或其他代理目录。

## 固定输入与边界

本切片只核对以下固定本地内容：

- `docs/架构与公共协议.md`
- `src/ohscanner/contracts.py`
- `src/ohscanner/runner.py`
- `src/ohscanner/detectors/catalog.py`（任务中的 `catalog.py` 在当前 checkout 的实际路径）
- `research/experiments/ark_runtime/c2_20261017/PARTIAL_ADMISSION_RFC.md`
- `research/experiments/ark_runtime/c3_20261017/C3_PARTIAL_RFC_UPDATE.md`
- `research/experiments/ark_runtime/c4_20261018/C4_PARTIAL_RFC.md`

目标 checkout 为 `E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019`，HEAD 为 `556cb145fec9f52afd1c49d10290e01036200f00`，固定 commit tree 为 `7ccd0895622669ac33595c1058e5f0ede0b8e5a5`。核验时 worktree clean；remote 仅用于陈述本地配置，不执行 fetch。未运行外部扫描器，未进行动态验证。

## 交付物

- `admission-rfc.md`：exact snapshot/build-profile/source identity、region admission、污染模型、状态和聚合语义。
- `compatibility-matrix.json`：source-bound schema v2、legacy v1 和公共 contracts/Runner/Catalog 的兼容切片。
- `acceptance-checklist.md`：positive/fixed/safe/unrelated/unknown 控制及 fail-closed 验收。
- `implementation-slices.md`：公共协议、Runner/Catalog 和算法修复的独立后续实现顺序。
- `README.md`：本索引、范围和禁止事项。

## 核心结论

现有 v2 已能绑定 finding 到 source SHA，并保留 blocked run 的局部候选；但 `ScanRequest` 只有 repository 名、full commit、snapshot digest 和单个 `profile_id`，`DetectorRun.file_outcomes` 也只到文件级。要准入 partial AST，必须以附加、显式、不可隐式推断的 admission record 补齐 tree/blob、build profile/dependency closure、region scope、parse/dependency contamination 与预算闭合状态。

准入只说明“某些有限程序事实在明确范围内可被保留和审计”，不说明漏洞、可达性、ownership、dominance、并发、attacker control、CIA impact、CVE 或任何指标。所有安全结论仍为 `candidate/unassessed`。

## 使用顺序

1. 读 `admission-rfc.md` 确认协议字段与 fail-closed 语义。
2. 用 `compatibility-matrix.json` 规划独立公共协议提交和兼容测试。
3. 按 `acceptance-checklist.md` 逐项建立 fixture/回归；缺项保持 unknown 或 not_analyzed。
4. 只在负责人批准协议切片后，依照 `implementation-slices.md` 落地；算法修复另行提交。