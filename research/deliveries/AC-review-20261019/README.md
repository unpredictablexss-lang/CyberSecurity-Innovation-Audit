# A/C 线评委审阅交付包

- `AC线开发与实验成果审阅材料.md`：能力、实验口径、CVE/PoC 边界及复核路径。
- `../../outputs/01a153a5-3a9e-79b2-95ee-6c2303a5db15/AC线开发与实验结果_20261019.xlsx`：总览、开发能力、实验结果、CVE与PoC、规模与限制、来源六个工作表。
- `sources/`：总结实际引用的 A 线原始 Markdown/CSV 报告及关键 CLI 回放 JSON/Markdown。C 线当前状态来自同一分支的 `docs/项目现状与下一步.md`，实现版本可由 `src/ohscanner/detectors/ark_runtime/model.py` 核验。
- `SHA256SUMS.txt`：对本交付目录（不含本清单）与配套 Excel 的 SHA-256 校验。

**重要边界：** 候选/公开 CVE 源码回放/组件机制 PoC 均不等于 OpenHarmony 产品漏洞确认。Contacts 路径穿越为未分配 CVE 的源码机制结论，产品适用性和版本待核验。CVE 修复前后候选数量仅描述固定回归集，不代表全局 Precision/Recall。全量扫描快照是 2026-10-18 历史报告，不是本次重跑。
