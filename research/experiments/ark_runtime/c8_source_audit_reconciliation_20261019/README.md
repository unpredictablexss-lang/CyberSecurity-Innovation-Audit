# C8 source-audit reconciliation scaffold

状态：`blocked_missing_input`。目标输入 `源码漏洞审查记录_20261018.md` 在当前 checkout、tracked paths、本地提交路径和 pinned object path 搜索中均未找到；本目录不把缺失输入转换成漏洞条目，也不声称已读取该文件。

本切片只写入本目录，不改生产代码、`docs/` 或其他代理目录。脚手架是 fail-closed 对账层：它检查输入身份、条目 schema、finding -> detector/rule/control 映射、positive/fixed/safe/unrelated/unknown 控制和缺项，不执行扫描器，不产生准确率或漏洞结论。

## 产物

- `input-manifest.json`：输入路径、缺失状态、SHA-256（存在时）、Git commit/tree/blob（可得时）和本地搜索证据。
- `audit-schema.json`：源码审查条目 source-bound v2 的约束；缺失值必须显式 `unknown`。
- `known-source-findings.json`：仅保留当前工作树可核验的 C3 六个 type-origin 反例、C4 Filter/Map/ToReversed/exception-order unknowns、C7 dependency/replay 限制，均标为 provisional/substitute evidence。
- `reconcile.py`：仅使用 Python 标准库；可选调用只读 `git cat-file` 核验记录的 Git 对象。它不调用扫描器。
- `expected-regressions.json`：type-origin 六反例、guard-before/after/unknown、partial owner fail-closed、历史对象缺失的验收范围。
- `run-manifest.json`：一次脚手架运行的结果、失败/unknown 账本和下一持续切片。

## 输入补齐后的重跑

在仓库根目录执行：

```powershell
python.exe research\experiments\ark_runtime\c8_source_audit_reconciliation_20261019\reconcile.py --write-run-manifest
```

输入仍缺失时，命令应报告 `execution_status=blocked_missing_input` 并保留 `extracted_vulnerability_entries=0`；只有显式 JSON 条目块通过 schema、source identity、映射和证据门检查后才会形成导入条目。`--strict-input` 在缺失输入时返回非零，供人工门使用。

## 边界

C3/C4/C7 内容是替代输入，不是 `源码漏洞审查记录_20261018.md` 的抽取结果。Filter/Map/ToReversed/exception-order、partial owner、历史 replay 和依赖状态均保留 unknown/义务；不得从本目录推导产品漏洞、CIA、CVE、Precision/Recall 或零 FP/FN。