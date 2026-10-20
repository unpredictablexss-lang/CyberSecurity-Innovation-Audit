# C8 source-audit reconciliation

状态：`remote_pinned_original_located / blocked_no_entries`。显式 fetch 后，原文已在共享本地 Git object store 的 `origin/codex/c-line-ark-runtime-20261018` 定位：commit `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`、tree `307ac8237263db793028e0bf34a82a85f60821a5`、path `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`、blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`、SHA-256 `732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240`。本目录通过 `git show` 只读核验；原文是 prose，没有显式 `c8-audit-entries` JSON block，因此结构化导入仍 fail-closed 为 `blocked_no_entries`。

本切片只写本目录，不执行扫描器，不改 Detector 语义、公共 contracts/Runner/Catalog 或历史 ID。`reconcile.py` 是 fail-closed 导入与对账层：先绑定输入 hash，再只抽取显式 `c8-audit-entries` JSON block，并校验 entry -> detector/rule/control/source identity。


## 远端 pinned 原文对账修正

原文第 196-221 行的 8 个 C 线 Ark Runtime 条目已在 `../c9_partial_owner_acceptance_20261019/source-audit-entry-reconciliation.json` 做 source-identity、finding-to-rule、control 对账。该对账只绑定源码对象和研究规则/控制，不把原文的 `candidate/unknown/未确认` 升级为产品漏洞，也不计算 Precision/Recall、FP/FN、CWE/CVE 或零错误指标。`source-audit-original.md` 是 `git show` 得到的 byte-identical 本地证据副本，其 Git blob 与 pinned object 相同。
## Fail-closed 输入状态

| 输入条件 | blocked 状态 | failure code | 行为 |
|---|---|---|---|
| 文件缺失 | `blocked_missing_input` | `input_missing` | 0 entries，missing 不是 safe/miss |
| 文件存在但无显式条目 | `blocked_no_entries` | `input_no_supported_entries` | 不从 prose 推断 entry |
| entry JSON/schema 无效 | `blocked_schema_invalid` | `input_schema_invalid` | 不生成 mapping/verdict |
| recorded hash 与文件不一致 | `blocked_hash_mismatch` | `input_hash_mismatch` | 在抽取前拒绝内容 |
| 文件存在但 hash 未绑定 | `blocked_hash_unbound` | `input_manifest_unbound` | 必须显式 refresh，不自动覆盖 manifest |

四类状态有确定性 self-test，并可连续重跑得到相同状态：

```powershell
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe research\experiments\ark_runtime\c8_source_audit_reconciliation_20261019\reconcile.py --self-test-fail-closed
```

## 当前 strict 命令

从 partial-owner worktree 根目录执行：

```powershell
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe research\experiments\ark_runtime\c8_source_audit_reconciliation_20261019\reconcile.py --strict-input --write-run-manifest
```

预期 exit code 为 `10`，`run-manifest.json` 记录 exact argv、blocked 状态、unknown ledger、input/artifact hash、限制、最小 patch 和后续义务。结构化条目补齐后，先显式绑定 hash，再运行 strict：

```powershell
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe research\experiments\ark_runtime\c8_source_audit_reconciliation_20261019\reconcile.py --refresh-input-manifest --write-run-manifest
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe research\experiments\ark_runtime\c8_source_audit_reconciliation_20261019\reconcile.py --strict-input --write-run-manifest
```

## Substitute evidence 边界

`known-source-findings.json` 明确记录：

- A sample30 `ohscanner-contacts-path-traversal-001` 的 technical report、PoC source manifest 与 provenance Git objects；
- 最新 A 线 `A_PATH_TRAVERSAL_DELIVERY_20261018` 的 research-only path source-to-sink detector/controls。

两者都是 `provisional_substitute_evidence`，不等于缺失的 `源码漏洞审查记录_20261018.md`，不在本对账层升级为 product confirmed/reportable，也不导入 Precision/Recall、FP/FN、CWE/CVE 或零错误结论。`ohscanner.cpp.path_traversal` 在固定 base 未进入产品 Runner/Catalog。

`expected-regressions.json` 只定义审计映射和未来可重放控制；`run-manifest.json` 是生成结果，不包含在 `minimal-patch.diff` 中。