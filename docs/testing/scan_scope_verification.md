# Scan Scope Verification Plan
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

> Branch: `feat/openharmony-target-onboarding`
> Status: **verified in Ubuntu 22.04 WSL2 on 2026-10-04**; 9/9 tests passed and the cJSON core scan reproduced 26 text candidates. Actual results and remaining unknowns are recorded in [PROGRAM_STATUS.md](../../PROGRAM_STATUS.md).
> Purpose: verify the new explicit source-scope feature before using its numbers in cJSON/OpenHarmony analysis.

## Why this change exists

The first real cJSON scan covered the whole repository and reported 49 text candidates. Manual triage showed that 22 came from tests and 1 from fuzzing, while the core `cJSON.c` / `cJSON_Utils.c` files contained 26 candidates.

Before comparing our scanner with clang-tidy / Clang Static Analyzer, the denominator must be explicit and reproducible. The scanner now supports repeatable relative `--include` and `--exclude` arguments and records the selected scope in JSON/Markdown reports.

This feature changes **scan scope only**. It does not make a candidate more likely to be a real vulnerability.

---

## 1. Sync the branch first

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
```

---

## 2. Run the full regression suite

```bash
python -m unittest discover -s tests -v
```

Expected after this change:

```text
Ran 9 tests
OK
```

The new tests cover:

1. include scope scans only the requested directory;
2. exclude scope prunes the requested directory;
3. overlapping include paths do not double-count files;
4. a scope path cannot escape the target root;
5. CLI scope is recorded consistently in JSON, Markdown, and stdout.

If any test fails, do not use new scoped scan counts in reports yet.

---

## 3. Confirm old CLI behavior still works

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
```

Expected:

```text
[OK] include scope: .
[OK] exclude scope: (none)
[OK] scanned files: 2
[OK] candidate findings: 1
```

This verifies backward compatibility when no explicit scope is provided.

---

## 4. Test include-only behavior on self-contained samples

```bash
python -m src.cli scan samples \
  --include vulnerable \
  --json-out outputs/reports/vulnerable_only.json \
  --md-out outputs/reports/vulnerable_only.md
```

Expected:

```text
[OK] include scope: vulnerable
[OK] scanned files: 1
[OK] candidate findings: 1
```

Then:

```bash
python -m src.cli scan samples \
  --include safe \
  --json-out outputs/reports/safe_only.json \
  --md-out outputs/reports/safe_only.md
```

Expected:

```text
[OK] include scope: safe
[OK] scanned files: 1
[OK] candidate findings: 0
```

---

## 5. Test exclusion behavior

```bash
python -m src.cli scan samples \
  --exclude safe \
  --json-out outputs/reports/exclude_safe.json \
  --md-out outputs/reports/exclude_safe.md
```

Expected:

```text
[OK] exclude scope: safe
[OK] scanned files: 1
[OK] candidate findings: 1
```

---

## 6. Test invalid scope handling

A path outside the target must be rejected:

```bash
python -m src.cli scan samples \
  --include ../outside \
  --json-out /tmp/invalid.json \
  --md-out /tmp/invalid.md
```

Expected: non-zero exit and an error containing:

```text
Include path escapes target root
```

A missing include path must also be rejected:

```bash
python -m src.cli scan samples \
  --include does-not-exist \
  --json-out /tmp/missing.json \
  --md-out /tmp/missing.md
```

Expected: non-zero exit and an error containing:

```text
Included path does not exist
```

---

## 7. Re-run cJSON with a fixed core-only denominator

The previous triage recorded 26 text candidates in the two core implementation files. Re-run exactly those files:

```bash
python -m src.cli scan /home/audit/openharmony-targets/third_party_cJSON \
  --include cJSON.c \
  --include cJSON_Utils.c \
  --json-out outputs/reports/cjson_core_candidate.json \
  --md-out outputs/reports/cjson_core_candidate.md
```

Record:

- include scope;
- scanned files;
- scanned lines;
- candidate findings;
- rule-id counts;
- skipped files.

For the already fixed cJSON commit, this run should be compared with the previously recorded **26 core candidates**. If the number differs, investigate before changing PROGRAM_STATUS or target_selection.md.

Do not interpret “26 candidates” as “26 vulnerabilities”.

---

## 8. Inspect report metadata

Check:

```bash
python - <<'PY'
import json
from pathlib import Path

p = Path("outputs/reports/cjson_core_candidate.json")
data = json.loads(p.read_text(encoding="utf-8"))
print(json.dumps(data["scope"], indent=2))
print("files:", data["scanned_files"])
print("lines:", data["scanned_lines"])
print("candidates:", data["finding_count"])
PY
```

Expected scope shape:

```json
{
  "include_paths": [
    "cJSON.c",
    "cJSON_Utils.c"
  ],
  "exclude_paths": []
}
```

The Markdown report should contain the same include/exclude scope.

---

## 9. Codex verification request

Give Codex this instruction after pulling the branch:

```text
Read PROGRAM_STATUS.md and docs/testing/scan_scope_verification.md first.

Run the full unittest suite and every command in the verification plan that does not require unavailable external dependencies.

For cJSON, use the already cloned fixed repository at:
/home/audit/openharmony-targets/third_party_cJSON

Do not change expected counts just to make tests pass.
If a count differs, inspect the code and explain why.

Report:
1. tests passed/failed;
2. exact failing test names if any;
3. cJSON core-only scanned files/lines/candidate count;
4. JSON scope metadata;
5. whether backward compatibility without --include/--exclude still works;
6. any code changes you made.
```

---

## Acceptance gate

Only after all of the following are true should the scoped result replace the old all-repository denominator in future analysis:

- all regression tests pass;
- old sample scan still works;
- invalid scope paths are rejected;
- core-only cJSON scan is reproducible;
- JSON and Markdown record the same scope;
- no duplicate file is counted when include paths overlap.

After this gate, proceed to the mature static-tool baseline and function-context work described in `PROGRAM_STATUS.md`.
