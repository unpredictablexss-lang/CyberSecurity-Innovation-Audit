# Function Context Verification Plan
> **政策更新 2026-10-10**：本文为历史记录（记录某时点实际做了什么），事实性内容保留原样。文中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**；当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物。

> Branch: `feat/openharmony-target-onboarding`
> Status: **verified in Ubuntu 22.04 WSL2 on 2026-10-04**; 14/14 tests passed, cJSON core remained 26 candidates, and all six spot checks matched. Actual results and unknowns are in [PROGRAM_STATUS.md](../../PROGRAM_STATUS.md).
> Scope: lightweight top-level C/C++ function context only. This is **not** Clang AST, CFG, data-flow, reachability, or vulnerability validation.

## Why this feature is next

The cJSON core-only scan is now reproducible at 2 files, 4,681 lines and 26 text candidates. The next practical problem from manual triage is that a Finding previously contained only one source line and usually had `function = null`.

This change adds a best-effort context layer so a candidate can carry:

- enclosing top-level function name;
- function start/end line;
- a small local source window around the candidate;
- an explicit `context_status`.

The resolver deliberately labels successful matches:

```text
heuristic_top_level_function
```

It does **not** claim AST-quality C/C++ semantics. Complex C++ class bodies, attributes/macros or malformed code may remain `unresolved`.

---

## 1. Sync before testing

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
```

---

## 2. Run all unit/regression tests

```bash
python -m unittest discover -s tests -v
```

Before this change the branch had 9 passing tests. Five new context tests were added, so the expected total is:

```text
Ran 14 tests
OK
```

Do not edit expected values merely to make tests pass. If the total or behavior differs, report the exact failing test and cause.

The new tests cover:

1. simple top-level C function resolution;
2. cJSON-style `CJSON_PUBLIC(...)` signature resolution;
3. braces inside comments/string literals do not terminate a function early;
4. unresolved top-level candidate still gets a local context window;
5. scanner copies function/context metadata into Finding.

---

## 3. Re-run the original sample scan

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_context.json \
  --md-out outputs/reports/samples_context.md
```

The old scan behavior must remain:

```text
scanned files: 2
candidate findings: 1
```

Now inspect the vulnerable Finding:

```bash
python - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("outputs/reports/samples_context.json").read_text(encoding="utf-8"))
f = data["findings"][0]
for key in (
    "function",
    "function_start_line",
    "function_end_line",
    "context_start_line",
    "context_end_line",
    "context_status",
    "context",
):
    print(f"{key}: {f.get(key)}")
PY
```

Expected essential behavior:

```text
function: bad_copy
context_status: heuristic_top_level_function
```

The context must include the `strcpy(buf, input);` line. Exact context start/end is determined by the local radius and function boundary; record the actual values.

---

## 4. Re-run the fixed cJSON core-only scan

Use the same fixed source commit already recorded in PROGRAM_STATUS:

```text
0c2c9dff82cc85539c8362132d7a5f6bf7d1e748
```

Run:

```bash
python -m src.cli scan /home/audit/openharmony-targets/third_party_cJSON \
  --include cJSON.c \
  --include cJSON_Utils.c \
  --json-out outputs/reports/cjson_core_context.json \
  --md-out outputs/reports/cjson_core_context.md
```

Acceptance requirement:

- scanned files remains 2;
- scanned lines remains 4,681;
- candidate findings remains 26;
- no candidate disappears merely because context resolution was added.

If the count changes, stop and investigate before updating status documents.

---

## 5. Measure context resolution instead of assuming it

Run:

```bash
python - <<'PY'
import json
from collections import Counter
from pathlib import Path

data = json.loads(Path("outputs/reports/cjson_core_context.json").read_text(encoding="utf-8"))
findings = data["findings"]

statuses = Counter(f.get("context_status") for f in findings)
functions = Counter(f.get("function") or "<unresolved>" for f in findings)

print("candidate_count:", len(findings))
print("context_status:", dict(statuses))
print("resolved:", sum(1 for f in findings if f.get("function")))
print("unresolved:", sum(1 for f in findings if not f.get("function")))
print("functions:")
for name, count in functions.most_common():
    print(f"  {name}: {count}")
PY
```

Do **not** assume all 26 must resolve. Record actual results. Any unresolved item should be inspected and classified as either:

- expected limitation of the heuristic;
- real parser bug;
- unusual source construct needing later Clang/Tree-sitter support.

---

## 6. Spot-check known cJSON candidates

The following locations belong to the fixed cJSON commit and are useful sanity checks:

| Location | Expected enclosing function |
|---|---|
| `cJSON.c:204` memcpy | `cJSON_strdup` |
| `cJSON.c:367` memcpy | `parse_number` |
| `cJSON.c:465` strcpy | `cJSON_SetValuestring` |
| `cJSON.c:570` memcpy | `ensure` |
| `cJSON_Utils.c:234` sprintf | `cJSONUtils_FindPointerFromObjectTo` |
| `cJSON_Utils.c:245` strcat | `cJSONUtils_FindPointerFromObjectTo` |

Check them automatically:

```bash
python - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("outputs/reports/cjson_core_context.json").read_text(encoding="utf-8"))

expected = {
    ("cJSON.c", 204): "cJSON_strdup",
    ("cJSON.c", 367): "parse_number",
    ("cJSON.c", 465): "cJSON_SetValuestring",
    ("cJSON.c", 570): "ensure",
    ("cJSON_Utils.c", 234): "cJSONUtils_FindPointerFromObjectTo",
    ("cJSON_Utils.c", 245): "cJSONUtils_FindPointerFromObjectTo",
}

seen = {}
for f in data["findings"]:
    key = (Path(f["file_path"]).name, f["line"])
    if key in expected:
        seen[key] = f.get("function")

for key, wanted in expected.items():
    actual = seen.get(key)
    print(key, "expected=", wanted, "actual=", actual, "OK" if actual == wanted else "MISMATCH")
PY
```

A mismatch is useful evidence: do not hide it. Determine whether the resolver or the expected line mapping is wrong.

---

## 7. Inspect Markdown output

Open:

```text
outputs/reports/cjson_core_context.md
```

Each candidate should now show:

- Function;
- Function range;
- Context status;
- Context lines;
- Evidence;
- Context.

The report must still retain the disclaimer that findings are text-pattern candidates and not validated vulnerabilities.

---

## 8. Performance sanity check

Context extraction should not make the tiny cJSON core scan unreasonably slow.

Measure once:

```bash
/usr/bin/time -v python -m src.cli scan /home/audit/openharmony-targets/third_party_cJSON \
  --include cJSON.c \
  --include cJSON_Utils.c \
  --json-out /tmp/cjson_context_perf.json \
  --md-out /tmp/cjson_context_perf.md
```

Record:

- elapsed wall time;
- maximum resident set size;
- exit code.

This is only a sanity measurement, not the final benchmark.

---

## 9. What Codex may fix

Codex may make minimal changes if tests reveal an actual bug in:

- function span detection;
- comment/string masking;
- cJSON macro-style signature extraction;
- context range calculation;
- report serialization.

Codex should **not** in this round:

- add Tree-sitter;
- add Clang Python bindings;
- implement CFG/data-flow/taint;
- add new dangerous API rules;
- change the cJSON source;
- mark a candidate as a vulnerability.

If the heuristic cannot reliably handle a construct, preserve it as `unresolved` and document the limitation rather than inventing semantic certainty.

---

## 10. Result report back to PROGRAM_STATUS

After testing, append a short factual record with:

1. total tests passed/failed;
2. sample `bad_copy` function-resolution result;
3. cJSON 2 files / lines / candidate count;
4. resolved vs unresolved candidate count;
5. six spot-check results;
6. elapsed time / peak RSS;
7. code changes Codex made, if any;
8. verified / unverified / unknown separated explicitly.

Do not call context extraction “AST analysis”. It is a lightweight heuristic layer whose purpose is to make manual triage and the next parser decision evidence-driven.
