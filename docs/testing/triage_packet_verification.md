# Candidate Triage Packet Verification

> Branch: `feat/openharmony-target-onboarding`  
> Status: **verified in Ubuntu 22.04 WSL2 on 2026-10-04**; 23/23 tests passed, fixed cJSON core produced 26 packets with 26 parsed calls and 0 unresolved. Actual results and limits are in [PROGRAM_STATUS.md](../../PROGRAM_STATUS.md).
> Purpose: turn the existing 26 cJSON text candidates into structured review packets without claiming any vulnerability.

## Why this is the next step

The current evidence chain is already reproducible:

- scanner/scope/context tests passed;
- Clang baseline runner passed;
- fixed cJSON core scope is 2 files / 4,681 lines / 26 text candidates;
- default `clang --analyze` produced zero diagnostics.

The next question is not “which tool wins?” It is:

> For each text candidate, what call is being made, what are its arguments, and what safety properties must be checked before the candidate can be accepted or rejected?

This round therefore adds **triage packets**, not vulnerability verdicts.

---

## 1. Sync the branch

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
git status
```

Do not continue with unexplained local modifications.

---

## 2. Run the full test suite

The previously verified total was 18 tests. Five triage tests were added.

Run:

```bash
python -m unittest discover -s tests -v
```

Expected if the new code is correct:

```text
Ran 23 tests
OK
```

Do not change expected values merely to get 23/23. If a test fails, record the exact test name, traceback, and root cause; make only the minimum justified fix.

The five new tests cover:

1. simple `strcpy(dst, src)` argument parsing;
2. nested calls inside `memcpy` arguments;
3. multiline `sprintf` and a format string containing a comma;
4. review-packet obligations/default states without promoting vulnerability status;
5. CLI JSON/Markdown triage output.

---

## 3. Confirm the cJSON source and candidate report

Target source:

```text
/home/audit/openharmony-targets/third_party_cJSON
```

Expected commit:

```text
0c2c9dff82cc85539c8362132d7a5f6bf7d1e748
```

Check:

```bash
cd /home/audit/openharmony-targets/third_party_cJSON
git rev-parse HEAD
git status --short
```

Do not modify cJSON.

Return to the audit project and ensure the source scan report exists:

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit

python -m src.cli scan \
  /home/audit/openharmony-targets/third_party_cJSON \
  --include cJSON.c \
  --include cJSON_Utils.c \
  --json-out outputs/reports/cjson_core_context.json \
  --md-out outputs/reports/cjson_core_context.md
```

Hard regression baseline remains:

```text
scanned_files = 2
scanned_lines = 4681
candidate_findings = 26
```

---

## 4. Build triage packets

Run:

```bash
python -m src.cli triage \
  --scan-report outputs/reports/cjson_core_context.json \
  --json-out outputs/reports/cjson_core_triage.json \
  --md-out outputs/reports/cjson_core_triage.md
```

Record stdout:

- candidate packets;
- parsed call expressions;
- unresolved call expressions.

Expected invariant:

```text
candidate packets = 26
```

Do **not** pre-assume all 26 calls must parse. Record actual parsed/unresolved counts.

---

## 5. Inspect packet structure

Run:

```bash
python - <<'PY'
import json
from collections import Counter
from pathlib import Path

p = Path("outputs/reports/cjson_core_triage.json")
data = json.loads(p.read_text(encoding="utf-8"))

print("candidate_count:", data["candidate_count"])
print("packet_count:", data["packet_count"])
print(
    "parse_status:",
    dict(Counter(p["call_parse_status"] for p in data["packets"]))
)
print(
    "call_names:",
    dict(Counter(p["call_name"] for p in data["packets"]))
)
print(
    "review_status:",
    dict(Counter(p["review"]["review_status"] for p in data["packets"]))
)

for packet in data["packets"]:
    print(
        Path(packet["file"]).name,
        packet["line"],
        packet["function"],
        packet["call_name"],
        packet["call_parse_status"],
        packet["call_arguments"],
        packet["candidate_id"],
    )
PY
```

The default review state must remain:

```text
review_status = unreviewed
input_control = unknown
destination_capacity = unknown
length_origin = unknown
guard_evidence = unknown
reachability = unknown
security_impact = unknown
runtime_validation = not_started
```

Generating a packet must not promote the source Finding.

---

## 6. Spot-check six known callsites

Inspect these fixed locations:

| Location | Call | Expected argument structure |
|---|---|---|
| `cJSON.c:204` | memcpy | `copy`, `string`, `length` |
| `cJSON.c:367` | memcpy | `number_c_string`, `buffer_at_offset(input_buffer)`, `number_string_length` |
| `cJSON.c:465` | strcpy | `object->valuestring`, `valuestring` |
| `cJSON.c:570` | memcpy | `newbuffer`, `p->buffer`, `p->offset + 1` |
| `cJSON_Utils.c:234` | sprintf | four arguments beginning with `(char*)full_pointer` and format `"/%lu%s"` |
| `cJSON_Utils.c:245` | strcat | `(char*)full_pointer`, `(char*)target_pointer` |

Use:

```bash
python - <<'PY'
import json
from pathlib import Path

data = json.loads(
    Path("outputs/reports/cjson_core_triage.json").read_text(encoding="utf-8")
)

wanted = {
    ("cJSON.c", 204),
    ("cJSON.c", 367),
    ("cJSON.c", 465),
    ("cJSON.c", 570),
    ("cJSON_Utils.c", 234),
    ("cJSON_Utils.c", 245),
}

for packet in data["packets"]:
    key = (Path(packet["file"]).name, int(packet["line"]))
    if key in wanted:
        print("\n", key)
        print(" function:", packet["function"])
        print(" call:", packet["call_name"])
        print(" status:", packet["call_parse_status"])
        print(" args:", packet["call_arguments"])
        print(" obligations:")
        for item in packet["obligations"]:
            print("  -", item)
PY
```

If a parsed argument differs only in whitespace/casting formatting, record the actual representation. If the parser merges/splits arguments incorrectly, treat it as a parser bug.

---

## 7. Check the Markdown triage report

Open:

```text
outputs/reports/cjson_core_triage.md
```

Each packet should include:

- stable candidate_id;
- file/line/function;
- call parse status;
- call expression;
- parsed arguments;
- security obligations;
- review fields, initially unknown/unreviewed;
- source context.

The header must explicitly say triage packets do not validate vulnerabilities.

---

## 8. Candidate ID stability check

Re-run the exact same `triage` command to a second output path:

```bash
python -m src.cli triage \
  --scan-report outputs/reports/cjson_core_context.json \
  --json-out /tmp/cjson_triage_second.json \
  --md-out /tmp/cjson_triage_second.md
```

Then compare IDs:

```bash
python - <<'PY'
import json
from pathlib import Path

a = json.loads(Path("outputs/reports/cjson_core_triage.json").read_text())
b = json.loads(Path("/tmp/cjson_triage_second.json").read_text())

ids_a = [p["candidate_id"] for p in a["packets"]]
ids_b = [p["candidate_id"] for p in b["packets"]]

print("same_ids:", ids_a == ids_b)
print("unique_ids:", len(ids_a) == len(set(ids_a)))
print("count:", len(ids_a))
PY
```

Expected:

```text
same_ids: True
unique_ids: True
count: 26
```

If not, investigate before using IDs in review records.

---

## 9. What Codex may fix

Minimal fixes are allowed in:

- `src/triage/callsite.py`;
- `src/triage/review.py`;
- `src/cli/main.py`;
- `tests/test_triage.py`;
- this verification document.

Do not in this round:

- modify cJSON;
- automatically label packets likely_safe / interesting / validated;
- implement CFG/data-flow/taint;
- generate PoC;
- add new dangerous APIs;
- infer attacker control without evidence.

The packet generator is a **review preparation layer**, not an automatic vulnerability classifier.

---

## 10. Completion record

After verification, update PROGRAM_STATUS with:

### Verified
- total tests;
- packet count;
- parsed/unresolved call count;
- call-name distribution;
- six spot-check results;
- stable/unique candidate ID result;
- files Codex changed, if any.

### Unverified
- actual input control;
- destination capacities;
- guard dominance;
- cross-function reachability;
- security impact;
- runtime triggerability.

### Unknown
- which of the 26 candidates are true security defects;
- whether any are reportable competition vulnerabilities.

Only after this triage-packet layer is reproducible should the next round manually complete review fields for the 3 `needs_context` and 2 `interesting` candidates and decide whether any deserves original-component runtime validation.
