# Clang Static Analyzer Baseline Verification

> Branch: `feat/openharmony-target-onboarding`  
> Status: **pending Ubuntu WSL / Codex verification**  
> Purpose: establish one mature static-analysis baseline on the exact same pinned cJSON core scope used by the MVP scanner.

## Why this is the next gate

The project already has:

- reproducible core scope: `cJSON.c` + `cJSON_Utils.c`;
- 2 files / 4,681 lines / 26 text candidates;
- 14/14 scanner + context tests;
- 26/26 heuristic function contexts on the pinned target.

The next question is not “can we add more rules?” but:

> What does a mature static analyzer report on the same fixed files, and how does that evidence compare with our candidate generator?

This baseline must remain separate from our Findings. A Clang warning is **not** automatically a vulnerability, and zero warnings is **not** proof of safety.

---

## 1. Sync the branch

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
git status
```

Do not continue if there are unexplained local modifications.

---

## 2. Verify Clang is available

```bash
clang --version
command -v clang
```

Record:

- executable path;
- first version line.

The new baseline runner invokes `clang --analyze`; it does not require `scan-build` or clang-tidy for this round.

---

## 3. Run the full project test suite

Four new baseline-runner tests were added after the previously verified 14 tests.

Run:

```bash
python -m unittest discover -s tests -v
```

Expected if the new implementation is correct:

```text
Ran 18 tests
OK
```

Do not change expected values just to get 18/18. If any test fails, record the exact test name and traceback, make only the minimum justified fix, and rerun the full suite.

---

## 4. Confirm the pinned cJSON checkout is unchanged

```bash
cd /home/audit/openharmony-targets/third_party_cJSON
git rev-parse HEAD
git status --short
```

Expected commit:

```text
0c2c9dff82cc85539c8362132d7a5f6bf7d1e748
```

The target source must not be modified to make the analyzer happy.

---

## 5. Run Clang Static Analyzer on the same two core files

Return to the audit project:

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
source .venv/bin/activate
```

Run:

```bash
python -m src.cli baseline-clang \
  /home/audit/openharmony-targets/third_party_cJSON \
  --file cJSON.c \
  --file cJSON_Utils.c \
  --json-out outputs/reports/cjson_clang_baseline.json \
  --md-out outputs/reports/cjson_clang_baseline.md
```

The command should print:

- Clang version;
- files = 2;
- parsed diagnostics count;
- failed files count;
- elapsed seconds;
- report paths.

Do not assume a particular warning count in advance.

### If Clang fails to parse/build a file

Do not edit cJSON.

First inspect the recorded command and stderr in the JSON report. If a real compiler flag is required, rerun with explicit repeatable arguments, for example:

```bash
--clang-arg=-std=c99
```

Arguments beginning with `-` should be passed in `--clang-arg=value` form.

Any extra flag used in the accepted run must be recorded in PROGRAM_STATUS.

---

## 6. Inspect the baseline JSON

Run:

```bash
python - <<'PY'
import json
from collections import Counter
from pathlib import Path

p = Path("outputs/reports/cjson_clang_baseline.json")
data = json.loads(p.read_text(encoding="utf-8"))

print("tool:", data["tool"])
print("clang_version:", data["clang_version"])
print("files:", data["files"])
print("file_count:", data["file_count"])
print("diagnostic_count:", data["diagnostic_count"])
print("failed_files:", data["failed_files"])
print("elapsed_seconds:", data["elapsed_seconds"])
print("levels:", dict(Counter(d["level"] for d in data["diagnostics"])))
print("checkers:", dict(Counter((d["checker"] or "<none>") for d in data["diagnostics"])))

for d in data["diagnostics"]:
    print(
        d["file"],
        d["line"],
        d["column"],
        d["level"],
        d["checker"],
        d["message"],
    )
PY
```

Record the actual output. Do not hide warnings, notes, errors, or failed files.

---

## 7. Compare Clang locations with our 26 text candidates

This is a descriptive comparison only. Exact-line overlap is useful evidence but is **not** a winner/accuracy score.

Run:

```bash
python - <<'PY'
import json
from pathlib import Path

candidate_data = json.loads(
    Path("outputs/reports/cjson_core_context.json").read_text(encoding="utf-8")
)
baseline_data = json.loads(
    Path("outputs/reports/cjson_clang_baseline.json").read_text(encoding="utf-8")
)

candidate_locations = {
    (Path(f["file_path"]).name, int(f["line"]))
    for f in candidate_data["findings"]
}

baseline_locations = {
    (Path(d["file"]).name, int(d["line"]))
    for d in baseline_data["diagnostics"]
    if d["level"] in {"warning", "error"}
}

print("candidate_locations:", len(candidate_locations))
print("baseline_warning_error_locations:", len(baseline_locations))
print("exact_location_overlap:", len(candidate_locations & baseline_locations))

print("\nOverlap:")
for item in sorted(candidate_locations & baseline_locations):
    print(item)

print("\nClang-only warning/error locations:")
for item in sorted(baseline_locations - candidate_locations):
    print(item)

print("\nText-candidate-only locations:")
for item in sorted(candidate_locations - baseline_locations):
    print(item)
PY
```

Interpret carefully:

- Clang may warn at a caller/condition rather than the dangerous-call line.
- Our text candidate may be safe after contextual review.
- Different location does not automatically mean a false positive or false negative.

---

## 8. Inspect Markdown

Open:

```text
outputs/reports/cjson_clang_baseline.md
```

Confirm it includes:

- target;
- Clang version;
- exact command per file;
- exit code;
- diagnostic count;
- elapsed time;
- parsed diagnostics;
- disclaimer that baseline warnings are not validated vulnerabilities.

---

## 9. Small performance sanity record

The runner already records per-file and total elapsed seconds.

Additionally run once under `/usr/bin/time -v`:

```bash
/usr/bin/time -v python -m src.cli baseline-clang \
  /home/audit/openharmony-targets/third_party_cJSON \
  --file cJSON.c \
  --file cJSON_Utils.c \
  --json-out /tmp/cjson_clang_perf.json \
  --md-out /tmp/cjson_clang_perf.md
```

Record:

- elapsed wall clock;
- maximum resident set size;
- exit status.

This remains a small-target sanity check, not the final competition benchmark.

---

## 10. What Codex may fix in this round

Minimal fixes are allowed in:

- `src/baseline/clang_analyzer.py`;
- `src/cli/main.py`;
- `tests/test_clang_baseline.py`;
- baseline verification docs.

Codex should not:

- alter cJSON source;
- add new dangerous API rules;
- install or integrate CodeQL/Joern;
- implement CFG/data-flow/taint;
- generate exploit PoCs;
- promote a Clang warning or text candidate to validated vulnerability.

If Clang cannot analyze a file because of a real compile configuration issue, preserve that as a failed/blocked baseline with stderr evidence instead of fabricating success.

---

## 11. Completion record

After testing, update PROGRAM_STATUS with separate sections:

### Verified
- total tests;
- actual Clang version/path;
- actual baseline command;
- per-file exit codes;
- diagnostics count and level/checker distribution;
- exact-location overlap counts;
- elapsed/RSS sanity values.

### Unverified
- any tool or path not actually run;
- runtime exploitability;
- ASan/UBSan validation;
- full OpenHarmony build context.

### Unknown
- security impact of remaining candidates;
- whether a Clang-only diagnostic is a real vulnerability;
- whether a text-candidate-only location is safe without manual/semantic review.

Only after this baseline is reproducible should the next round focus on a small number of candidates for boundary/input reasoning and original-component runtime validation.
