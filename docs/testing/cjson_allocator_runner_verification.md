# cJSON Controlled Allocator Validation Runner Verification

> Branch: `feat/openharmony-target-onboarding`
> Status: code written; **pending Ubuntu 22.04 WSL2 verification**.
> Scope: authorized competition research on the pinned OpenHarmony cJSON component.

## Purpose

This gate turns the existing allocator robustness harness into a reproducible runtime evidence record. It is intentionally narrow:

- compile the original pinned `cJSON.c` and `cJSON_Utils.c` together with `validation/cjson/allocator_robustness.c`;
- enable ASan and UBSan;
- execute normal controls first;
- execute controlled `fail-second` allocator cases repeatedly;
- save build/run commands, exit codes, stdout/stderr and sanitizer detection;
- classify the result as component-level robustness evidence only.

A sanitizer-triggered failure does **not** establish OpenHarmony system reachability, attacker control, security impact, or a reportable vulnerability.

## 1. Sync

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
git status
```

Do not continue with unexplained local modifications.

## 2. Verify pinned target

```bash
cd /home/audit/openharmony-targets/third_party_cJSON
git rev-parse HEAD
git status --short
```

Expected source commit:

```text
0c2c9dff82cc85539c8362132d7a5f6bf7d1e748
```

Do not modify the target source.

## 3. Run full tests

Five runtime-validation tests were added after the previously verified 23 tests.

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
source .venv/bin/activate
python -m unittest discover -s tests -v
```

Expected if the implementation is correct:

```text
Ran 28 tests
OK
```

This expected number is not yet a verified fact. Record any failure exactly; do not edit expectations merely to reach 28.

## 4. Run controlled validation

```bash
python -m src.cli validate-cjson-allocator \
  /home/audit/openharmony-targets/third_party_cJSON \
  --harness validation/cjson/allocator_robustness.c \
  --binary outputs/bin/cjson_allocator_robustness \
  --repeat 3 \
  --json-out outputs/reports/cjson_allocator_validation.json \
  --md-out outputs/reports/cjson_allocator_validation.md
```

The runner compiles with:

```text
-std=c99
-g
-O1
-fno-omit-frame-pointer
-fsanitize=address,undefined
```

and links the original pinned `cJSON.c` and `cJSON_Utils.c`.

## 5. Acceptance logic

The runner distinguishes:

- `build_failed`: sanitizer harness could not build;
- `harness_invalid`: either normal control is not clean;
- `controlled_failure_sanitizer`: a fail-second run produces sanitizer evidence after clean controls;
- `controlled_failure_nonzero`: controlled failure exits nonzero without parsed sanitizer evidence;
- `failure_not_triggered`: controlled failure runs remain clean;
- `inconclusive`: timeout/mixed evidence.

Do not rename `controlled_failure_sanitizer` to “validated vulnerability”.

## 6. Inspect JSON

```bash
python - <<'PY'
import json
from collections import Counter
from pathlib import Path

data = json.loads(
    Path("outputs/reports/cjson_allocator_validation.json").read_text(encoding="utf-8")
)

print("build:", data["build"]["outcome"])
print("overall:", data["outcome"])
print("run_count:", len(data["runs"]))
print("outcomes:", dict(Counter(r["outcome"] for r in data["runs"])))
print("sanitizer_runs:", sum(bool(r["sanitizer_detected"]) for r in data["runs"]))

for r in data["runs"]:
    print(
        r["case"],
        r["allocator_mode"],
        r["exit_code"],
        r["outcome"],
        r["sanitizer_detected"],
    )
PY
```

With `--repeat 3`, a successful build should schedule 8 runtime cases total: 2 normal controls plus 3 array/object failure pairs.

## 7. Performance sanity record

```bash
/usr/bin/time -v python -m src.cli validate-cjson-allocator \
  /home/audit/openharmony-targets/third_party_cJSON \
  --harness validation/cjson/allocator_robustness.c \
  --binary /tmp/cjson_allocator_robustness \
  --repeat 3 \
  --json-out /tmp/cjson_allocator_validation.json \
  --md-out /tmp/cjson_allocator_validation.md
```

Record wall time, maximum RSS and exit status. This is only a small-target sanity measurement.

## 8. Interpretation gate

If normal controls fail, stop and mark `harness_invalid`.

If the controlled allocation failure produces a sanitizer-confirmed invalid access, the supported statement is:

> The original pinned cJSON component exhibits a reproducible invalid-access robustness failure under the tested allocator-failure condition.

Still unknown until separately established:

- whether an OpenHarmony application/service can reach this path;
- whether an attacker can influence the required memory-pressure/failure condition;
- whether the behavior crosses a security boundary;
- affected OpenHarmony versions;
- CVE status;
- competition-reportable vulnerability status.

If the runtime gate only demonstrates an allocation-failure crash with no meaningful security impact, keep it as a robustness/quality result and move discovery effort to a higher-value candidate or the first-party `c_utils` target.
