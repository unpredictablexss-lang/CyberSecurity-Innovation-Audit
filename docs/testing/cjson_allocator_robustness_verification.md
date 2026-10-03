# cJSON allocator robustness verification

> Branch: `feat/openharmony-target-onboarding`  
> Target commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`  
> Status: **pending Ubuntu WSL / Codex verification**
>
> Goal: evaluate one deduplicated robustness root cause in `cJSONUtils_FindPointerFromObjectTo` using the original pinned cJSON sources and the public allocator-hook API. This is a component-level robustness experiment, not a vulnerability or exploitability claim.

## 1. Read before running

Read:

- `PROGRAM_STATUS.md`
- `docs/reviews/cjson_priority_review.md`
- this file

The source review currently treats `cJSON_Utils.c:234` and `:245` as one root-cause family: a `cJSON_malloc` result is used without an explicit NULL check in the array/object paths.

The experiment must distinguish:

- normal allocator control;
- controlled allocation-failure behavior;
- sanitizer/runtime observation;
- security impact, which remains unknown.

## 2. Sync project and confirm target

~~~bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git checkout feat/openharmony-target-onboarding
git pull --ff-only
source .venv/bin/activate
git status

cd /home/audit/openharmony-targets/third_party_cJSON
git rev-parse HEAD
git status --short
~~~

Expected target commit:

~~~text
0c2c9dff82cc85539c8362132d7a5f6bf7d1e748
~~~

Do not modify cJSON source.

## 3. Run project regression first

~~~bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
python -m unittest discover -s tests -v
~~~

The previously verified total is 23/23. This experiment adds a standalone C harness, not a new Python unit test, so the expected Python regression total remains 23 unless Codex makes justified test changes.

## 4. Build the original-component harness

Record tool version:

~~~bash
clang --version
~~~

Build:

~~~bash
TARGET=/home/audit/openharmony-targets/third_party_cJSON

clang   -fsanitize=address,undefined   -fno-omit-frame-pointer   -g -O1   -I"$TARGET"   validation/cjson/allocator_robustness.c   "$TARGET/cJSON.c"   "$TARGET/cJSON_Utils.c"   -lm   -o /tmp/cjson_allocator_robustness
~~~

Record the build exit code and any warnings/errors.

Do not copy or edit target implementation code into the harness.

## 5. Normal controls

Run both public API paths with the normal allocator:

~~~bash
/tmp/cjson_allocator_robustness array normal
echo "array_normal_exit=$?"

/tmp/cjson_allocator_robustness object normal
echo "object_normal_exit=$?"
~~~

Record:

- stdout;
- stderr;
- exit code.

Both normal controls should complete before interpreting any failure-injection result.

## 6. Controlled allocation-failure runs

The harness builds the cJSON object graph first, then installs a test allocator through the public `cJSON_InitHooks` API. The test allocator is configured so the earlier path allocation can succeed while the following allocation returns NULL.

Run separately:

~~~bash
set +e

/tmp/cjson_allocator_robustness array fail-second   > /tmp/cjson_array_fail.stdout   2> /tmp/cjson_array_fail.stderr
echo "array_fail_exit=$?"

/tmp/cjson_allocator_robustness object fail-second   > /tmp/cjson_object_fail.stdout   2> /tmp/cjson_object_fail.stderr
echo "object_fail_exit=$?"

set -e
~~~

Inspect:

~~~bash
cat /tmp/cjson_array_fail.stdout
cat /tmp/cjson_array_fail.stderr
cat /tmp/cjson_object_fail.stdout
cat /tmp/cjson_object_fail.stderr
~~~

Do not pre-assume the exact outcome. Record whether each run:

- returned normally;
- returned NULL;
- produced UBSan evidence;
- produced ASan evidence;
- terminated by signal;
- produced some other result.

## 7. Repeatability

If a failure mode produces a deterministic runtime error, repeat that same mode five times and record the exit code for each run.

Do not discard failed or inconsistent repetitions. If results vary, mark reproducibility as partial/inconclusive.

## 8. Evidence interpretation

Possible engineering outcomes:

### A. Normal controls succeed, failure mode returns safely
The suspected unchecked-allocation issue is not reproduced by this harness. Record `not_triggered` or `refuted_for_tested_condition`.

### B. Normal controls succeed, failure mode produces a sanitizer-confirmed invalid access
Record a **component-level robustness issue under controlled allocator failure**.

This may justify a state such as:

~~~text
validated_component_behavior
quality_issue_candidate
~~~

It still does **not** establish:

- attacker control in OpenHarmony;
- system-service reachability;
- privilege-boundary impact;
- a reportable security vulnerability;
- CVE/new-vulnerability status.

### C. Harness or build is invalid
Record `harness_invalid` or `environment_blocked`; do not treat it as positive or negative vulnerability evidence.

## 9. What Codex may change

Minimal fixes are allowed in:

- `validation/cjson/allocator_robustness.c`
- this verification document
- `PROGRAM_STATUS.md`

Codex must not:

- modify cJSON source;
- weaken sanitizer settings merely to obtain a clean run;
- label the result a high-severity vulnerability;
- start CFG/data-flow/taint work;
- start a new target before this result is recorded.

## 10. Completion record

Update `PROGRAM_STATUS.md` with separate Verified / Unverified / Unknown facts.

Report:

1. Python regression result;
2. exact target commit and clean/dirty status;
3. exact compile command and build exit code;
4. normal array stdout/exit;
5. normal object stdout/exit;
6. failure array outcome and sanitizer summary, if any;
7. failure object outcome and sanitizer summary, if any;
8. repeatability results;
9. whether both source locations appear to share one root cause;
10. whether the result is best described as component robustness, quality issue, inconclusive, or blocked;
11. security impact that remains unknown.

Do not proceed to system-level vulnerability claims from this host-side experiment alone.
