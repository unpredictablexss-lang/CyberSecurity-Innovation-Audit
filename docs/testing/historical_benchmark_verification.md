# Historical benchmark verification gate

> Branch: `feat/historical-vuln-benchmark`  
> Status: PR #4 implementation is no longer “pending”: historical samples, root-cause hit matrix, and benchmark summary report are implemented.  
> Current gate: independently review the code and saved-evidence boundaries, synchronize closeout documentation, and verify CI against the **final** PR head before ready/merge. No automatic merge.

---

## 1. Sync the branch

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
git fetch origin
git checkout feat/historical-vuln-benchmark
git pull --ff-only
source .venv/bin/activate
python -m pip install -r requirements.txt
git status --short
```

Do not continue if there are unexplained local changes.

---

## 2. Run the full project tests

```bash
python -m unittest discover -s tests -v
```

The earlier branch checkpoint recorded 105 passing tests. The **pre-closeout code head** `dd908f2137ebb6a60fb8e876b04958677738f252` passed GitHub Actions CI Run #58 on Ubuntu 22.04 / Python 3.10:

```text
Ran 149 tests in 2.134s
OK
```

This does **not** pre-approve subsequent documentation commits. Check CI again against the final head. Record actual totals and any failure; never change expectations merely to match a number.

---

## 3. Verify the current sample set

The current benchmark set contains four manifests under `benchmarks/historical/`:

```text
c_utils_singleton_uaf.json
kernel_liteos_a_getgroups_oob.json
communication_dsoftbus_null_deref.json
arkcompiler_ets_runtime_jsarray_sort_oob.json
```

Expected root-cause groups:

```text
lifetime_uaf
concurrency_race
null_deref
oob_write
```

The benchmark remains positive-only and small; it must not be used to calculate formal Precision / Recall.

---

## 4. Run historical replay per sample when local target repos exist

Example for the c_utils sample:

```bash
python -m src.cli benchmark-historical \
  --sample benchmarks/historical/c_utils_singleton_uaf.json \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --json-out outputs/reports/c_utils_singleton_uaf_benchmark.json \
  --md-out outputs/reports/c_utils_singleton_uaf_benchmark.md
```

Acceptance facts must come from Git history and generated JSON, not hard-coded expectations:

- vulnerable and fixed commits exist locally;
- fixed commit is directly based on the pinned vulnerable commit, when the sample declares that relationship;
- affected files are in the changed-file set;
- affected symbols are present in materialized vulnerable/fixed files;
- `runtime_validation` / `runtime_replay_status` remains `not_run` unless a later dedicated validation branch changes it.

Generated reports under `outputs/reports/` remain local and should not be committed unless the team intentionally adds a fixtures directory.

---

## 5. Verify root-cause hit matrix behavior

The root-cause matrix is intentionally weaker than a vulnerability verdict. It should only emit:

```text
possible_hit
miss
unknown
not_applicable
```

Interpretation:

- `possible_hit`: a tool touched the affected file / symbol region;
- `miss`: the tool ran but did not touch that region;
- `unknown`: missing/failed execution, incomplete scope or unresolved/partial AST coverage;
- `not_applicable`: the tool does not apply to this analysis unit.

Do not convert these states into TP / FP / FN. Do not call `possible_hit` a confirmed vulnerability.

---

## 6. Verify benchmark-report CLI

The summary CLI exists and should remain available:

```bash
python -m src.cli benchmark-report \
  --samples-dir benchmarks/historical/ \
  --json-out outputs/reports/historical_benchmark_summary.json \
  --md-out outputs/reports/historical_benchmark_summary.md
```

The generated Markdown title should be:

```text
Historical Benchmark Summary Report
```

It must not be titled or interpreted as a vulnerability report, and `validated_vulnerability` must remain `0` in this branch.

---

## 7. Verify external-tool normalization path

For external scanner outputs, the safe path is:

```bash
python -m src.cli normalize-tool-output \
  --provider semgrep \
  --input path/to/semgrep.json \
  --target-id <target-id> \
  --commit <pinned-commit> \
  --scope-files <n> \
  --scope-loc <n> \
  --elapsed-seconds <seconds> \
  --json-out outputs/reports/semgrep.normalized.json \
  --md-out outputs/reports/semgrep.normalized.md
```

Then compare normalized outputs with:

```bash
python -m src.cli compare-tools \
  --report outputs/reports/semgrep.normalized.json \
  --report outputs/reports/cppcheck.normalized.json \
  --json-out outputs/reports/tool_comparison.json \
  --md-out outputs/reports/tool_comparison.md
```

Adapters preserve diagnostics as evidence. They do not execute scanners and do not decide exploitability.

---

## 8. Final repository checks

```bash
git diff --check
git status --short
```

For PR #4 closure, also check the PR description and `PROGRAM_STATUS.md` agree on:

- 7 historical samples;
- root-cause matrix complete;
- benchmark-report CLI present;
- no Precision / Recall from 4 positive samples;
- `validated_vulnerability = 0`;
- PR remains draft until the user explicitly decides otherwise.

---

## 9. What this gate proves

If this verification passes, the project has a reproducible historical benchmark path:

```text
published fix pair
  -> pinned vulnerable/fixed commits
  -> changed-file verification
  -> affected source materialization
  -> candidate / AST replay
  -> normalized tool evidence when available
  -> root-cause hit matrix
  -> benchmark summary report
```

This is still benchmark evidence only. Do not report any historical sample as a newly discovered vulnerability.

## 10. Earlier closure checkpoint (2026-10-08)

This is a historical checkpoint predating the later 64-cell experiments and 149-test head. Local regression at that checkpoint: 142 tests passed. The historical 105-test CI note above does
not verify the current head. Keep current remote CI and PR-description checks
pending until the exact pushed head can be inspected.

Replay the own static baselines without checking out target code:

```bash
python -m scripts.replay_static_baselines --target-root /path/to/component-repos
python -m src.cli benchmark-report \
  --results outputs/reports/static_baselines/inputs.json \
  --json-out outputs/reports/static_baselines/rebuilt.json \
  --md-out outputs/reports/static_baselines/rebuilt.md
```

Component directories use repository basenames from the sample manifests.
The saved normalized artifacts can be reloaded by benchmark-report. Inspect
failures.json as well as summary.json: failed historical materialization
leaves cells unknown, and successful arkcompiler replay alone does not finish
the four-sample experiment gate. On the present machine, three target repos
lack the pinned vulnerable commit, so the fresh summary has 4 miss cells and
60 unknown cells. No external-tool run is fabricated from older prose.

Optional repeated `--fallback-target-root` arguments try other existing local
component directories, without fetching. If all attempts fail, each directory
and reason are retained in failures.json. Missing source blobs count as a
materialization failure even when the commit object itself is present.

Tool Capability Matrix and compare-tools share target/commit/files/LOC and
duplicate-tool checks. Matrix implementation is complete; the experiment-filled
cross-tool capability table remains pending. Local Git reads disable origin
promisor lazy fetching, disallow protocol transport and use a timeout so absent partial-clone objects do not
silently turn a local experiment into an unbounded network operation.

## 11. PR #4 first-stage closeout review (2026-10-09)

Scope of this PR: four pinned historical fix-pair manifests, scanner evidence normalization, stored-run provenance, separate vulnerable/fixed root-cause matrix, and benchmark reports. This is a **historical static benchmark/evidence engineering baseline**, not complete scanner coverage or new vulnerability discovery.

- Pre-closeout code head `dd908f2` passed remote CI **149/149** (Run #58); verify a fresh successful CI run for any new documentation head.
- The scoped experiment inventory contains 64 revision/tool cells: `possible_hit=5`, `miss=29`, `unknown=20`, `not_applicable=10`. These describe region/evidence states, **not** TP/FP/FN or vulnerabilities.
- Joern adapter and saved-query normalization exist. The dsoftbus nothrow query differentiated vulnerable/fixed revisions in the local experiment; query evidence is syntactic and does not prove control-flow guard dominance.
- CodeQL c_utils header-only units were not applicable in this no-build profile; six other units reported missing includes and remain unknown. Kernel/Joern partial parsing and Clang missing original build dependencies remain coverage limitations.
- Generated native logs and normalized experimental artifacts were stored locally under ignored output paths. The repository documents commands and checks, but their retained local bytes are **not** independently re-executed by CI. Reviewers should inspect a pinned input manifest, native logs, report hashes and regenerated summary before treating the experiment as independently reproduced.
- Before ready/merge: (1) synchronize PR description and PROGRAM_STATUS; (2) obtain independent human code/security-boundary review for changed adapters, source mapping, report loading, scripts and rule licensing; (3) ensure final head CI is green; (4) record limitations as follow-up work rather than incorrectly marking incomplete analyses as misses.
- Current limits stay explicit: `validated_vulnerability=0`, runtime replay `not_run`, no formal Precision/Recall, no PoC or exploitability claim.

