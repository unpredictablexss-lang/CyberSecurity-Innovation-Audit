# Historical vulnerability benchmark verification

> Branch: feat/historical-vuln-benchmark
> Status: implementation prepared on GitHub; local WSL verification is pending.
> First seed: OpenHarmony commonlibrary_c_utils singleton.h published UAF fix.

## 1. Sync the new branch

Run in Ubuntu 22.04 WSL2:

    cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
    git checkout main
    git pull --ff-only
    git checkout feat/historical-vuln-benchmark
    git pull --ff-only
    source .venv/bin/activate
    python -m pip install -r requirements.txt
    git status

Do not continue if there are unexplained local changes.

## 2. Run the full project tests

    python -m unittest discover -s tests -v

The previous main branch recorded 43 local tests. This branch adds five historical
benchmark tests, so the expected total is 48 if no other local-only tests have
changed. Do not edit expected values merely to reach 48; record the actual total
and any failing test names.

## 3. Make sure the historical commits are available locally

The first manifest pins:

- vulnerable: bdfafdaafddb01ab7ae13354ce2ada9555d7935c
- fixed: 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7
- affected file: base/include/singleton.h

Check:

    git -C /home/audit/openharmony-targets/commonlibrary_c_utils cat-file -e bdfafdaafddb01ab7ae13354ce2ada9555d7935c^{commit}
    git -C /home/audit/openharmony-targets/commonlibrary_c_utils cat-file -e 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7^{commit}

If the shallow checkout does not contain them, fetch the published history without
modifying source files:

    git -C /home/audit/openharmony-targets/commonlibrary_c_utils fetch origin 9a3f281120307ec7dcce17fae882dcc4e6a6f4d7
    git -C /home/audit/openharmony-targets/commonlibrary_c_utils fetch origin bdfafdaafddb01ab7ae13354ce2ada9555d7935c

If direct SHA fetch is refused, use a normal history fetch or unshallow the clone,
then re-run cat-file.

## 4. Run the first historical replay

    cd ~/openharmony-audit/CyberSecurity-Innovation-Audit
    source .venv/bin/activate

    python -m src.cli benchmark-historical \
      --sample benchmarks/historical/c_utils_singleton_uaf.json \
      --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
      --json-out outputs/reports/c_utils_singleton_uaf_benchmark.json \
      --md-out outputs/reports/c_utils_singleton_uaf_benchmark.md

Acceptance facts that should come from Git history, not hard-coded expectations:

- both commits exist;
- fixed commit is directly based on the pinned vulnerable commit;
- base/include/singleton.h is in the changed-file set;
- GetInstance and DestroyInstance are present in the affected source;
- the report keeps runtime_validation = not_run.

The current dangerous-API scanner is expected to have no meaningful overlap with
this concurrency/lifetime UAF. Record the actual vulnerable/fixed candidate counts
instead of changing the scanner to make the historical case pass.

## 5. Inspect the JSON report

    python - <<'PY'
    import json
    from pathlib import Path

    p = Path("outputs/reports/c_utils_singleton_uaf_benchmark.json")
    d = json.loads(p.read_text(encoding="utf-8"))

    print("sample:", d["sample"]["sample_id"])
    print("vulnerable_exists:", d["vulnerable_commit_exists"])
    print("fixed_exists:", d["fixed_commit_exists"])
    print("direct_parent_match:", d["direct_parent_match"])
    print("changed_files:", d["changed_files"])
    print("affected_files_changed:", d["affected_files_changed"])
    print("vulnerable_candidates:", d["vulnerable"]["candidate_count"])
    print("fixed_candidates:", d["fixed"]["candidate_count"])
    print("vulnerable_overlap:", d["text_candidate_overlap_in_vulnerable"])
    print("fixed_overlap:", d["text_candidate_overlap_in_fixed"])
    print("vulnerable_symbols:", d["vulnerable"]["affected_symbols_present"])
    print("fixed_symbols:", d["fixed"]["affected_symbols_present"])
    print("runtime_validation:", d["runtime_validation"])
    PY

## 6. Inspect the Markdown boundary language

Open:

    outputs/reports/c_utils_singleton_uaf_benchmark.md

Confirm it explicitly says:

- this is published historical ground truth;
- the replay is not a new vulnerability discovery;
- static overlap is not exploitability proof;
- Precision is not computed from one positive-only sample.

## 7. Final repository checks

    git diff --check
    git status

Generated reports under outputs/reports remain local and should not be committed.

## 8. What this gate proves

If this verification passes, the project has its first executable historical
ground-truth benchmark path:

    published fix pair
      -> pinned vulnerable/fixed commits
      -> changed-file verification
      -> vulnerable/fixed source materialization
      -> current scanner replay
      -> AST sanity evidence
      -> JSON/Markdown benchmark report

For singleton.h specifically, a miss is useful evidence: the current text scanner
does not cover concurrency/lifetime UAF. The next benchmark step is to reproduce
this historical case with TSan or another concurrency-aware method and then grow
the manifest set to 3-5 first-party root causes.

Do not report this historical case as a newly discovered vulnerability.
