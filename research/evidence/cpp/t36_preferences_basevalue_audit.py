#!/usr/bin/env python3
"""Verify the independent T36 replay and original A0 queue bindings."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
RAW = HERE / "t36_preferences_basevalue_cli_20261024.json"
REPORT = HERE / "t36_preferences_basevalue_audit_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SOURCE = "test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesbasevalue_fuzzer/BUILD.gn"
IDS = [f"CR-{i:04d}" for i in range(41, 66)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def bind(path: str) -> dict[str, str]:
    content = git("show", f"{COMMIT}:{path}")
    return {"path": path, "blob": git("hash-object", "--stdin", data=content).decode().strip(),
            "sha256": hashlib.sha256(content).hexdigest()}


def main() -> None:
    with QUEUE_CSV.open(encoding="utf-8-sig", newline="") as f:
        csv_rows = list(csv.DictReader(f))
    queue = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    cmap, jmap = ({r["queue_id"]: r for r in rows} for rows in (csv_rows, queue))
    assert len(csv_rows) == len(queue) == len(cmap) == len(jmap) == 345
    assert set(cmap) == set(jmap)
    for qid in cmap:
        for k in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(cmap[qid][k]) == str(jmap[qid][k]), (qid, k)
    assert git("rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    source, build = bind(SOURCE), bind(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["repository"] == REPO and raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["status"] == "completed" and raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 25)
    diags = {int(d["line"]): d for d in run["diagnostics"] if d["file"] == SOURCE}
    assert len(diags) == 25
    items = []
    for qid in IDS:
        row = cmap[qid]
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SOURCE)
        assert row["blob"] == source["blob"] and row["source_sha256"].lower() == source["sha256"]
        assert row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence"
        line = int(row["line"])
        d = diags[line]
        items.append({"queue_id": qid, "line": line, "source": {**source, "repository": REPO, "commit": COMMIT, "tree": TREE},
                      "original_status": row["original_status"], "queue_status": row["queue_status"],
                      "finding": {"detector": run["tool"], "version": run["tool_version"], "rule_id": d["rule_id"], "symbol": d["symbol"], "parse": "complete", "coverage": "syntax_candidate"},
                      "disposition": "PARTIAL", "queue_preserved": True})
    assert {int(cmap[q]["line"]) for q in IDS} == set(diags)
    report = {"schema_version": "t36-preferences-basevalue-audit-v1", "task": "T36", "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": source},
              "build": {"file": build, "target": "ohos_fuzztest(DBPreferencesBaseValueFuzzTest)", "group": "group(fuzztest) [testonly = true]", "entry": "LLVMFuzzerTestOneInput"},
              "cli": {"tool": run["tool"], "version": run["tool_version"], "status": run["status"], "parse": raw["source_parsing"]["parsing_status"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"], "findings": run["diagnostic_count"], "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
              "a0": {"total_rows": 345, "audited_ids": IDS, "source_statuses_unchanged": True}, "items": items, "overall": "PARTIAL", "queue_states_changed": False,
              "limitations": ["GN places this target under ohos_fuzztest and a testonly fuzztest group; this establishes harness classification, not production inclusion/exclusion in a specific product image.", "The fuzz entry invokes Preferences APIs but does not establish production call paths, attacker reachability, or an actual unordered concurrent access to the same shared_ptr.", "No product manifest/build target, thread interleaving, lock/atomic protocol, or CIA impact evidence is bound."]}
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS T36: 25 source-bound rows; 25 CLI syntax candidates; A0 rows={len(csv_rows)}; states preserved")


if __name__ == "__main__":
    main()
