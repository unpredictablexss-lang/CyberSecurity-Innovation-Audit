#!/usr/bin/env python3
"""Build source-bound D35 replay evidence for Preferences fuzz candidates."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = HERE / "d35_preferences_fuzz_20261024.json"
OUTPUT = HERE / "d35_preferences_source_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
REPO = "openharmony/distributeddatamgr_preferences"
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
SOURCE = "test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferences_fuzzer/BUILD.gn"
IDS = [f"CR-{n:04d}" for n in range(22, 41)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def bind(path: str) -> dict[str, str]:
    blob = git("show", f"{COMMIT}:{path}")
    return {
        "path": path,
        "blob": git("hash-object", "--stdin", data=blob).decode().strip(),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def main() -> None:
    csv_rows = list(csv.DictReader(QUEUE_CSV.open(encoding="utf-8-sig", newline="")))
    queue = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    cmap = {row["queue_id"]: row for row in csv_rows}
    jmap = {row["queue_id"]: row for row in queue}
    assert len(csv_rows) == len(queue) == len(cmap) == len(jmap) == 345
    assert set(cmap) == set(jmap)
    assert git("rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    source_binding, build_binding = bind(SOURCE), bind(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == REPO
    assert raw["status"] == "completed"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19
    )
    diagnostics = [d for d in run["diagnostics"] if d["file"] == SOURCE]
    by_line = {d["line"]: d for d in diagnostics}
    assert len(diagnostics) == 19
    selected = []
    for qid in IDS:
        row, json_row = cmap[qid], jmap[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(json_row[key]), (qid, key)
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SOURCE), qid
        assert row["blob"] == source_binding["blob"]
        assert row["source_sha256"].lower() == source_binding["sha256"]
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        diag = by_line.get(int(row["line"]))
        assert diag is not None, (qid, row["line"])
        fi = diag.get("finding_identity", {})
        selected.append({
            "queue_id": qid,
            "candidate_id": row["candidate_id"],
            "source": {**source_binding, "repository": REPO, "commit": COMMIT, "tree": TREE, "line": int(row["line"])},
            "original_a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
            "replay": {
                "detector": run["tool"], "version": run["tool_version"], "parse_status": "complete",
                "coverage": "syntax_candidate", "finding_line": diag["line"], "symbol": diag["symbol"],
                "rule_id": diag["rule_id"], "diagnostic_id": diag["diagnostic_id"],
                "stable_finding_identity": fi.get("stable", {}).get("id"),
                "stable_identity_status": fi.get("stable", {}).get("status"),
                "occurrence_finding_identity": fi.get("occurrence", {}).get("id"),
                "occurrence_identity_status": fi.get("occurrence", {}).get("status"),
            },
            "disposition": "PARTIAL",
            "reason": "The source is part of an ohos_fuzztest test harness; syntax candidates are not production vulnerability evidence. Runtime race, production reachability, product build and impact are unverified.",
            "queue_preserved": True,
        })
    assert {int(cmap[q]["line"]) for q in IDS} == set(by_line)
    report = {
        "schema_version": "d35-preferences-fuzz-source-replay-v1",
        "task": "D35",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": source_binding},
        "build_target": {
            "file": build_binding, "target": "ohos_fuzztest(DBPreferencesFuzzTest)",
            "test_group": "group(fuzztest) [testonly = true]",
            "harness_entry": "LLVMFuzzerTestOneInput", "production_evidence": False,
        },
        "queue": {"csv": str(QUEUE_CSV), "json": str(QUEUE), "total_rows": 345, "audited_ids": IDS,
                  "a0_status_unchanged": True},
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"],
                "status": run["status"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "parse": raw["source_parsing"]["parsing_status"], "findings": run["diagnostic_count"],
                "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
        "items": selected,
        "overall_disposition": "PARTIAL",
        "detector_change": "none; all 19 source locations replay and the audited source is test-only harness code",
        "queue_states_changed": False,
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.name}: {len(selected)} queue rows; {len(diagnostics)} source candidates")


if __name__ == "__main__":
    main()
