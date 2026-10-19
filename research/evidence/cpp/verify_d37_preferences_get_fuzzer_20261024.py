from __future__ import annotations

import collections
import csv
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
RAW = HERE / "d37_preferences_get_fuzzer_20261024.json"
REPORT = HERE / "d37_preferences_get_fuzzer_replay_20261024.json"


def main() -> None:
    subprocess.check_call([sys.executable, str(HERE / "d37_preferences_get_fuzzer_replay_20261024.py")])
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    jrows = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    byid = {r["queue_id"]: r for r in rows}
    assert len(rows) == len(jrows) == len(byid) == 345
    assert {r["queue_id"] for r in jrows} == set(byid)
    counts = {k: dict(collections.Counter(r[k] for r in rows)) for k in ("original_status", "queue_status")}
    assert counts["original_status"] == {"not_testable": 336, "not_reproduced": 9}
    assert counts["queue_status"] == {"paused_pending_evidence": 331, "queued_not_reproduced": 9, "queued_first_batch": 5}
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    replay = json.loads(REPORT.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 25)
    assert replay["task"] == "D37" and replay["overall_disposition"] == "PARTIAL" and replay["queue_states_changed"] is False
    assert [x["queue_id"] for x in replay["items"]] == [f"CR-{i:04d}" for i in range(66, 91)]
    source = replay["source"]["file"]
    build = replay["build_target"]["file"]
    assert source["blob"] == "7a5c8a263fa4142579a3f4c6161c7d28b3350f50"
    assert source["sha256"] == "3e72c80d962f8dc9df6573328198c37072f4dddcd88dbc004ed2f72128d176b9"
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == source["path"]}
    assert len(diags) == 25
    for item in replay["items"]:
        q = byid[item["queue_id"]]
        assert q["path"] == source["path"] and int(q["line"]) == item["source"]["line"]
        assert q["blob"] == item["source"]["blob"] and q["source_sha256"].lower() == item["source"]["sha256"]
        assert (q["original_status"], q["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = diags[item["replay"]["finding_line"]]
        assert diag["diagnostic_id"] == item["replay"]["diagnostic_id"]
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"]
    assert replay["build_target"]["target"] == "ohos_fuzztest(DBPreferencesGetFuzzTest)"
    assert replay["build_target"]["production_evidence"] is False
    assert build["blob"] and build["sha256"]
    assert len(replay["structured_vibe_prompt"]["steps"]) == 4
    print("PASS D37: exact A0 source binding; complete current CLI parse; 25/25 line candidates")
    print("PASS GN: DBPreferencesGetFuzzTest is under testonly fuzztest group")
    print("PASS A0: all 345 row counts preserved; CR-0066–CR-0090 remain not_testable / paused_pending_evidence")
    print("PASS disposition: PARTIAL; no product-root miss established; no detector change")


if __name__ == "__main__":
    main()
