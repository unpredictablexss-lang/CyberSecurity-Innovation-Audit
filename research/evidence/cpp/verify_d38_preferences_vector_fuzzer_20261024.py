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
RAW = HERE / "d38_preferences_vector_fuzzer_20261024.json"
REPLAY = HERE / "d38_preferences_vector_fuzzer_replay_20261024.json"


def main() -> None:
    subprocess.check_call([sys.executable, str(HERE / "d38_preferences_vector_fuzzer_replay_20261024.py")])
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    jrows = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    byid = {r["queue_id"]: r for r in rows}
    assert len(rows) == len(jrows) == len(byid) == 345
    assert {r["queue_id"] for r in jrows} == set(byid)
    counts = {k: dict(collections.Counter(r[k] for r in rows)) for k in ("original_status", "queue_status")}
    assert counts["original_status"] == {"not_testable": 336, "not_reproduced": 9}
    assert counts["queue_status"] == {"paused_pending_evidence": 331, "queued_not_reproduced": 9, "queued_first_batch": 5}
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    replay = json.loads(REPLAY.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 6)
    assert replay["task"] == "D38" and replay["overall_disposition"] == "PARTIAL" and replay["queue_states_changed"] is False
    assert [x["queue_id"] for x in replay["items"]] == [f"CR-{i:04d}" for i in range(91, 97)]
    source = replay["source"]["file"]
    build = replay["build_target"]["file"]
    assert source["blob"] == "3de64e85dcba575ed35b6bc7f3e5b2fbcf223e2c"
    assert source["sha256"] == "4b4f6e8e9f7f8e4d06887b93f67352ba9c5e9cf9b697c7814cc713573c0b7dfe"
    assert build["blob"] == "56471b31f18f3184a79badfacf35a6fa8ab03552"
    assert build["sha256"] == "54a176a31ab5e5d768d1f4408ec86e1b85c6a47880088936c23a528ba5d59770"
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == source["path"]}
    assert len(diags) == 6
    for item in replay["items"]:
        q = byid[item["queue_id"]]
        assert q["path"] == source["path"] and int(q["line"]) == item["source"]["line"]
        assert q["blob"] == item["source"]["blob"] and q["source_sha256"].lower() == item["source"]["sha256"]
        assert (q["original_status"], q["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = diags[item["replay"]["finding_line"]]
        assert diag["diagnostic_id"] == item["replay"]["diagnostic_id"]
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"]
    assert replay["build_target"]["target"] == "ohos_fuzztest(DBPreferencesVectorFuzzTest)"
    assert replay["build_target"]["production_evidence"] is False
    assert len(replay["structured_vibe_prompt"]["steps"]) == 4
    print("PASS D38: exact A0 source binding; complete current CLI parse; 6/6 line candidates")
    print("PASS GN: DBPreferencesVectorFuzzTest is under testonly fuzztest group")
    print("PASS A0: all 345 row counts preserved; CR-0091–CR-0096 remain not_testable / paused_pending_evidence")
    print("PASS disposition: PARTIAL; no product-root miss established; no detector change")


if __name__ == "__main__":
    main()
