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
RAW = HERE / "d39_preferences_fuzzer_cli_20261024.json"
REPLAY = HERE / "d39_preferences_fuzzer_replay_20261024.json"


def main() -> None:
    subprocess.check_call([sys.executable, str(HERE / "d39_preferences_fuzzer_replay_20261024.py")])
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
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19)
    assert replay["task"] == "D39" and replay["overall_disposition"] == "PARTIAL" and not replay["queue_states_changed"]
    assert [x["queue_id"] for x in replay["items"]] == [f"CR-{i:04d}" for i in range(97, 116)]
    source = replay["source"]["file"]
    build = replay["build_target"]["file"]
    assert source["blob"] == "fad8bdb1b87a8566b355b0ea4dbd5020c42c405c"
    assert source["sha256"] == "140266d2693d7a0028767c80670d01682c2e7deca2634412028a59504a976e29"
    assert build["blob"] == "8506a0917b7fbff48a6d14ccb4c1f931db5db251"
    assert build["sha256"] == "d10327b19d3006cc1f0c9ad52d858a009cd0c90d8d4c0e14be6e2d870c132488"
    expected = {46, 51, 53, 68, 69, 77, 78, 86, 87, 95, 96, 104, 105, 113, 114, 115, 124, 125, 126}
    diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == source["path"]}
    assert set(diags) == expected
    assert replay["behavior"]["thread_creation_or_dispatch_in_entry"] is False
    assert replay["build_target"]["target"] == "ohos_fuzztest(PreferencesFuzzTest)"
    assert replay["build_target"]["test_group"] == 'group("fuzztest") [testonly = true]'
    assert replay["build_target"]["production_evidence"] is False
    for item in replay["items"]:
        q = byid[item["queue_id"]]
        assert q["path"] == source["path"] and int(q["line"]) == item["source"]["line"]
        assert q["blob"] == item["source"]["blob"] and q["source_sha256"].lower() == item["source"]["sha256"]
        assert (q["original_status"], q["queue_status"]) == ("not_testable", "paused_pending_evidence")
        assert item["replay"]["diagnostic_id"] == diags[int(q["line"])]["diagnostic_id"]
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"]
    print("PASS D39: exact A0 source binding; complete shared_ptr_race 0.5.1 CLI parse; 19/19 row candidates")
    print("PASS GN/source behavior: PreferencesFuzzTest under testonly fuzztest group; fuzzer entry calls are sequential")
    print("PASS A0: all 345 rows and status counts preserved; CR-0097–CR-0115 remain not_testable / paused_pending_evidence")
    print("PASS disposition: PARTIAL; no labeled product-root miss established; no detector change")


if __name__ == "__main__":
    main()
