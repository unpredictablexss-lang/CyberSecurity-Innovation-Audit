from __future__ import annotations
import collections, csv, hashlib, json, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OBJ = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
SRC = "test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesget_fuzzer/BUILD.gn"

def git(*args, data=None):
    return subprocess.check_output(["git", f"--git-dir={OBJ}", *args], input=data)

def main():
    report = json.loads((HERE / "t37_preferences_get_fuzzer_replay_20261024.json").read_text(encoding="utf-8"))
    raw = json.loads((HERE / "t37_preferences_get_fuzzer_20261024.json").read_text(encoding="utf-8"))
    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    rows = list(csv.DictReader(queue_path.open(encoding="utf-8-sig", newline="")))
    qmap = {r["queue_id"]: r for r in rows}
    qjson = json.loads(queue_path.with_name("queue.json").read_text(encoding="utf-8"))["queue"]
    assert len(rows) == len(qjson) == len(qmap) == 345
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == "7761d9e273ae7007046ae115797f255e554523ae"
    for path, binding in ((SRC, report["source"]["file"]), (BUILD, report["build_target"]["file"])):
        content = git("show", f"{COMMIT}:{path}")
        assert git("hash-object", "--stdin", data=content).decode().strip() == binding["blob"]
        assert hashlib.sha256(content).hexdigest() == binding["sha256"]
    build = git("show", f"{COMMIT}:{BUILD}")
    source = git("show", f"{COMMIT}:{SRC}")
    assert b'ohos_fuzztest("DBPreferencesGetFuzzTest")' in build
    assert b'group("fuzztest")' in build and b"testonly = true" in build
    assert b"LLVMFuzzerTestOneInput" in source
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 25)
    ds = [d for d in run["diagnostics"] if d["file"] == SRC]
    assert len(ds) == 25 and {d["line"] for d in ds} == {i["source"]["line"] for i in report["items"]}
    assert len(report["items"]) == 25 and {i["queue_id"] for i in report["items"]} == {f"CR-{n:04d}" for n in range(66, 91)}
    for item in report["items"]:
        q = qmap[item["queue_id"]]
        assert q["path"] == SRC and int(q["line"]) == item["source"]["line"]
        assert q["blob"] == report["source"]["file"]["blob"] and q["source_sha256"].lower() == report["source"]["file"]["sha256"]
        assert (q["original_status"], q["queue_status"]) == ("not_testable", "paused_pending_evidence")
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"] is True
    states = {k: dict(collections.Counter(r[k] for r in rows)) for k in ("original_status", "queue_status")}
    assert states["original_status"] == {"not_testable": 336, "not_reproduced": 9}
    assert states["queue_status"] == {"paused_pending_evidence": 331, "queued_not_reproduced": 9, "queued_first_batch": 5}
    print("PASS T37 exact source/BUILD Git blob and SHA provenance; fuzz target=testonly")
    print("PASS current shared_ptr_race 0.5.1 replay: complete parse, 25/25 source locations")
    print("PASS A0: CR-0066–CR-0090 identity and states preserved; 345-row queue unchanged")
    print("PASS disposition: PARTIAL; product reachability/race/impact not inferred")

if __name__ == "__main__": main()
