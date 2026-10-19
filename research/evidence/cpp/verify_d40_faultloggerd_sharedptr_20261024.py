#!/usr/bin/env python3
"""Verify D40's exact A0 rows, source objects, and current CLI replay."""
from __future__ import annotations
import argparse, csv, hashlib, json, subprocess
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
IDS = {f"CR-{i:04d}" for i in range(119, 161)}
RAW = HERE / "d40_faultloggerd_sharedptr_20261024.json"
REPLAY = HERE / "d40_faultloggerd_sharedptr_replay_20261024.json"
def git(gitdir: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={gitdir}", *args], input=data)
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-git-dir", type=Path, required=True)
    ap.add_argument("--queue-csv", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv")
    ap.add_argument("--queue-json", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json")
    a = ap.parse_args(); gd = a.source_git_dir.resolve()
    assert git(gd, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git(gd, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    rows = list(csv.DictReader(a.queue_csv.open(encoding="utf-8-sig", newline="")))
    qj = json.loads(a.queue_json.read_text(encoding="utf-8"))["queue"]
    cmap = {r["queue_id"]: r for r in rows}; jmap = {r["queue_id"]: r for r in qj}
    assert len(rows) == len(qj) == len(cmap) == len(jmap) == 345
    selected = {k: v for k, v in cmap.items() if k in IDS}
    assert set(selected) == IDS
    replay = json.loads(REPLAY.read_text(encoding="utf-8")); raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == "openharmony/hiviewdfx_faultloggerd"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 11}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 11)
    assert replay["source"]["commit"] == COMMIT and replay["source"]["tree"] == TREE
    assert set(replay["queue"]["audited_ids"]) == IDS and len(replay["items"]) == 42
    ds = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    for item in replay["items"]:
        qid = item["queue_id"]; row = selected[qid]; jrow = jmap[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key])
        assert row["candidate_id"] == item["candidate_id"]
        src = item["source"]
        for key in ("repository", "commit", "tree", "path", "line", "blob"):
            assert str(row[key]) == str(src[key]), (qid, key)
        assert row["source_sha256"] == src["sha256"], (qid, "source_sha256")
        assert row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence"
        assert row["commit"] == COMMIT and row["tree"] == TREE
        content = git(gd, "show", f"{COMMIT}:{row['path']}")
        blob = git(gd, "hash-object", "--stdin", data=content).decode().strip()
        sha = hashlib.sha256(content).hexdigest()
        assert (blob, sha) == (row["blob"], row["source_sha256"])
        assert item["source"]["blob"] == blob and item["source"]["sha256"] == sha
        assert item["replay"]["result"] == ("matched_exact_line" if (row["path"], int(row["line"])) in ds else "no_current_finding_at_a0_line")
    followup = replay["production_call_context_followup"]
    assert followup["source_identity"]["commit"] == COMMIT
    assert followup["source_identity"]["tree"] == TREE
    expected_paths = {"tools/process_dump/lite_process_dumper.cpp", "tools/process_dump/minidump_dumper.cpp", "tools/process_dump/BUILD.gn", "interfaces/innerkits/unwinder_refactor/src/unwind_local/local_unwinder.cpp", "interfaces/innerkits/unwinder_refactor/BUILD.gn", "interfaces/innerkits/unwinder/src/unwind_local/thread_context.cpp", "interfaces/innerkits/unwinder/include/thread_context.h", "BUILD.gn"}
    identities = {x["path"]: x for x in followup["source_identity"]["files"]}
    assert set(identities) == expected_paths
    for path, ident in identities.items():
        content = git(gd, "show", f"{COMMIT}:{path}")
        assert git(gd, "hash-object", "--stdin", data=content).decode().strip() == ident["blob"]
        assert hashlib.sha256(content).hexdigest() == ident["sha256"]
    lite = git(gd, "show", f"{COMMIT}:tools/process_dump/lite_process_dumper.cpp").decode().splitlines()
    mini = git(gd, "show", f"{COMMIT}:tools/process_dump/minidump_dumper.cpp").decode().splitlines()
    local = git(gd, "show", f"{COMMIT}:interfaces/innerkits/unwinder_refactor/src/unwind_local/local_unwinder.cpp").decode().splitlines()
    assert "SetMaps(dfxMaps_)" in lite[361] and "SetMaps(dfxMaps_)" in mini[513]
    assert "CollectThreadContext(tid)" in local[175] and "ReleaseCollectThreadContext()" in local[176] and "ReleaseCollectThreadContext()" in local[180]
    build = git(gd, "show", f"{COMMIT}:tools/process_dump/BUILD.gn").decode()
    refbuild = git(gd, "show", f"{COMMIT}:interfaces/innerkits/unwinder_refactor/BUILD.gn").decode()
    assert '"lite_process_dumper.cpp"' in build and '"minidump_dumper.cpp"' in build
    assert 'ohos_executable("processdump")' in build and "install_enable = true" in build
    assert '"src/unwind_local/local_unwinder.cpp"' in refbuild and 'ohos_shared_library("libunwinder_refactor")' in refbuild
    assert followup["correction"].startswith("D40 initial statement that no production SetMaps caller was found was wrong")
    assert replay["queue"]["states_changed"] is False
    print("D40 exact source commit/tree and 11-file parse-complete CLI replay: PASS")
    print("D40 42 A0 source hashes, candidate-line mapping and unchanged states: PASS")
    print("T40 exact production caller, LocalUnwinder lifecycle, and BUILD identities/context: PASS")
    print("A0 345-row count and original/queue state cross-check: PASS")
    return 0
if __name__ == "__main__": raise SystemExit(main())
