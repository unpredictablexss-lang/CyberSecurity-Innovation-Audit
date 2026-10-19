from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / "research/evidence/cpp/t38_preferences_vector_cli_20261024.json"
OUT = ROOT / "research/evidence/cpp/t38_preferences_vector_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
A0_QUEUE = Path(r"D:\openHarmonyScanner\tmp\a0_triage_t22_verify_20261020\queue.csv")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPO = "openharmony/distributeddatamgr_preferences"
SRC = "test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesvector_fuzzer/BUILD.gn"
IDS = [f"CR-{i:04d}" for i in range(91, 97)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def bind(path: str) -> dict[str, str | int]:
    blob = git("show", f"{COMMIT}:{path}")
    return {"path": path, "blob": git("hash-object", "--stdin", data=blob).decode().strip(),
            "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}


def main() -> None:
    rows = list(csv.DictReader(A0_QUEUE.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345 and len({r["queue_id"] for r in rows}) == 345
    qmap = {r["queue_id"]: r for r in rows}
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    src, build = bind(SRC), bind(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert (raw["commit"], raw["git_tree"], raw["repository"]) == (COMMIT, TREE, REPO)
    assert raw["scope"]["declared_scope"] == [SRC]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 6)
    diagnostics = {d["line"]: d for d in run["diagnostics"] if d["file"] == SRC}
    assert set(diagnostics) == {45, 50, 52, 68, 77, 78}
    items = []
    for qid in IDS:
        row = qmap[qid]
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (REPO, COMMIT, TREE, SRC)
        assert row["blob"] == src["blob"] and row["source_sha256"].lower() == src["sha256"]
        assert (row["original_status"], row["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = diagnostics[int(row["line"])]
        assert diag["source_sha256"] == row["source_sha256"].lower()
        items.append({"queue_id": qid, "candidate_id": row["candidate_id"], "source_line": int(row["line"]),
                      "source": {**src, "repository": REPO, "commit": COMMIT, "tree": TREE},
                      "original_a0": {"original_status": row["original_status"], "queue_status": row["queue_status"]},
                      "replay": {"detector": run["tool"], "version": run["tool_version"],
                                 "parse_status": "complete", "diagnostic_id": diag["diagnostic_id"],
                                 "rule_id": diag["rule_id"], "finding_line": diag["line"], "symbol": diag["symbol"]},
                      "disposition": "PARTIAL"})
    report = {
        "schema_version": "t38-preferences-vector-independent-audit-v1",
        "task": "T38",
        "integration_base": "5d6e6897aa9dd0b366f6efc057204e06e9494638",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE, "file": src},
        "build_target": {"file": build, "target": "ohos_fuzztest(DBPreferencesVectorFuzzTest)",
                         "group": 'group("fuzztest") { testonly = true }',
                         "production_build_or_reachability_proven": False},
        "cli": {"raw": RAW.name, "detector": run["tool"], "version": run["tool_version"],
                "status": run["status"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                "parse": raw["source_parsing"]["parsing_status"], "finding_count": run["diagnostic_count"],
                "command": "python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race"},
        "a0": {"rows": len(rows), "audited_ids": IDS, "queue_state_unchanged": True},
        "items": items,
        "limitations": ["The exact GN target is a fuzz test and only its fuzztest aggregation group is testonly; whether the target is part of a product build is not established.",
                        "LLVMFuzzerTestOneInput sequentially calls setup, Put/Get helpers, and teardown; this translation unit has no demonstrated concurrent execution.",
                        "Product caller reachability, same-object overlap, synchronization protocol, attacker control, and security impact remain unproven."],
        "overall_disposition": "PARTIAL",
        "queue_states_changed": False,
        "detector_or_test_changes": False,
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS T38: {len(items)} rows bound; {len(diagnostics)} candidates reproduced; A0 rows={len(rows)}")


if __name__ == "__main__":
    main()
