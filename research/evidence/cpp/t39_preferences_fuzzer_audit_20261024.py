from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
RAW = EVIDENCE / "t39_preferences_fuzzer_cli_20261024.json"
OUT = EVIDENCE / "t39_preferences_fuzzer_audit_20261024.json"
SOURCE_REPO = Path(r"D:\openHarmonyScanner\tmp\t39-preferences-source-20261024")
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
REPOSITORY = "openharmony/distributeddatamgr_preferences"
SOURCE_PATH = "test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp"
BUILD_PATH = "test/native/fuzztest/preferences_fuzzer/BUILD.gn"
IDS = [f"CR-{number:04d}" for number in range(97, 116)]


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(SOURCE_REPO), *args], text=True
    ).strip()


def file_identity(path: str) -> dict[str, str | int]:
    data = subprocess.check_output(["git", "-C", str(SOURCE_REPO), "show", f"{COMMIT}:{path}"])
    return {
        "path": path,
        "blob": git("rev-parse", f"{COMMIT}:{path}"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def source_lines(path: str) -> list[str]:
    data = subprocess.check_output(["git", "-C", str(SOURCE_REPO), "show", f"{COMMIT}:{path}"])
    return data.decode("utf-8").splitlines()


def main() -> None:
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 345 and len({row["queue_id"] for row in rows}) == 345
    by_id = {row["queue_id"]: row for row in rows}
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", "HEAD^{tree}") == TREE
    source = file_identity(SOURCE_PATH)
    build = file_identity(BUILD_PATH)
    src_lines = source_lines(SOURCE_PATH)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert (raw["repository"], raw["commit"], raw["git_tree"]) == (REPOSITORY, COMMIT, TREE)
    assert raw["scope"]["declared_scope"] == [SOURCE_PATH]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19
    )
    diagnostics = {
        item["line"]: item for item in run["diagnostics"] if item["file"] == SOURCE_PATH
    }
    assert len(diagnostics) == 19
    items = []
    for queue_id in IDS:
        row = by_id[queue_id]
        assert (row["repository"], row["commit"], row["tree"], row["path"]) == (
            REPOSITORY, COMMIT, TREE, SOURCE_PATH
        )
        assert row["blob"] == source["blob"]
        assert row["source_sha256"].lower() == source["sha256"]
        assert (row["original_status"], row["queue_status"]) == (
            "not_testable", "paused_pending_evidence"
        )
        line = int(row["line"])
        diagnostic = diagnostics[line]
        assert diagnostic["source_sha256"] == source["sha256"]
        items.append({
            "queue_id": queue_id,
            "candidate_id": row["candidate_id"],
            "source_line": line,
            "source_line_text": src_lines[line - 1].strip(),
            "source": {**source, "repository": REPOSITORY, "commit": COMMIT, "tree": TREE},
            "original_a0": {
                "original_status": row["original_status"],
                "queue_status": row["queue_status"],
            },
            "replay": {
                "detector": run["tool"],
                "version": run["tool_version"],
                "parse_status": "complete",
                "diagnostic_id": diagnostic["diagnostic_id"],
                "rule_id": diagnostic["rule_id"],
                "finding_line": diagnostic["line"],
                "symbol": diagnostic["symbol"],
                "evidence_type": diagnostic["evidence_type"],
                "source_sha256": diagnostic["source_sha256"],
            },
            "disposition": "PARTIAL",
        })
    queue_bytes = QUEUE.read_bytes()
    report = {
        "schema_version": "t39-preferences-fuzzer-independent-audit-v1",
        "task": "T39",
        "integration_base": "10e06fe7e4a49d69175fc4f30aee90a4011f6f98",
        "source": {"repository": REPOSITORY, "commit": COMMIT, "tree": TREE, "file": source},
        "build_target": {
            "file": build,
            "target": 'ohos_fuzztest("PreferencesFuzzTest")',
            "aggregation_group": 'group("fuzztest")',
            "group_testonly": True,
            "product_build_or_reachability_proven": False,
        },
        "cli": {
            "raw": RAW.name,
            "detector": run["tool"],
            "version": run["tool_version"],
            "status": run["status"],
            "scope_files": run["scope_files"],
            "scope_loc": run["scope_loc"],
            "parse": raw["source_parsing"]["parsing_status"],
            "finding_count": run["diagnostic_count"],
            "elapsed_seconds": run["elapsed_seconds"],
            "command": (
                "python -m src.cli.main ohscan-run --repo-dir "
                "D:\\openHarmonyScanner\\tmp\\t39-preferences-source-20261024 "
                "--repository openharmony/distributeddatamgr_preferences "
                f"--commit {COMMIT} --include {SOURCE_PATH} "
                "--detector ohscanner.cpp.shared_ptr_race"
            ),
        },
        "a0": {
            "rows": len(rows),
            "queue_csv_sha256": hashlib.sha256(queue_bytes).hexdigest(),
            "audited_ids": IDS,
            "queue_state_unchanged": True,
        },
        "items": items,
        "limitations": [
            "The GN file defines an ohos_fuzztest target and places it under a group marked testonly=true; whether this target or the component is included in a product build is not established.",
            "LLVMFuzzerTestOneInput sequentially initializes Preferences_, invokes seven Put/Get/Delete/Clear/Flush helpers, then tears down; this translation unit shows no thread creation or parallel dispatch, so it does not establish concurrent access to the same object.",
            "The 19 syntax candidates are source-level shared_ptr access observations, not 19 independently established races or vulnerabilities.",
            "Product caller reachability, effective product build selection, cross-thread same-object overlap, synchronization/ownership protocol, attacker control, trigger conditions, and security impact remain unknown.",
        ],
        "overall_disposition": "PARTIAL",
        "queue_states_changed": False,
        "detector_or_test_changes": False,
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS T39 replay record: {len(items)} A0 IDs mapped to {len(diagnostics)} complete-parse candidates")


if __name__ == "__main__":
    main()
