from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = Path(r"D:\openHarmonyScanner\tmp\t43-taihe-source-20261026")
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = ROOT / "research/evidence/cpp/t43_independent_cli_20261026.json"
OUT = ROOT / "research/evidence/cpp/t43_independent_checkout_attestation_20261026.json"
COMMIT = "d91f43e80d892bca694c6b0fce8ea27cd644919f"
TREE = "8c5eecdad09e2fe960ce5f3728959a4726f0a91d"
IDS = [f"CR-{i:04d}" for i in range(197, 214)]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SRC), *args], text=True).strip()


def git_bytes(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(SRC), *args])


def main() -> None:
    with QUEUE.open(encoding="utf-8-sig", newline="") as f:
        all_rows = list(csv.DictReader(f))
    rows = {r["queue_id"]: r for r in all_rows}
    assert len(all_rows) == len(rows) == 345
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", "HEAD^{tree}") == TREE
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["source_parsing"]["parsing_status"] == {"complete": 2}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", 16)
    findings = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    per_id = []
    for qid in IDS:
        r = rows[qid]
        assert (r["repository"], r["commit"], r["tree"]) == ("openharmony/arkcompiler_taihe_ffi_gen", COMMIT, TREE)
        data = git_bytes("show", f"{COMMIT}:{r['path']}")
        blob = git("rev-parse", f"{COMMIT}:{r['path']}")
        sha = hashlib.sha256(data).hexdigest()
        assert blob == r["blob"] and sha == r["source_sha256"]
        assert (r["original_status"], r["queue_status"]) == ("not_testable", "paused_pending_evidence")
        diag = findings.get((r["path"], int(r["line"])))
        if diag:
            assert diag["source_sha256"] == sha and diag["rule_id"] == "ohcpp-shared-ptr-race-candidate-001"
        lines = data.decode("utf-8").splitlines()
        per_id.append({"queue_id": qid, "candidate_id": r["candidate_id"], "path": r["path"], "line": int(r["line"]), "line_text": lines[int(r["line"]) - 1].strip(), "blob": blob, "sha256": sha, "finding_id": diag["diagnostic_id"] if diag else None, "mapping": "matched" if diag else "not_matched"})
    build = git_bytes("show", f"{COMMIT}:BUILD.gn")
    build_text = build.decode("utf-8")
    root_refs = {p: p in build_text for p in {x["path"] for x in per_id}}
    assert not any(root_refs.values())
    files = git("ls-tree", "-r", "--name-only", COMMIT).splitlines()
    nested_test_builds = [p for p in files if p.startswith("test/") and p.endswith("BUILD.gn")]
    assert nested_test_builds == ["test/integer/author/BUILD.gn", "test/integer/user/BUILD.gn"]
    header = git_bytes("show", f"{COMMIT}:test/ra_napi_image/author/include/image_source_taihe.h").decode("utf-8")
    assert "This file is a test file." in header
    queue_bytes = QUEUE.read_bytes()
    result = {
        "schema": "t43-independent-checkout-attestation-v1",
        "verification_checkout": str(ROOT),
        "verification_checkout_head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "source": {"repository": "openharmony/arkcompiler_taihe_ffi_gen", "commit": COMMIT, "tree": TREE},
        "cli": {"artifact": RAW.name, "detector": run["tool"], "version": run["tool_version"], "parse": raw["source_parsing"]["parsing_status"], "diagnostics": run["diagnostic_count"], "scope_files": run["scope_files"], "scope_loc": run["scope_loc"]},
        "build": {"root_BUILD_gn_sha256": hashlib.sha256(build).hexdigest(), "root_build_references": root_refs, "nested_test_builds": nested_test_builds, "ra_napi_header_says_test_file": True, "product_target_bound": False},
        "a0": {"count": len(all_rows), "queue_csv_sha256": hashlib.sha256(queue_bytes).hexdigest(), "ids": IDS, "unchanged": True},
        "per_id": per_id,
        "summary": {"matched": sum(x["finding_id"] is not None for x in per_id), "unmatched": [x["queue_id"] for x in per_id if x["finding_id"] is None], "disposition": "PARTIAL/BLOCK", "reason": "product build, same-object conflicting cross-thread accesses, caller/reachability and trusted fix/safety ground truth unestablished"},
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS independent checkout attestation: 17 IDs; 16 findings; full parse; source, BUILD.gn, and A0 identities verified")


if __name__ == "__main__":
    main()
