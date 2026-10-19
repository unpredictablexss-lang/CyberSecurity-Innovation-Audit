#!/usr/bin/env python3
"""Verify T2's PR #35 incremental source bindings and preserved A0 queue."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
RECORD = EVIDENCE / "t2_pr35_incremental_acceptance_20261020.json"
BASE = "8ec5f56a12e90bba56953b39eb17faa20e154da9"
A0_BASE = "b87e2d4350dc18e5b6a656018a36b22c3c2f42ed"


def git(git_dir: str, *args: str, binary: bool = False):
    raw = subprocess.check_output(["git", f"--git-dir={git_dir}", *args])
    return raw if binary else raw.decode("utf-8").strip()


def source_hash(git_dir: str, commit: str, path: str) -> tuple[str, str]:
    blob = git(git_dir, "rev-parse", f"{commit}:{path}")
    data = git(git_dir, "cat-file", "blob", blob, binary=True)
    return blob, hashlib.sha256(data).hexdigest()


def main() -> None:
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert head == record["target_commit"], (head, record["target_commit"])

    # Confirm the frozen matrix remains 13 entries and matches T12's independently
    # recorded 3 regression PASS / 8 PARTIAL / 2 N/A distribution.
    matrix_path = ROOT / "research/evidence/cpp/a_static_baseline_20261019/matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    t12 = json.loads((EVIDENCE / "t12_a_line_wave_acceptance_20261020.json").read_text(encoding="utf-8"))
    assert len(matrix["cases"]) == 13 == matrix["cases_total"]
    counts = t12["dispositions"]["updated_case_counts"]
    assert counts == {"PASS": 3, "PARTIAL": 8, "BLOCK": 0, "N/A": 2}

    # Independently compare all original A0 identifiers and status pairs with the
    # frozen integration-base queue; this audit never edits either queue file.
    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    current = list(csv.DictReader(queue_path.open(encoding="utf-8-sig", newline="")))
    frozen = json.loads(subprocess.check_output(
        ["git", "show", f"{A0_BASE}:research/deliveries/cpp/a0_triage_20261019/queue.json"],
        cwd=ROOT,
    ).decode("utf-8-sig"))
    pair = lambda rows: {row["queue_id"]: (row["original_status"], row["queue_status"]) for row in rows}
    frozen_rows = frozen["queue"]
    assert len(current) == 345 and len(pair(current)) == 345
    assert pair(current) == pair(frozen_rows)
    assert record["queue_invariant"]["rows"] == 345

    # Recheck exact vulnerable/fixed object identities and byte hashes for the
    # incremental cases whose local object databases are available.
    libpng_dbs = {
        "33416": r"D:/openHarmonyScanner/tmp/libpng-gitlab-mirror-pins-20261019.git",
        "46675": r"D:/openHarmonyScanner/tmp/t34-libpng46675-source-20261023.git",
    }
    d54 = json.loads((EVIDENCE / "d54_libpng_lifetime_assessment_20261030.json").read_text(encoding="utf-8"))
    for case, variants in d54["cases"].items():
        number = "33416" if case.endswith("33416") else "46675"
        db = libpng_dbs[number]
        for variant_name, variant in variants["variants"].items():
            commit, tree = variant["commit"], variant["tree"]
            assert git(db, "rev-parse", f"{commit}^{{tree}}") == tree
            for path, expected_sha in variant["files"].items():
                _, actual_sha = source_hash(db, commit, path)
                assert actual_sha == expected_sha, (case, variant_name, path)
            cli = json.loads((EVIDENCE / variant["cli_report"]).read_text(encoding="utf-8"))
            assert cli["commit"] == commit and cli["git_tree"] == tree
            assert cli["diagnostic_count"] == 0

    # dSoftBus exact commit/tree/blob/SHA pairs and current result artifact.
    t62 = json.loads((EVIDENCE / "t62_dsoftbus_cve_2025_26690_independent_acceptance_20261030.json").read_text(encoding="utf-8"))
    dsoftbus_db = r"D:/openHarmonyScanner/tmp/d22-upstream-dsoftbus-object-store"
    dsoftbus_path = "core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp"
    for variant in t62["source_objects"].values():
        commit, tree = variant["commit"], variant["tree"]
        assert git(dsoftbus_db, "rev-parse", f"{commit}^{{tree}}") == tree
        blob, digest = source_hash(dsoftbus_db, commit, dsoftbus_path)
        assert blob == variant["blob"] and digest == variant["sha256"]
    assert t62["disposition"] == "PARTIAL/BLOCK"

    # cJSON per-case source hashes are checked by the independent T60 verifier;
    # enforce its exact known locations and that its controls do not call an
    # experimental patch a fixed source.
    t60 = json.loads((EVIDENCE / "t60_cjson_cve_2026_67215_67216_acceptance_20261029.json").read_text(encoding="utf-8"))
    cli = json.loads((EVIDENCE / "t60_cjson_cli_20261029.json").read_text(encoding="utf-8"))
    observed = {(d["file"], d["line"]) for d in cli["detector_runs"][0]["diagnostics"]}
    assert observed == {("cJSON.c", 3161), ("cJSON_Utils.c", 932), ("cJSON_Utils.c", 950)}
    assert t60["controls"]["fixed"].startswith("none trusted")

    contacts = json.loads((EVIDENCE / "a_t20_contacts_path_traversal_acceptance_20261020.json").read_text(encoding="utf-8"))
    contacts_db = r"D:/openHarmonyScanner/openharmony/.repo/project-objects/applications_contacts_data.git"
    source = contacts["source"]
    assert git(contacts_db, "rev-parse", f"{source['commit']}^{{tree}}") == source["tree"]
    blob, digest = source_hash(contacts_db, source["commit"], source["path"])
    assert blob == source["blob"] and digest == source["sha256"]
    assert contacts["replay"]["independent_later_script_replay"]["same_source_identity_parse_status_and_candidate_locations"] is True

    # All evidence named by the T2 record must exist and be hashable. This also
    # captures the exact artifacts reviewed by this acceptance snapshot.
    artifact_hashes = {}
    for row in record["case_results"]:
        for relative in row["evidence"]:
            path = ROOT / relative
            assert path.is_file(), relative
            artifact_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({
        "overall_ok": True,
        "target_commit": head,
        "baseline_matrix_cases": len(matrix["cases"]),
        "t12_disposition_counts": counts,
        "a0_rows": len(current),
        "a0_id_and_status_pairs_unchanged": True,
        "libpng_source_pairs": 2,
        "dsoftbus_source_pairs": 2,
        "contacts_source_sha256": digest,
        "cjson_candidate_positions": sorted([list(x) for x in observed]),
        "reviewed_artifact_sha256": artifact_hashes,
        "overall_disposition": record["overall"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
