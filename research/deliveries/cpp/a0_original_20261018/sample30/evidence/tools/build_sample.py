from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCAN_ROOT = Path(r"D:\openHarmonyScanner\openharmony-full-scan-20261017")
OUTPUT_ROOT = Path(r"D:\openHarmonyScanner\outputs\01a14d00-bc78-7ac2-9520-210d4b92b1ac")
SEED = "20261018"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wsl_path(path: Path) -> str:
    raw = str(path)
    normalized = raw.replace("\\", "/")
    if normalized.startswith("/mnt/d/"):
        return normalized
    if raw.startswith("D:\\"):
        return "/mnt/d/" + raw[3:].replace("\\", "/")
    raise ValueError(f"expected D: or /mnt/d path: {raw}")

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def diagnostics(result: dict) -> list[dict]:
    output = []
    for run in result.get("detector_runs", []):
        for diagnostic in run.get("diagnostics", []):
            item = dict(diagnostic)
            item["detector_version"] = run.get("tool_version", "")
            item["run_id"] = run.get("run_id", "")
            output.append(item)
    return output


def main() -> None:
    evidence = OUTPUT_ROOT / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    eligible = []
    for project_dir in sorted((SCAN_ROOT / "projects").iterdir()):
        required = [project_dir / name for name in ("report.md", "result.json", "run_meta.json")]
        if not all(path.is_file() for path in required):
            continue
        request = load_json(project_dir / "request.json")
        result = load_json(project_dir / "result.json")
        run_meta = load_json(project_dir / "run_meta.json")
        diags = diagnostics(result)
        rank_digest = hashlib.sha256(
            f"{SEED}\0{result['repository']}\0{result['snapshot_sha256']}".encode("utf-8")
        ).hexdigest()
        eligible.append({
            "project_dir": project_dir,
            "request": request,
            "result": result,
            "run_meta": run_meta,
            "diagnostics": diags,
            "rank_digest": rank_digest,
        })

    strata = {
        "candidate_bearing": sorted(
            (row for row in eligible if row["diagnostics"]),
            key=lambda row: (row["rank_digest"], row["result"]["repository"], row["result"]["snapshot_sha256"]),
        )[:20],
        "zero_candidate": sorted(
            (row for row in eligible if not row["diagnostics"]),
            key=lambda row: (row["rank_digest"], row["result"]["repository"], row["result"]["snapshot_sha256"]),
        )[:10],
    }
    selected = strata["candidate_bearing"] + strata["zero_candidate"]

    records = []
    for order, row in enumerate(selected, 1):
        project_dir = row["project_dir"]
        request, result, run_meta = row["request"], row["result"], row["run_meta"]
        records.append({
            "sample_order": order,
            "stratum": "candidate_bearing" if row["diagnostics"] else "zero_candidate",
            "rank_digest": row["rank_digest"],
            "project_dir": str(project_dir),
            "wsl_repo_dir": wsl_path(Path(request["repo_dir"])),
            "report_md": str(project_dir / "report.md"),
            "result_json": str(project_dir / "result.json"),
            "run_meta_json": str(project_dir / "run_meta.json"),
            "repository": result["repository"],
            "project_path": request["project_path"],
            "commit": result["commit"],
            "git_tree": result["git_tree"],
            "snapshot_sha256": result["snapshot_sha256"],
            "profile_id": result["profile_id"],
            "diagnostic_count": len(row["diagnostics"]),
            "diagnostics": row["diagnostics"],
            "artifact_sha256": {
                "report.md": sha256_file(project_dir / "report.md"),
                "result.json": sha256_file(project_dir / "result.json"),
                "run_meta.json": sha256_file(project_dir / "run_meta.json"),
                "request.json": sha256_file(project_dir / "request.json"),
            },
            "run_consistency": {
                "commit_matches": run_meta.get("actual_commit") == result.get("commit") == request.get("actual_commit"),
                "tree_matches": run_meta.get("git_tree") == result.get("git_tree") == request.get("git_tree"),
                "count_matches": run_meta.get("diagnostic_count") == result.get("diagnostic_count") == len(row["diagnostics"]),
                "status": run_meta.get("scanner_status"),
                "execution_state": run_meta.get("execution_state"),
            },
        })

    summary = load_json(SCAN_ROOT / "summary.json")
    project_dirs = list((SCAN_ROOT / "projects").iterdir())
    listed_project_count = int(summary["project_count"])
    counts = {
        "eligible_reports": len(eligible),
        "excluded_failed_or_no_report": listed_project_count - len(eligible),
        "summary_project_count": listed_project_count,
        "observed_project_directories": len(project_dirs),
        "unlisted_partial_project_directories": len(project_dirs) - listed_project_count,
        "population_candidate_bearing_reports": sum(bool(row["diagnostics"]) for row in eligible),
        "population_zero_candidate_reports": sum(not row["diagnostics"] for row in eligible),
        "population_diagnostics": sum(len(row["diagnostics"]) for row in eligible),
        "sample_candidate_bearing_reports": len(strata["candidate_bearing"]),
        "sample_zero_candidate_reports": len(strata["zero_candidate"]),
        "sample_reports": len(records),
        "sample_diagnostics": sum(len(row["diagnostics"]) for row in records),
        "sample_high_priority_candidates": sum(
            diagnostic["rule_id"] != "ipc.relay.descriptor-boundary"
            for row in records for diagnostic in row["diagnostics"]
        ),
        "sample_normal_priority_candidates": sum(
            diagnostic["rule_id"] == "ipc.relay.descriptor-boundary"
            for row in records for diagnostic in row["diagnostics"]
        ),
    }
    manifest = {
        "schema_version": "openharmony-a-line-sample30-v1",
        "created_at": "2026-10-18T00:00:00+08:00",
        "source_root": str(SCAN_ROOT),
        "seed": SEED,
        "algorithm": {
            "description": "SHA-256(seed NUL repository NUL snapshot_sha256), ascending hexadecimal digest; tie-break by repository then snapshot_sha256.",
            "input_encoding": "UTF-8",
            "seed": SEED,
            "strata": {
                "candidate_bearing": {"population": counts["population_candidate_bearing_reports"], "sample_size": 20},
                "zero_candidate": {"population": counts["population_zero_candidate_reports"], "sample_size": 10},
            },
        },
        "counts": counts,
        "records": records,
    }
    (evidence / "sample_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(counts, ensure_ascii=False, indent=2))
    for record in records:
        print(record["sample_order"], record["stratum"], record["repository"], record["diagnostic_count"], record["rank_digest"])


if __name__ == "__main__":
    main()


