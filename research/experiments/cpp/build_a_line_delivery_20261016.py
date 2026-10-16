"""Build the A-line half-year/cross-version delivery manifest from fixed reports."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object: " + str(path))
    return value


def artifact(path: Path, root: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def git_text(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, encoding="utf-8"
    ).strip()


def project_checkout() -> dict[str, Any]:
    status = subprocess.check_output(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1"],
        text=True,
        encoding="utf-8",
    )
    rows = [line for line in status.splitlines() if line]
    return {
        "branch": git_text("rev-parse", "--abbrev-ref", "HEAD"),
        "head": git_text("rev-parse", "HEAD"),
        "tree": git_text("rev-parse", "HEAD^{tree}"),
        "remote": git_text("remote", "get-url", "origin"),
        "dirty": bool(rows),
        "dirty_file_count": len(rows),
        "dirty_status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        "dirty_worktree_preserved": True,
    }


def normalized_halfyear(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "commit": item.get("commit"),
            "parent": item.get("parent"),
            "git_tree": item.get("git_tree"),
            "changed_paths": item.get("changed_paths", []),
            "source_manifest": item.get("source_manifest", []),
            "execution_status": item.get("execution_status"),
            "coverage_status": item.get("coverage_status"),
            "candidate_count": item.get("candidate_count"),
            "candidate_count_status": item.get("candidate_count_status"),
            "candidate_keys": sorted(
                row.get("source_observation_key")
                for row in item.get("candidates", [])
            ),
        }
        for item in report.get("commits", [])
    ]


def count_values(rows: Sequence[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts = Counter(str(item.get(key)) for item in rows)
    return dict(sorted(counts.items()))


def build(args: argparse.Namespace) -> dict[str, Any]:
    cold_path = args.halfyear_cold.resolve()
    warm_path = args.halfyear_warm.resolve()
    cross_dir = args.cross_version.resolve()
    truth_path = args.truth_manifest.resolve()
    holdout_path = args.holdout_manifest.resolve()
    output = args.out_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty: " + str(output))
    output.mkdir(parents=True, exist_ok=True)

    cold = load_json(cold_path)
    warm = load_json(warm_path)
    cross_summary = load_json(cross_dir / "run-summary.json")
    impact = load_json(cross_dir / "impact_evidence.json")
    accuracy = load_json(cross_dir / "accuracy_evaluation.json")
    truth = load_json(truth_path)
    holdout = load_json(holdout_path)
    review_verification_path = (
        ROOT / "research/evidence/cpp/review_20261014/verification.json"
    )
    review_verification = load_json(review_verification_path)

    cold_norm = normalized_halfyear(cold)
    warm_norm = normalized_halfyear(warm)
    controls = holdout.get("controls", [])
    control_counts = count_values(controls, "category")
    rows = impact["candidates"][0]["versions"]
    observation_counts = count_values(rows, "observation_relation")
    impact_counts = count_values(rows, "impact_status")

    dataset = {
        "schema_version": 1,
        "kind": "ohscanner.evaluation-dataset-gate.v1",
        "required_categories": ["vulnerable", "fixed", "safe", "unrelated"],
        "synthetic_control_category_counts": {
            name: control_counts.get(name, 0)
            for name in ("vulnerable", "fixed", "safe", "unrelated")
        },
        "controlled_mechanism_label_counts": truth.get(
            "controlled_mechanism_label_counts", {}
        ),
        "independent_holdout_count": holdout.get("holdout_candidate_count"),
        "development_count": holdout.get("development_candidate_count"),
        "holdout_leakage_checks": holdout.get("leakage_checks", {}),
        "truth_set_status": truth.get("truth_set_status"),
        "eligible_for_metrics": accuracy["eligible_for_metrics"],
        "published_counts": accuracy["counts"],
        "precision": accuracy["precision"],
        "recall": accuracy["recall"],
        "reasons": accuracy["reasons"],
        "interpretation": (
            "Synthetic vulnerable/fixed/safe/unrelated controls are retained as "
            "controls only. The independent holdout and truth set are separate. "
            "No Precision/Recall is published because the frozen real-truth gate "
            "is not eligible and predictions are incomplete."
        ),
    }
    dataset_path = output / "evaluation-dataset-manifest.json"
    write_json(dataset_path, dataset)

    invariance = {
        "schema_version": 1,
        "kind": "ohscanner.halfyear-scaling-invariance.v1",
        "status": (
            "proved"
            if cold_norm == warm_norm
            and cold["coverage_invariance"]["entry_digest"]
            == warm["coverage_invariance"]["entry_digest"]
            and cold["totals"] == warm["totals"]
            else "failed"
        ),
        "cold": {
            "path": cold_path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(cold_path),
            "shard_size": cold["coverage_invariance"]["shard_size"],
            "shard_count": cold["coverage_invariance"]["shard_count"],
            "entry_digest": cold["coverage_invariance"]["entry_digest"],
            "cache": cold["cache"],
            "performance": cold["performance"],
        },
        "warm": {
            "path": warm_path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(warm_path),
            "shard_size": warm["coverage_invariance"]["shard_size"],
            "shard_count": warm["coverage_invariance"]["shard_count"],
            "entry_digest": warm["coverage_invariance"]["entry_digest"],
            "cache": warm["cache"],
            "performance": warm["performance"],
        },
        "normalized_commit_projection_equal": cold_norm == warm_norm,
        "aggregate_totals_equal": cold["totals"] == warm["totals"],
        "cross_version": cross_summary["coverage_invariance"],
        "scope": (
            "Cold/warm half-year runs use different shard sizes and incremental "
            "cache state. Exact source manifests, coverage, candidate identities, "
            "candidate_count status and failure/unknown states are unchanged."
        ),
    }
    invariance_path = output / "coverage-invariance.json"
    write_json(invariance_path, invariance)

    key_artifacts = [
        artifact(cold_path, ROOT, "halfyear_json_cold"),
        artifact(cold_path.parent / "halfyear_candidates.md", ROOT, "halfyear_markdown_cold"),
        artifact(cold_path.parent / "manifest.json", ROOT, "halfyear_manifest_cold"),
        artifact(warm_path, ROOT, "halfyear_json_warm"),
        artifact(warm_path.parent / "halfyear_candidates.md", ROOT, "halfyear_markdown_warm"),
        artifact(warm_path.parent / "manifest.json", ROOT, "halfyear_manifest_warm"),
        artifact(cross_dir / "comparison-manifest.json", ROOT, "cross_version_comparison"),
        artifact(cross_dir / "impact_evidence.json", ROOT, "impact_evidence_json"),
        artifact(cross_dir / "impact_evidence.md", ROOT, "impact_evidence_markdown"),
        artifact(cross_dir / "boundary-regression.json", ROOT, "boundary_regression"),
        artifact(cross_dir / "performance.json", ROOT, "cross_version_performance"),
        artifact(cross_dir / "accuracy_evaluation.json", ROOT, "accuracy_evaluation"),
        artifact(dataset_path, ROOT, "evaluation_dataset_gate"),
        artifact(invariance_path, ROOT, "coverage_invariance"),
    ]
    manifest = {
        "schema_version": 1,
        "kind": "ohscanner.a-line-halfyear-cross-version-delivery.v1",
        "generated_date": "2026-10-16",
        "project_checkout": project_checkout(),
        "invocations": {
            "delivery_builder": {
                "argv": list(sys.argv),
                "argv_exact": True,
                "working_directory": str(Path.cwd()),
            },
            "halfyear_cold": cold.get("invocation", {}),
            "halfyear_warm": warm.get("invocation", {}),
            "cross_version": cross_summary.get("invocation", {}),
        },
        "target": {
            "repository": cold["repository"],
            "repository_path": cold["repository_path"],
            "window": cold["window"],
            "profile_id": cold["profile_id"],
            "detectors": cold["detectors"],
        },
        "cross_version": {
            "repository": impact["repository"],
            "version_range": impact["version_range"],
            "scope": impact["scope"],
            "candidate_count": len(impact["candidates"]),
            "observation_relation_counts": observation_counts,
            "impact_status_counts": impact_counts,
            "product_version_binding": impact["product_version_binding"],
        },
        "performance": {
            "halfyear_cold": cold["performance"],
            "halfyear_warm": warm["performance"],
            "cross_version": cross_summary["performance"],
        },
        "coverage": {
            "halfyear_cold_totals": cold["totals"],
            "halfyear_warm_totals": warm["totals"],
            "cross_version_invariance": cross_summary["coverage_invariance"],
            "scaling_invariance_status": invariance["status"],
        },
        "evaluation": dataset,
        "known_false_positive_risks": [
            {
                "item": "Historical shared_ptr candidate review",
                "count": review_verification["candidate_status_counts"].get(
                    "likely_false_positive", 0
                ),
                "boundary": (
                    "Candidate-level mechanism noise review; not a detector-wide "
                    "false-positive rate and not a safety result."
                ),
            },
            {
                "item": "Synthetic fixed/safe/unrelated controls",
                "count": sum(
                    control_counts.get(name, 0)
                    for name in ("fixed", "safe", "unrelated")
                ),
                "boundary": "Synthetic controls are not independent real-world truth.",
            },
        ],
        "known_false_negative_risks": [
            "Half-year MVP scans only changed source paths present in each selected commit tree.",
            "Six scanned commits retain partial coverage and eleven commits have unknown candidate_count.",
            "Macro, build-context, CFG, cross-function alias and indirect-call gaps can hide real root causes.",
            "A clean component control does not prove product safety or absence of other vulnerable mechanisms.",
        ],
        "unknowns": [
            "Product build applicability, entry/privilege/deployment boundary and CIA impact.",
            "Per-component multi-repo product version binding for the selected candidate.",
            "Reliable independent vulnerable/fixed/safe/unrelated holdout predictions sufficient for Precision/Recall.",
            "Child-process peak RSS; reported measured RSS covers the Python runner process.",
            "CWE/CVE confirmation and reportable product vulnerability status.",
        ],
        "next_steps": [
            "Run frozen R0/R1/R2 only after model/tool/data-processing authorization and bind exact versions and budgets.",
            "Collect product build, per-component SHAs, entry/privilege traces, CIA evidence and patch revalidation.",
            "Execute the independent holdout and publish root-cause TP/FP/FN only for reliable complete truth.",
            "Measure child-process RSS and rerun coverage invariance before any source-scope expansion.",
        ],
        "artifacts": key_artifacts,
        "limitations": [
            "Zero findings is not proof of safety.",
            "Model or rule self-evaluation is never ground truth.",
            "Commit time and first-parent topology are not vulnerability propagation proof.",
            "added/persistent/disappeared are candidate observation relations, not affected/fixed/not_present impact states.",
        ],
    }
    manifest_path = output / "delivery-manifest.json"
    write_json(manifest_path, manifest)

    lines = [
        "# A-line half-year and cross-version delivery",
        "",
        "> Candidate-level evidence only; no confirmed/reportable product vulnerability.",
        "",
        f"- Project HEAD: `{manifest['project_checkout']['head']}`",
        f"- Target: `{cold['repository']}`",
        f"- Half-year scaling invariance: `{invariance['status']}`",
        f"- Cross-version coverage invariance: `{cross_summary['coverage_invariance']['status']}`",
        f"- Accuracy gate: `{accuracy['status']}`",
        f"- Precision / Recall: `{accuracy['precision']}` / `{accuracy['recall']}`",
        f"- Observation relations: `{json.dumps(observation_counts, sort_keys=True)}`",
        f"- Impact evidence: `{json.dumps(impact_counts, sort_keys=True)}`",
        "",
        "## Performance",
        "",
        f"- Half-year cold wall / peak RSS: `{cold['performance']['resource_monitor']['wall_seconds']}` / "
        f"`{cold['performance']['resource_monitor']['peak_rss_bytes']}` bytes",
        f"- Half-year warm wall / peak RSS: `{warm['performance']['resource_monitor']['wall_seconds']}` / "
        f"`{warm['performance']['resource_monitor']['peak_rss_bytes']}` bytes",
        f"- Cross-version wall / peak RSS: `{cross_summary['performance']['wall_seconds']}` / "
        f"`{cross_summary['performance']['peak_rss_bytes']}` bytes",
        f"- Half-year source files / bytes / lines: "
        f"`{cold['performance']['files']['scanned_source_files']}` / "
        f"`{cold['performance']['files']['source_bytes']}` / "
        f"`{cold['performance']['files']['source_lines']}`",
        "",
        "## Accuracy boundary",
        "",
        dataset["interpretation"],
        "",
        "## Known risks",
        "",
    ]
    lines.extend(
        "- FP risk: " + item["item"] + " (" + str(item["count"]) + ")"
        for item in manifest["known_false_positive_risks"]
    )
    lines.extend("- FN risk: " + item for item in manifest["known_false_negative_risks"])
    lines.extend("- Unknown: " + item for item in manifest["unknowns"])
    lines.extend(["", "## Next steps", ""])
    lines.extend("- " + item for item in manifest["next_steps"])
    lines.append("")
    (output / "delivery.md").write_text("\n".join(lines), encoding="utf-8")

    final_manifest = {
        "schema_version": 1,
        "kind": "ohscanner.a-line-delivery-artifact-manifest.v1",
        "files": {
            path.name: {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "artifact-manifest.json"
        },
    }
    write_json(output / "artifact-manifest.json", final_manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--halfyear-cold",
        type=Path,
        default=ROOT / "outputs/reports/halfyear_candidate_mvp_commonlibrary_20261016_v6/halfyear_candidates.json",
    )
    parser.add_argument(
        "--halfyear-warm",
        type=Path,
        default=ROOT / "outputs/reports/halfyear_candidate_mvp_commonlibrary_20261016_v6_cache/halfyear_candidates.json",
    )
    parser.add_argument(
        "--cross-version",
        type=Path,
        default=ROOT / "outputs/reports/cross_version_impact_delayed_singleton_20261016_v4",
    )
    parser.add_argument(
        "--truth-manifest",
        type=Path,
        default=ROOT / "research/evidence/cpp/independent_truth_review_20261015/truth_set_manifest.json",
    )
    parser.add_argument(
        "--holdout-manifest",
        type=Path,
        default=ROOT / "research/evidence/cpp/review_20261014/holdout_manifest.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "outputs/reports/a_line_halfyear_cross_version_delivery_20261016",
    )
    args = parser.parse_args()
    manifest = build(args)
    print(json.dumps({
        "status": "completed",
        "output": str(args.out_dir.resolve()),
        "scaling_invariance": manifest["coverage"]["scaling_invariance_status"],
        "accuracy_status": manifest["evaluation"]["eligible_for_metrics"],
        "argv": list(sys.argv),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()