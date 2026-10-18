"""Verify D41 frozen replays and prepare a prediction-blinded review packet."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

from d19_unreviewed_replay import pinned_source_paths

DETECTOR = "ohscanner.data.sensitive_exposure"
ENGINE_PATHS = (
    "src/ohscanner/detectors/data/sensitive_exposure.py",
    "src/ohscanner/detectors/data/models.py",
    "src/ohscanner/execution.py",
    "src/ohscanner/runner.py",
    "src/ohscanner/git_source.py",
    "src/ohscanner/indexing.py",
    "requirements.txt",
    "requirements-web.txt",
)
SEED = "D41-review-packet-20261019-v1"
CANDIDATE_SAMPLE_PER_REPO = 8
CONTROL_SAMPLE_PER_REPO = 10


def git(repo: Path, *args: str, binary: bool = False):
    result = subprocess.check_output(["git", "-C", str(repo), *args], text=not binary)
    return result if binary else result.strip()


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def signature(report: dict):
    run = next(item for item in report.get("detector_runs", []) if item.get("tool") == DETECTOR)
    rows = []
    for finding in run.get("diagnostics", []):
        rows.append((
            finding.get("file"), finding.get("line"), finding.get("rule_id"),
            finding.get("diagnostic_id"), finding.get("source_sha256"),
            json.dumps(finding.get("evidence_obligations", []), sort_keys=True),
        ))
    return sorted(rows)


def digest_key(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitcode-corpus-root", type=Path, required=True)
    parser.add_argument("--perf-corpus-root", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--review-packet", type=Path, required=True)
    parser.add_argument("--review-key", type=Path, default=Path("/tmp/D41_HOLDOUT_REVIEW_KEY.json"))
    args = parser.parse_args()

    checkout = Path(__file__).resolve().parents[2]
    manifest = read_json(checkout / "research/data_sensitive/D41_HOLDOUT_MANIFEST.json")
    bundle = hashlib.sha256()
    for rel in ENGINE_PATHS:
        data = (checkout / rel).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        expected = next(item["sha256"] for item in manifest["engine_files"] if item["path"] == rel)
        if actual != expected:
            raise SystemExit("frozen detector/runtime hash drift: " + rel)
        bundle.update(rel.encode("utf-8") + b"\0" + bytes.fromhex(actual))
    if bundle.hexdigest() != manifest["engine_bundle_sha256"]:
        raise SystemExit("frozen detector/runtime bundle hash drift")

    rows = []
    all_candidate_cases = []
    control_pools = []
    for repo_row in manifest["repositories"]:
        alias = repo_row["source_alias"]
        root = args.gitcode_corpus_root if alias.startswith("gitcode-corpus/") else args.perf_corpus_root
        source_repo = (root / alias.split("/", 1)[1]).resolve(strict=True)
        commit = repo_row["commit"]
        if git(source_repo, "status", "--porcelain"):
            raise SystemExit("source checkout became dirty after freeze: " + repo_row["repository"])
        if git(source_repo, "rev-parse", commit + "^{tree}") != repo_row["tree"]:
            raise SystemExit("frozen source tree mismatch: " + repo_row["repository"])

        output_dir = checkout / "research/data_sensitive/D41_HOLDOUT" / repo_row["repository"].split("/", 1)[1]
        first = read_json(output_dir / "first.json")
        replay = read_json(output_dir / "replay.json")
        summary = read_json(output_dir / "summary.json")
        if (first.get("git_tree") != repo_row["tree"] or replay.get("git_tree") != repo_row["tree"]
                or first.get("snapshot_sha256") != replay.get("snapshot_sha256")
                or signature(first) != signature(replay)
                or first.get("detector_coverage") != replay.get("detector_coverage")
                or summary.get("same_scope_replay_equal") is not True
                or summary.get("commit") != commit
                or summary.get("detector_version") != manifest["detector_version"]):
            raise SystemExit("D41 replay verification failed: " + repo_row["repository"])

        run = next(item for item in first["detector_runs"] if item["tool"] == DETECTOR)
        coverage = first["detector_coverage"]["detectors"][DETECTOR]
        findings = run.get("diagnostics", [])
        rules = Counter(item.get("rule_id", "unknown") for item in findings)
        cwes = Counter(item.get("candidate_cwe") or "none" for item in findings)
        rows.append({
            "repository": repo_row["repository"],
            "commit": commit,
            "tree": repo_row["tree"],
            "scope_files": repo_row["eligible_source_files"],
            "snapshot_sha256": first["snapshot_sha256"],
            "detector_status": run["status"],
            "task_status": first.get("status"),
            "candidate_count": len(findings),
            "candidate_rule_counts": dict(sorted(rules.items())),
            "candidate_cwe_counts": dict(sorted(cwes.items())),
            "coverage_counts": coverage.get("coverage_counts", {}),
            "same_scope_replay_equal": True,
            "report_sha256": {
                name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
                for name in ("first.json", "replay.json", "summary.json")
            },
            "two_run_seconds": summary.get("wall_seconds_two_runs"),
            "peak_rss_kib": summary.get("peak_rss_kib"),
            "validated_vulnerability": first.get("validated_vulnerability"),
        })
        hit_files = {item["file"] for item in findings}
        for finding in findings:
            all_candidate_cases.append((repo_row, finding, source_repo))
        paths = pinned_source_paths(source_repo, commit)
        controls = [path for path in paths if path not in hit_files]
        control_pools.append((repo_row, source_repo, controls))

    all_counts = Counter()
    all_rules = Counter()
    all_cwes = Counter()
    for row in rows:
        all_counts.update(row["coverage_counts"])
        all_rules.update(row["candidate_rule_counts"])
        all_cwes.update(row["candidate_cwe_counts"])
    result = {
        "schema": 1,
        "study": manifest["study"],
        "state": "replayed_pending_independent_review",
        "preregistration_commit": git(checkout, "log", "-1", "--format=%H", "e33dc02"),
        "detector_baseline_commit": manifest["detector_baseline_commit"],
        "detector_id": DETECTOR,
        "detector_version": manifest["detector_version"],
        "engine_bundle_sha256": manifest["engine_bundle_sha256"],
        "component_count": len(rows),
        "scope_file_count": sum(item["scope_files"] for item in rows),
        "total_candidate_count": sum(item["candidate_count"] for item in rows),
        "candidate_rule_counts": dict(sorted(all_rules.items())),
        "candidate_cwe_counts": dict(sorted(all_cwes.items())),
        "aggregate_coverage_counts": dict(sorted(all_counts.items())),
        "components_with_stable_replays": sum(item["same_scope_replay_equal"] for item in rows),
        "independent_labels": {
            "supported_risk": 0, "protected_safe": 0, "unrelated": 0, "unknown": 0,
            "status": "pending_external_independent_review",
        },
        "validated_vulnerability": 0,
        "components": rows,
        "limits": [
            "All 201 machine observations are unresolved-escape candidates, not CWE findings or vulnerabilities.",
            "All six DetectorRuns are blocked; zero files were fully analyzed, so not analyzed/partial areas remain unknown.",
            "Repeatability is not accuracy. No TP/FP/FN/recall/precision claim is possible before independent labels.",
            "No product build, logging configuration, unauthorized reader, impact, or product fix retest was evaluated.",
        ],
    }
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    sample_entries = []
    key_entries = []
    for repo_row, finding, source_repo in all_candidate_cases:
        key = digest_key(SEED, repo_row["repository"], finding["file"], str(finding["line"]), finding["diagnostic_id"])
        sample_entries.append({
            "case_id": "D41-" + key[:12],
            "repository": repo_row["repository"],
            "commit": repo_row["commit"],
            "tree": repo_row["tree"],
            "file": finding["file"],
            "anchor_line": finding["line"],
            "source_sha256": finding["source_sha256"],
        })
        key_entries.append({
            "case_id": "D41-" + key[:12],
            "selection_origin": "scanner_observation",
            "diagnostic_id": finding["diagnostic_id"],
            "rule_id": finding["rule_id"],
        })

    selected_candidates = []
    for repo_row in manifest["repositories"]:
        candidates = [item for item in all_candidate_cases if item[0]["repository"] == repo_row["repository"]]
        candidates.sort(key=lambda item: digest_key(SEED, item[0]["repository"], item[1]["diagnostic_id"]))
        selected_candidates.extend(candidates[:min(CANDIDATE_SAMPLE_PER_REPO, len(candidates))])
    selected_keys = {
        "D41-" + digest_key(SEED, row["repository"], finding["file"], str(finding["line"]), finding["diagnostic_id"])[:12]
        for row, finding, _ in selected_candidates
    }
    sample_entries = [entry for entry in sample_entries if entry["case_id"] in selected_keys]
    key_entries = [entry for entry in key_entries if entry["case_id"] in selected_keys]

    for repo_row, source_repo, controls in control_pools:
        ranked = sorted(controls, key=lambda path: digest_key(SEED, repo_row["repository"], "control", path))
        selected = ranked[:min(CONTROL_SAMPLE_PER_REPO, len(ranked))]
        for path in selected:
            source = git(source_repo, "show", repo_row["commit"] + ":" + path, binary=True)
            lines = source.decode("utf-8", errors="replace").splitlines()
            nonblank = [index + 1 for index, line in enumerate(lines) if line.strip()]
            if not nonblank:
                continue
            anchor = nonblank[int(digest_key(SEED, repo_row["repository"], path, "line")[:8], 16) % len(nonblank)]
            source_sha = hashlib.sha256(source).hexdigest()
            key = digest_key(SEED, repo_row["repository"], path, str(anchor), "control")
            sample_entries.append({
                "case_id": "D41-" + key[:12],
                "repository": repo_row["repository"],
                "commit": repo_row["commit"],
                "tree": repo_row["tree"],
                "file": path,
                "anchor_line": anchor,
                "source_sha256": source_sha,
            })
            key_entries.append({
                "case_id": "D41-" + key[:12],
                "selection_origin": "post-scan_random_noncandidate_file_control",
                "diagnostic_id": None,
                "rule_id": None,
            })

    sample_entries.sort(key=lambda item: digest_key(SEED, item["case_id"], "shuffle"))
    packet = {
        "schema": 1,
        "title": "D41 blind source review packet",
        "state": "pending_independent_labels",
        "source_commit_manifest": "D41_HOLDOUT_MANIFEST.json",
        "candidate_sample_per_repo_max": CANDIDATE_SAMPLE_PER_REPO,
        "control_sample_per_repo_max": CONTROL_SAMPLE_PER_REPO,
        "case_count": len(sample_entries),
        "independent_labeler_required": True,
        "review_labels": ["supported_risk", "protected_safe", "unrelated", "unknown"],
        "review_instructions": [
            "Do not edit the detector or model before labeling.",
            "Inspect the exact file from the listed commit and verify the listed file SHA-256.",
            "Record line-bound evidence for a sensitive source, flow, and output/sink plus supporting and contradicting controls.",
            "Use unknown for insufficient type, control-flow, build, or log-reader evidence; no case is a confirmed product vulnerability by packet inclusion.",
            "This stratified review packet is sampled after the static scan and is not a population accuracy estimate; it supports manual case review only.",
        ],
        "cases": sample_entries,
    }
    args.review_packet.parent.mkdir(parents=True, exist_ok=True)
    args.review_packet.write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.review_key.parent.mkdir(parents=True, exist_ok=True)
    args.review_key.write_text(json.dumps({
        "schema": 1, "seed": SEED, "warning": "Keep separate from reviewers until labels are frozen.",
        "cases": sorted(key_entries, key=lambda item: item["case_id"]),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "components": len(rows),
        "files": result["scope_file_count"],
        "candidates": result["total_candidate_count"],
        "coverage": result["aggregate_coverage_counts"],
        "review_packet_cases": len(sample_entries),
        "independent_labels": 0,
        "state": result["state"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())