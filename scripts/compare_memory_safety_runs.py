"""Compare two a_memory_safety_scan evidence runs without interpreting accuracy."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path


DEFAULT_OLD = "ea7d13a69852d5e639e090671b040f7dcd32eebc"


def old_json(repo: Path, commit: str, path: str):
    raw = subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{path}"])
    return json.loads(raw)


def rule_counts(report) -> Counter[str]:
    counts: Counter[str] = Counter()
    for run in report["detector_runs"]:
        for finding in run["findings"]:
            counts[f'{run["detector_id"]}|{finding["rule_id"]}'] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--old-commit", default=DEFAULT_OLD)
    parser.add_argument("--current-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    base = "research/evidence/cpp/a_memory_safety_scan_20261017"
    old_summary = old_json(args.repo, args.old_commit, f"{base}/summary.json")
    new_summary = json.loads((args.current_dir / "summary.json").read_text(encoding="utf-8"))
    old_rules: Counter[str] = Counter()
    new_rules: Counter[str] = Counter()
    components = []
    for old_row in old_summary["components"]:
        name = old_row["component"]
        old_report = old_json(args.repo, args.old_commit, f"{base}/{name}.json")
        new_report = json.loads((args.current_dir / f"{name}.json").read_text(encoding="utf-8"))
        old_rules.update(rule_counts(old_report))
        new_rules.update(rule_counts(new_report))
        new_row = next(item for item in new_summary["components"] if item["component"] == name)
        components.append({
            "component": name,
            "old_candidates": old_row["candidate_count"],
            "new_candidates": new_row["candidate_count"],
            "delta": new_row["candidate_count"] - old_row["candidate_count"],
        })
    report = {
        "schema_version": 1,
        "experiment_kind": "a_memory_safety_old_new_comparison",
        "old_commit": args.old_commit,
        "old_totals": old_summary["totals"],
        "new_totals": new_summary["totals"],
        "components": components,
        "rules": [
            {
                "detector_rule": key,
                "old": old_rules[key],
                "new": new_rules[key],
                "delta": new_rules[key] - old_rules[key],
            }
            for key in sorted(set(old_rules) | set(new_rules))
        ],
        "interpretation": [
            "Candidate delta measures detector coverage and lexical grouping changes only.",
            "It is not an accuracy improvement, vulnerability count, or Precision/Recall estimate.",
        ],
    }
    (args.out_dir / "comparison.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    old_totals = old_summary["totals"]
    new_totals = new_summary["totals"]
    lines = [
        "# A memory-safety old/new comparison",
        "",
        f"Old commit: `{args.old_commit}`",
        "",
        "| Metric | Old | New | Delta |",
        "|---|---:|---:|---:|",
        f"| Candidates | {old_totals['candidate_count']} | {new_totals['candidate_count']} | {new_totals['candidate_count'] - old_totals['candidate_count']} |",
        f"| Lexical groups | {old_totals['candidate_groups']} | {new_totals['candidate_groups']} | {new_totals['candidate_groups'] - old_totals['candidate_groups']} |",
        f"| Wall s | {old_totals['wall_seconds']:.3f} | {new_totals['wall_seconds']:.3f} | {new_totals['wall_seconds'] - old_totals['wall_seconds']:.3f} |",
        "",
        "## Interpretation",
        "",
        "- Candidate delta measures coverage and grouping changes only.",
        "- It is not an accuracy improvement, vulnerability count, or Precision/Recall estimate.",
    ]
    (args.out_dir / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
