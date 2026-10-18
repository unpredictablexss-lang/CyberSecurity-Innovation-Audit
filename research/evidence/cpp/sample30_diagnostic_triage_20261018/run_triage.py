#!/usr/bin/env python3
"""Aggregate the delivered sample30 diagnostics by repository/rule/member.

This reads only the committed sandbox manifest; it does not need the 30 pinned
source roots and does not produce new findings. Counts are access-point
diagnostics, not root causes, vulnerabilities or Precision/Recall.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "research"
    / "deliveries"
    / "a-line-sample30"
    / "20261018"
    / "evidence"
    / "sample_manifest.json"
)


def _operation(message: str) -> str:
    if "member write" in message:
        return "write"
    if "member read" in message:
        return "read"
    return "other"


def _aggregate(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    groups: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    totals_by_rule: Counter = Counter()
    samples_without_diagnostics = 0
    diagnostic_total = 0
    for record in records:
        diagnostics = record.get("diagnostics", [])
        if not diagnostics:
            samples_without_diagnostics += 1
        for item in diagnostics:
            diagnostic_total += 1
            rule = item["rule_id"]
            totals_by_rule[rule] += 1
            key = (
                record["repository"],
                rule,
                item["file"],
                item.get("symbol") or "<none>",
            )
            group = groups.setdefault(key, {
                "repository": key[0],
                "rule_id": rule,
                "file": key[2],
                "symbol": key[3],
                "count": 0,
                "reads": 0,
                "writes": 0,
                "other": 0,
                "detector_versions": set(),
                "samples": set(),
            })
            group["count"] += 1
            operation = _operation(item.get("message", ""))
            group[
                "reads" if operation == "read"
                else "writes" if operation == "write"
                else "other"
            ] += 1
            version = item.get("detector_version")
            if version:
                group["detector_versions"].add(version)
            group["samples"].add(record["sample_order"])
    rows = []
    for key in sorted(groups):
        group = groups[key]
        rows.append({
            **{name: group[name] for name in (
                "repository", "rule_id", "file", "symbol", "count",
                "reads", "writes", "other",
            )},
            "detector_versions": sorted(group["detector_versions"]),
            "samples": sorted(group["samples"]),
        })
    by_rule_groups = Counter(item["rule_id"] for item in rows)
    return {
        "samples": len(records),
        "samples_without_diagnostics": samples_without_diagnostics,
        "diagnostic_total": diagnostic_total,
        "by_rule": dict(sorted(totals_by_rule.items())),
        "member_groups_by_rule": dict(sorted(by_rule_groups.items())),
        "member_groups": rows,
    }


def _write_markdown(summary: Dict[str, Any], path: Path) -> None:
    lines = [
        "# sample30 diagnostic triage (2026-10-18)",
        "",
        "> Delivered diagnostics only; counts are access points, not root causes,",
        "> vulnerabilities or Precision/Recall. Class identity needs the pinned sources.",
        "",
        f"- Samples: {summary['samples']} "
        f"({summary['samples_without_diagnostics']} without diagnostics)",
        f"- Diagnostics: {summary['diagnostic_total']}",
        "",
        "| Rule | Diagnostics | Repository/file/member groups |",
        "|---|---:|---:|",
    ]
    for rule, count in summary["by_rule"].items():
        lines.append(
            f"| `{rule}` | {count} | "
            f"{summary['member_groups_by_rule'].get(rule, 0)} |"
        )
    lines.extend(["", "## Top groups", ""])
    for item in sorted(
        summary["member_groups"], key=lambda row: (-row["count"], row["file"])
    )[:20]:
        lines.append(
            f"- `{item['repository']}` `{item['file']}` `{item['symbol']}`: "
            f"{item['count']} diagnostic(s), reads={item['reads']}, "
            f"writes={item['writes']}, samples={item['samples']}"
        )
    lines.extend([
        "",
        "## Boundary",
        "",
        "- The 30 pinned source roots are not present locally; no rerun is claimed.",
        "- Grouping uses repository/file/symbol because the delivered diagnostics",
        "  do not carry qualified class identity.",
        "- Candidate counts are not vulnerability counts; `validated_vulnerability=0`.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    records = manifest["records"]
    summary = {
        "schema_version": 1,
        "experiment_kind": "a_line_sample30_delivered_diagnostic_triage",
        "status": "completed_with_limitations",
        "source_manifest": str(args.manifest.relative_to(PROJECT_ROOT)),
        "source_manifest_sha256": __import__("hashlib").sha256(
            args.manifest.read_bytes()
        ).hexdigest(),
        **_aggregate(records),
        "validated_vulnerability": 0,
        "eligible_for_metrics": False,
        "limitations": [
            "Delivered diagnostics only; no pinned-source rerun was performed.",
            "Groups are repository/file/symbol shapes, not qualified class/member roots.",
            "Counts are not vulnerabilities and no Precision/Recall is computed.",
        ],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    _write_markdown(summary, args.out_dir / "triage.md")
    print("diagnostics=" + str(summary["diagnostic_total"]))
    print("rules=" + ",".join(summary["by_rule"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
