from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

ROOT = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit")
REPORT_ROOT = ROOT / "outputs/reports/third_party_high_risk_20261016"
TARGETS = {
    "third_party_cJSON": {
        "commit": "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748",
        "risk_basis": "JSON parser/printer with historical memory-safety exposure",
        "text_scope": "text_core",
    },
    "third_party_curl": {
        "commit": "1386bb128bb060b284309397b97adcaaec21c003",
        "risk_basis": "network protocol parser and transfer engine",
        "text_scope": "text_lib",
    },
    "third_party_sqlite": {
        "commit": "34478e73d5a6d22237edacea92b331fb76127982",
        "risk_basis": "SQL parser and storage engine",
        "text_scope": "text_src",
    },
    "third_party_zlib": {
        "commit": "0a0c45d7e478826b59e67cc613be3e4b6957432c",
        "risk_basis": "compression/decompression and minizip archive parsing",
        "text_scope": "text_minizip",
    },
}

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

targets = []
for name, meta in TARGETS.items():
    research_path = REPORT_ROOT / name / "report.json"
    research = json.loads(research_path.read_text(encoding="utf-8"))
    null_run = next(
        row for row in research["detector_runs"]
        if row["tool"] == "ohscanner.cpp.null_dereference"
    )
    messages = [row["message"] for row in null_run["diagnostics"]]
    high_signal = sum(
        "guard_relation=not_dominating" in message
        or "error_path=error_branch_falls_through" in message
        for message in messages
    )
    text_path = REPORT_ROOT / name / meta["text_scope"] / "report.json"
    text = json.loads(text_path.read_text(encoding="utf-8"))
    rule_counts = {}
    for row in text["findings"]:
        rule_counts[row["rule_id"]] = rule_counts.get(row["rule_id"], 0) + 1
    targets.append({
        "repository": research["repository"],
        "commit": meta["commit"],
        "risk_basis": meta["risk_basis"],
        "source_files": research["scope"]["selected_source_files"],
        "source_bytes": research["scope"]["selected_source_bytes"],
        "research_null_dereference": {
            "status": null_run["status"],
            "coverage": research["detector_coverage"]["detectors"]["ohscanner.cpp.null_dereference"]["status"],
            "candidate_observations": null_run["diagnostic_count"],
            "higher_signal_subset": high_signal,
            "report": str(research_path),
            "report_sha256": sha256(research_path),
        },
        "legacy_text_dangerous_calls": {
            "status": "research_only",
            "candidate_observations": text["finding_count"],
            "rule_counts": dict(sorted(rule_counts.items())),
            "report": str(text_path),
            "report_sha256": sha256(text_path),
        },
    })

summary = {
    "schema_version": 1,
    "kind": "ohscanner.third-party-high-risk-research-summary-v1",
    "generated": "2026-10-16 Asia/Shanghai",
    "clone_root": "/mnt/e/网安/_third_party_targets_20261016",
    "targets": targets,
    "packaging_targets_not_source_scanned": [
        {
            "repository": "openharmony/third_party_libxml2",
            "commit": "805b206067cdf3cfcd9ba64cde09daad9614c215",
            "reason": "OpenHarmony repository stores the upstream source as libxml2-2.14.0.tar.xz plus CVE patches; no tracked C source tree was scanned.",
        },
        {
            "repository": "openharmony/third_party_libjpeg-turbo",
            "commit": "a56aa6aaf4801fad9a753eec912174fce2fd1838",
            "reason": "OpenHarmony repository stores an upstream tarball plus patches; only four wrapper/configuration C/H files are directly tracked.",
        },
    ],
    "totals": {
        "source_files_research_scan": sum(row["source_files"] for row in targets),
        "research_null_candidate_observations": sum(
            row["research_null_dereference"]["candidate_observations"] for row in targets
        ),
        "research_null_higher_signal_subset": sum(
            row["research_null_dereference"]["higher_signal_subset"] for row in targets
        ),
        "legacy_text_candidate_observations": sum(
            row["legacy_text_dangerous_calls"]["candidate_observations"] for row in targets
        ),
        "validated_vulnerabilities": 0,
        "confirmed": 0,
        "reportable": 0,
    },
    "catalog_boundary": {
        "ohscanner.cpp.null_dereference": "research-only; public_catalog_registration=false",
        "legacy_text_engine": "candidate-pattern baseline, not source-bound first-party schema v2",
    },
    "limitations": [
        "All observations remain candidate/unassessed; no CVE or product impact is established.",
        "The null detector treats many pointer parameters as may-be-null and produced high-volume noise on third-party C code.",
        "The text engine only recognizes strcpy/strcat/sprintf/gets/memcpy-shaped calls and does not prove bounds, reachability or impact.",
        "libxml2 and libjpeg-turbo source archives were not unpacked or converted into synthetic Git provenance.",
    ],
}
json_path = REPORT_ROOT / "summary.json"
json_path.write_text(
    json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
lines = [
    "# Third-party high-risk research scan summary",
    "",
    "> Candidate-pattern research only; validated vulnerabilities: 0.",
    "",
    "| Repository | Source files | NULL candidates | Higher-signal subset | Text dangerous-call candidates |",
    "|---|---:|---:|---:|---:|",
]
for row in targets:
    lines.append(
        f"| `{row['repository']}` | {row['source_files']} | "
        f"{row['research_null_dereference']['candidate_observations']} | "
        f"{row['research_null_dereference']['higher_signal_subset']} | "
        f"{row['legacy_text_dangerous_calls']['candidate_observations']} |"
    )
lines += [
    "",
    "## Boundary",
    "",
    "- `ohscanner.cpp.null_dereference` is research-only and not registered in the public catalog.",
    "- The text engine is a dangerous-call candidate baseline, not a vulnerability verdict.",
    "- Packaging repositories `third_party_libxml2` and `third_party_libjpeg-turbo` require archive extraction and explicit synthetic provenance before scanning.",
    "- No result is confirmed/reportable; all candidates retain evidence obligations.",
]
md_path = REPORT_ROOT / "summary.md"
md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(json.dumps({
    "json": str(json_path),
    "json_sha256": sha256(json_path),
    "markdown": str(md_path),
    "markdown_sha256": sha256(md_path),
    "totals": summary["totals"],
}, ensure_ascii=False, indent=2))
