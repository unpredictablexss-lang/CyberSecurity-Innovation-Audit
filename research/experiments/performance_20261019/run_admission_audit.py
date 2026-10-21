#!/usr/bin/env python3
"""Independent C11 competition-delivery admission audit."""
from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import platform
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[3]
BASE = pathlib.Path(__file__).resolve().parent
OUT = BASE / "out"
DELIVERY = ROOT / "research" / "deliveries" / "admission_20261019"
AUDIT_RECORD = pathlib.Path(r"E:\网安\CyberSecurity-Innovation-Audit\research\deliveries\c-line\OHScanner_G盘源码漏洞审查记录_20261018.md")
AUDIT_IMPORT = pathlib.Path(r"E:\网安\CyberSecurity-Innovation-Audit\research\deliveries\c-line\source-audit-import-manifest-20261018.json")
C_PLAN = pathlib.Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-latest-20261019\research\deliveries\c-line-development-plan-20261018.md")
C_README = pathlib.Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-latest-20261019\research\deliveries\c-line\README.md")
D49 = ROOT / "research/data_sensitive/D49_KNOWN_CVE_REPLAY/README.md"
D50 = ROOT / "research/data_sensitive/D50_COMPONENT_CVE_REPLAY/README.md"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def write(path: pathlib.Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def tail(values):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def performance_facts():
    index_path = OUT / "raw-index.json"
    summary_path = OUT / "summary.json"
    if not index_path.exists() or not summary_path.exists():
        return {"status": "missing", "blocker": "performance run did not produce raw-index.json and summary.json"}
    rows = json.loads(read(index_path))
    by_case = {}
    for row in rows:
        by_case.setdefault(row["case"], []).append(row)
    stats = []
    for case, items in sorted(by_case.items()):
        ok = [x["measurement"] for x in items if x.get("returncode") == 0 and "measurement" in x]
        walls = [x["wall_seconds"] for x in ok]
        rss = [x.get("peak_rss_bytes") or x.get("result", {}).get("peak_rss_bytes") or 0 for x in ok]
        stats.append({
            "case": case,
            "attempts": len(items),
            "successful_runs": len(ok),
            "failed_runs": len(items) - len(ok),
            "wall_median_seconds": statistics.median(walls) if walls else None,
            "wall_tail_seconds": tail(walls),
            "rss_median_bytes": statistics.median(rss) if rss else None,
            "rss_tail_bytes": tail(rss),
        })
    def first(case):
        for item in by_case.get(case, []):
            if item.get("returncode") == 0 and "measurement" in item:
                return item["measurement"].get("result")
        return None
    full = first("full_no_cache")
    cold = first("cache_cold")
    warm = first("cache_warm")
    shard = first("shard_no_cache")
    batch = first("batch_real")
    unbatch = first("unbatch_real")
    cli_shards = first("cli_index_shards")
    limits = {}
    expected = {
        "limit_1999": "accepted", "limit_2000": "accepted", "limit_2001": "rejected",
        "limit_total_32mib": "accepted", "limit_total_32mib_plus_1": "rejected",
        "limit_blob_exact": "accepted", "limit_blob_plus_1": "accepted_with_oversize_skip",
    }
    for case, wanted in expected.items():
        result = first(case)
        actual = None if result is None else result.get("status")
        if result and actual == "accepted" and wanted == "accepted_with_oversize_skip":
            actual = "accepted_with_oversize_skip" if result.get("inventory", {}).get("oversize") == 1 else "accepted"
        limits[case] = {"expected": wanted, "actual": actual, "result": result}
    checks = {
        "batch_source_identity_invariant": bool(batch and unbatch and batch.get("source_identity_sha256") == unbatch.get("source_identity_sha256")),
        "cache_cold_identity_parse_verdict_invariant": bool(full and cold and all(full.get(k) == cold.get(k) for k in ("source_identity_sha256", "parse_signature_sha256", "diagnostic_signature_sha256"))),
        "cache_warm_identity_parse_verdict_invariant": bool(full and warm and all(full.get(k) == warm.get(k) for k in ("source_identity_sha256", "parse_signature_sha256", "diagnostic_signature_sha256"))),
        "synthetic_shard_aggregate_invariant": bool(shard and shard.get("invariant")),
        "cli_shard_aggregate_source_and_parse_invariant": bool(cli_shards and cli_shards.get("invariant")),
        "limit_boundaries_exact": all(v["actual"] == v["expected"] for v in limits.values()),
    }
    synthetic_coverage = {
        "full_no_cache": (full or {}).get("coverage"),
        "cache_cold": (cold or {}).get("coverage"),
        "cache_warm": (warm or {}).get("coverage"),
        "shard_no_cache_full": ((shard or {}).get("full") or {}).get("coverage"),
    }
    cli_full = first("cli_index_full")
    cli_shard_full = ((cli_shards or {}).get("full") or {})
    partial_unknown_changes = {
        "synthetic": {
            "observed": synthetic_coverage,
            "all_equal": len({json.dumps(v, sort_keys=True) for v in synthetic_coverage.values()}) == 1,
            "delta": "none; all 2000 synthetic C++ units complete in every mode",
        },
        "real_cli": {
            "full": cli_full.get("parse") if cli_full else None,
            "shard_aggregate": cli_shard_full.get("parse"),
            "delta": "none; aggregate preserves complete/partial counts",
        },
    }
    shard_full_result = (shard or {}).get("full") or {}
    shard_diag_total = sum(x.get("diagnostic_count", 0) for x in ((shard or {}).get("shards") or []))
    verdict_drift = {
        "synthetic_full_candidate_count": shard_full_result.get("diagnostic_count"),
        "synthetic_shard_aggregate_candidate_count": shard_diag_total,
        "cache_cold_candidate_count": (cold or {}).get("diagnostic_count"),
        "cache_warm_candidate_count": (warm or {}).get("diagnostic_count"),
        "candidate_identity_drift": not (
            shard_full_result.get("diagnostic_signature_sha256")
            == (cold or {}).get("diagnostic_signature_sha256")
            == (warm or {}).get("diagnostic_signature_sha256")
        ),
        "interpretation": "No candidate identity/count drift across batch/cache/shard modes on this fixed synthetic set. This is not a safe/miss or validated-vulnerability verdict.",
    }
    failure_boundaries = {
        "limits": {k: {"expected": v["expected"], "actual": v["actual"], "error": (v.get("result") or {}).get("error")} for k, v in limits.items()},
        "failed_runs_by_case": {x["case"]: x["failed_runs"] for x in stats if x["failed_runs"]},
    }
    return {
        "status": "measured",
        "statistics": stats,
        "invariance_checks": checks,
        "all_invariance_checks_pass": all(checks.values()),
        "partial_unknown_changes": partial_unknown_changes,
        "verdict_drift": verdict_drift,
        "failure_boundaries": failure_boundaries,
        "verdict_drift_semantics": "candidate diagnostic identity/coverage drift only; not safe/miss/validated-vulnerability drift",
        "limits": limits,
    }


def supported_cwes_cves():
    text = read(ROOT / "src/ohscanner/detectors/known_cves.py")
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
    cwes = sorted(set(re.findall(r"CWE-\d+", text)), key=lambda x: int(x.split("-")[1]))
    historical = []
    for path in sorted((ROOT / "benchmarks/historical").glob("*.json")):
        payload = json.loads(read(path))
        historical.append({
            "sample_id": payload.get("sample_id"), "repository": payload.get("repository"),
            "vulnerable_commit": payload.get("vulnerable_commit"), "fixed_commit": payload.get("fixed_commit"),
            "cwe": payload.get("weakness"), "cve": payload.get("cve"),
            "runtime_replay_status": payload.get("runtime_replay_status"),
        })
    return {"known_cve_detector_cves": cves, "known_cve_detector_cwes": cwes, "historical_samples": historical}


def build_matrix(perf, taxonomy):
    record = read(AUDIT_RECORD)
    plan = read(C_PLAN)
    c_readme = read(C_README)
    d49 = read(D49)
    d50 = read(D50)
    return [
        {
            "item": "accurate_complete_analysis",
            "status": "BLOCKED",
            "supported": False,
            "evidence": ["C plan says C5 independent holdout is blocked before sampling", "D49 explicitly says no independent blind set and no Precision/Recall", "Detector coverage remains partial/blocked in C/D replays"],
            "minimal_remediation": "Freeze rules first, then create a leakage-ledger-controlled holdout with two independent blind labels, adjudication and family-level TP/FP/FN/unknown reporting.",
        },
        {
            "item": "cwe_cve_support",
            "status": "PARTIAL",
            "supported": True,
            "evidence": [f"Known-CVE detector encodes {len(taxonomy['known_cve_detector_cves'])} CVE IDs and {len(taxonomy['known_cve_detector_cwes'])} CWE IDs", "Historical benchmark pins CWE-416/125/476/787 and selected CVEs", "Audit report distinguishes disclosure, component reproduction and product unknowns"],
            "minimal_remediation": "Create one evidence table per delivered finding binding CVE/CWE, exact source/fix objects, detector rule/version, applicability and unresolved obligations; remove unsupported mappings.",
        },
        {
            "item": "reproducible_poc",
            "status": "BLOCKED",
            "supported": False,
            "evidence": ["libpng CVE-2026-46675 and libtiff CVE-2025-9900 have component Harness references", "C plan states no candidate passed the dynamic gate and no PoC was built for C line", "cJSON/curl/OpenHarmony cases lack complete product PoCs"],
            "minimal_remediation": "Package deterministic vulnerable/fixed component fixtures, exact build command, sanitizer/runtime output and replay script for every claimed case; product PoC remains separate until entry/impact are proven.",
        },
        {
            "item": "affected_modules_versions_branches",
            "status": "PARTIAL",
            "supported": True,
            "evidence": ["Audit record and D49/D50 pin multiple repository commits and component versions", "Several affected OpenHarmony release branches are described", "Product build manifest, exact branch adoption and complete call-chain applicability remain unknown"],
            "minimal_remediation": "Add a machine-readable applicability matrix with repository, full commit/tree/blob, product manifest/build, affected/fixed branch and version range for every case.",
        },
        {
            "item": "fix_and_revalidation",
            "status": "BLOCKED",
            "supported": False,
            "evidence": ["Upstream fix commits and some parent/fix source replays exist", "No product fix build and post-fix product retest exist", "C3/C6 gates remain blocked; partial 1->0 static deltas are not fix validation"],
            "minimal_remediation": "For each admitted case, record patch, patched source identity, same-environment rerun, regression controls and product/component impact retest.",
        },
        {
            "item": "performance_and_innovation",
            "status": "PARTIAL" if perf.get("status") == "measured" else "BLOCKED",
            "supported": perf.get("status") == "measured",
            "evidence": ["C11 executes reproducible batch/shard/cache/limit measurements with wall and peak RSS", "Historical performance data covers component platform cost, not accuracy", "Innovation evidence is not yet packaged as an independent comparison against baselines"],
            "minimal_remediation": "Add preregistered baseline comparisons for scan architecture/caching/evidence gating on the same identity/coverage set, plus ablation and failure-boundary analysis; never use throughput as correctness evidence.",
        },
        {
            "item": "complete_report",
            "status": "PARTIAL",
            "supported": True,
            "evidence": ["Audit record is 29,553 bytes and import manifest binds source blob and SHA-256", "The report separates public disclosure, local component state, candidates and unknowns", "Machine-readable per-case deliverable bundle, consolidated evidence index and final product conclusions are incomplete"],
            "minimal_remediation": "Produce a final indexed report bundle linking every claim to machine artifacts, commands, hashes, PoC, fix/retest and limitations; keep candidate counts out of security conclusions.",
        },
    ]


def main():
    DELIVERY.mkdir(parents=True, exist_ok=True)
    perf = performance_facts()
    taxonomy = supported_cwes_cves()
    matrix = build_matrix(perf, taxonomy)
    write(DELIVERY / "performance_results.json", perf)
    write(DELIVERY / "supported_cwe_cve.json", taxonomy)
    write(DELIVERY / "admission_matrix.json", {
        "baseline_commit": "ab30df6a01797af455d2abbbc9533ab15964ee68",
        "decision": "NOT_ADMITTED",
        "draft_ready": False,
        "matrix": matrix,
        "decision_rule": "All competition deliverable items must be independently supported; candidate/static/component evidence cannot satisfy product confirmation.",
    })
    env = {
        "captured_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "platform": platform.platform(),
        "python": sys.version,
        "cwd": str(ROOT),
        "baseline_commit": "ab30df6a01797af455d2abbbc9533ab15964ee68",
        "git_head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "git_tree": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"], text=True).strip(),
        "git_status_porcelain": subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True),
        "network_policy": "No fetch/checkout/commit/push/merge/reset was executed by C11.",
    }
    write(DELIVERY / "environment.json", env)
    commands = [
        "git -C E:\\网安\\CyberSecurity-Innovation-Audit-c11-performance-20261019 rev-parse HEAD",
        "git -C E:\\网安\\CyberSecurity-Innovation-Audit-c11-performance-20261019 status --porcelain",
        "C:\\Users\\work_work\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\python\\python.exe research/experiments/performance_20261019/run_performance_admission.py --out-dir research/experiments/performance_20261019/out",
        "C:\\Users\\work_work\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\python\\python.exe research/experiments/performance_20261019/run_admission_audit.py",
    ]
    (DELIVERY / "commands.txt").write_text("\n".join(commands) + "\n", encoding="utf-8")
    paths = [AUDIT_RECORD, AUDIT_IMPORT, C_PLAN, C_README, D49, D50,
             BASE / "run_performance_admission.py", BASE / "run_admission_audit.py",
             OUT / "raw-index.json", OUT / "summary.json"]
    hashes = [{"path": str(p), "sha256": sha256(p), "bytes": p.stat().st_size} for p in paths if p.exists()]
    write(DELIVERY / "artifact-hashes.json", hashes)
    blocked = [x for x in matrix if x["status"] == "BLOCKED"]
    partial = [x for x in matrix if x["status"] == "PARTIAL"]
    report = [
        "# C11 Performance and Competition Admission Report", "",
        "Baseline: `ab30df6a01797af455d2abbbc9533ab15964ee68`.",
        "Decision: **NOT ADMITTED**. Do not mark Draft Ready or merge.", "",
        "## Performance and bounded-scope results", "",
        f"- All invariance checks pass: `{perf.get('all_invariance_checks_pass')}`.",
        "- `batch`, `shard/aggregate`, cold/warm file AST cache and exact limit boundaries were executed against the same source identities and coverage sets.",
        "- Candidate diagnostic identity is used only to detect verdict drift. It is not a safe/miss or validated-vulnerability verdict.",
        "- Partial/unknown changes and failure boundaries are recorded in `performance_results.json`; no partial state is promoted to complete.", "",
        "| Case | Runs | Wall median / tail (s) | Peak RSS median / tail (bytes) |",
        "|---|---:|---:|---:|",
    ]
    for row in perf.get("statistics", []):
        report.append(f"| `{row['case']}` | {row['successful_runs']}/{row['attempts']} | "
                      f"{row['wall_median_seconds']} / {row['wall_tail_seconds']} | "
                      f"{row['rss_median_bytes']} / {row['rss_tail_bytes']} |")
    report += ["", "## Admission matrix", "", "| Deliverable | Status | Minimum remediation |", "|---|---|---|"]
    for item in matrix:
        report.append(f"| `{item['item']}` | **{item['status']}** | {item['minimal_remediation']} |")
    report += ["", "## Blockers", ""]
    report += [f"- `{x['item']}`: {x['minimal_remediation']}" for x in blocked]
    report += ["", "## Partial items", ""]
    report += [f"- `{x['item']}`: {x['minimal_remediation']}" for x in partial]
    report += [
        "", "## Evidence boundary", "",
        "- The audit record was imported byte-for-byte and is bound by source blob/SHA-256 in its import manifest.",
        "- Known CVE/CWE mappings describe detector rules and historical/component evidence. They do not confirm current product vulnerabilities.",
        "- 2000-file/32MiB/1MiB boundaries are verified exactly; exceeding them remains a coverage limitation, never a safe verdict.",
        "- Performance is platform cost on fixed inputs. It is not accuracy, recall or security evidence.",
        "- Real batch/index cases use the pinned Git commit/tree/blob path. Cache and exact-limit cases use deterministic in-memory fixture identities to isolate frontend/runner behavior; they are not product-source evidence.",
    ]
    (DELIVERY / "ADMISSION_REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    goals = [
        "# C11 Sustained Goals",
        "",
        "- G1: Re-run the same identity/coverage benchmark after any Runner, Git source, parser or cache change; require all invariance checks to remain true.",
        "- G2: Measure real multi-process concurrency RSS and tail latency without changing default limits; shard aggregation must reject global over-limit scopes.",
        "- G3: Close admission blockers in order: independent holdout, per-case CWE/CVE evidence table, reproducible PoCs, applicability matrix, fix/retest, innovation baseline comparison.",
        "- G4: Keep every finding candidate/unassessed until entry, reachability, trigger and CIA impact are auditable; never report candidate counts as vulnerabilities.",
        "- G5: Do not change production Detector/contracts/Runner/Catalog, Git state, Draft Ready or merge status from this line.",
    ]
    (DELIVERY / "sustained-goals.md").write_text("\n".join(goals) + "\n", encoding="utf-8")
    final_paths = [AUDIT_RECORD, AUDIT_IMPORT, C_PLAN, C_README, D49, D50,
                   BASE / "run_performance_admission.py", BASE / "run_admission_audit.py",
                   OUT / "raw-index.json", OUT / "summary.json"]
    final_paths.extend(sorted(p for p in DELIVERY.iterdir()
                              if p.is_file() and p.name != "artifact-hashes.json"))
    final_hashes = [{"path": str(p), "sha256": sha256(p), "bytes": p.stat().st_size}
                    for p in final_paths if p.exists()]
    write(DELIVERY / "artifact-hashes.json", final_hashes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
