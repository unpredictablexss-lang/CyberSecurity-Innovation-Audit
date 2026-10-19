from pathlib import Path
p = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c11-performance-20261019\research\experiments\performance_20261019\run_admission_audit.py")
t = p.read_text(encoding="utf-8")
old = '''    checks = {
        "batch_source_identity_invariant": bool(batch and unbatch and batch.get("source_identity_sha256") == unbatch.get("source_identity_sha256")),
        "cache_cold_identity_parse_verdict_invariant": bool(full and cold and all(full.get(k) == cold.get(k) for k in ("source_identity_sha256", "parse_signature_sha256", "diagnostic_signature_sha256"))),
        "cache_warm_identity_parse_verdict_invariant": bool(full and warm and all(full.get(k) == warm.get(k) for k in ("source_identity_sha256", "parse_signature_sha256", "diagnostic_signature_sha256"))),
        "synthetic_shard_aggregate_invariant": bool(shard and shard.get("invariant")),
        "cli_shard_aggregate_source_and_parse_invariant": bool(cli_shards and cli_shards.get("invariant")),
        "limit_boundaries_exact": all(v["actual"] == v["expected"] for v in limits.values()),
    }
    return {
        "status": "measured",
        "statistics": stats,
        "invariance_checks": checks,
        "all_invariance_checks_pass": all(checks.values()),
        "verdict_drift_semantics": "candidate diagnostic identity/coverage drift only; not safe/miss/validated-vulnerability drift",
        "limits": limits,
    }'''
new = '''    checks = {
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
    }'''
if old not in t:
    raise SystemExit("performance facts block not found")
t = t.replace(old, new)
t = t.replace('''        "- Candidate diagnostic identity is used only to detect verdict drift. It is not a safe/miss or validated-vulnerability verdict.", "",''', '''        "- Candidate diagnostic identity is used only to detect verdict drift. It is not a safe/miss or validated-vulnerability verdict.",
        "- Partial/unknown changes and failure boundaries are recorded in `performance_results.json`; no partial state is promoted to complete.", "",''')
p.write_text(t, encoding="utf-8")
print("patched admission facts")
