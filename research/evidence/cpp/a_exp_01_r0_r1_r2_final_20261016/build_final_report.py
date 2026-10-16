#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EXP = ROOT / "research/experiments/cpp/r0_r1_r2_20261015"
RUN = EXP / "run_20261016_unblock_attempt"
R0DIR = EXP / "run_20261016_r0_agent_blind_nonhuman"
OUT = Path(__file__).resolve().parent


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rate(n: int, d: int) -> float | None:
    return round(n / d, 6) if d else None


def group_view(g: dict) -> dict:
    return {
        "planned": g["planned_runs"],
        "present": g.get("present_run_records", g.get("executed_runs", 0)),
        "completed": g.get("completed", 0),
        "failed": g.get("failed", 0),
        "missing": g.get("missing_run_records", g.get("awaiting_independent_human_reviewer", g["planned_runs"])),
        "completion_rate": rate(g.get("completed", 0), g["planned_runs"]),
        "failure_rate": rate(g.get("failed", 0), g["planned_runs"]),
        "provider_attempts": g.get("model_provider_attempts", 0),
        "tool_calls": g.get("tool_calls", 0),
        "usage": g.get("usage", {}),
        "reference_cost_usd_upper_bound": g.get("reference_cost_usd_upper_bound"),
        "timing_wall_ms": g.get("timing_wall_ms"),
        "failure_codes": g.get("failure_codes", {}),
        "labels": g.get("output_labels", {}),
        "evidence_gate_status": g.get("evidence_gate_status", {}),
        "references": g.get("references", {}),
        "independent_new_facts": g.get("independent_new_facts", {}),
        "item_stability": g.get("item_stability", {}),
        "run_validation": g.get("run_validation", {}),
        "per_repetition": g.get("per_repetition", []),
    }


def main() -> None:
    metrics = load(RUN / "metrics.json")
    execution = load(RUN / "execution_record.json")
    pricing = load(RUN / "pricing_record.json")
    validation = load(RUN / "run_validation.json")
    planned_budget = load(ROOT / "research/evidence/cpp/a_exp_01_r1_r2_20261016/fail_closed_preflight/r2_extra_budget.json")
    candidate_doc = load(EXP / "initial_candidate_set.json")
    evidence_doc = load(EXP / "evidence_catalog.json")
    r0_lock = load(R0DIR / "R0_AGENT_REVIEW_LOCK.json")

    allowed_by_item = {
        item["experiment_item_id"]: set(item["evidence_ids"] + item["fact_ids"])
        for item in candidate_doc["items"]
    }
    source_identity_by_item = {
        item["experiment_item_id"]: item["source_identity"] for item in candidate_doc["items"]
    }
    evidence_by_item = {item["experiment_item_id"]: item for item in evidence_doc["items"]}

    r0_records = [
        json.loads(line)
        for line in (R0DIR / "r0_agent_blind_reviews.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(r0_records) == 135
    assert {r["experiment_item_id"] for r in r0_records} == set(allowed_by_item)
    assert Counter(r["repetition"] for r in r0_records) == {1: 45, 2: 45, 3: 45}

    invalid_refs = []
    claims_count = 0
    refs_count = 0
    unique_refs = set()
    for record in r0_records:
        item_id = record["experiment_item_id"]
        for claim in record["form"]["claims"]:
            claims_count += 1
            if not claim["evidence_refs"]:
                invalid_refs.append({"run_id": record["run_id"], "claim_id": claim["claim_id"], "reason": "empty"})
            for ref in claim["evidence_refs"]:
                refs_count += 1
                unique_refs.add(ref)
                if ref not in allowed_by_item[item_id]:
                    invalid_refs.append({
                        "run_id": record["run_id"],
                        "claim_id": claim["claim_id"],
                        "ref": ref,
                        "reason": "illegal_or_out_of_item_scope",
                    })

    by_item = defaultdict(list)
    for record in r0_records:
        form = record["form"]
        signature = {
            "mechanism_label": form["mechanism_label"],
            "product_assessment": form["product_assessment"],
            "evidence_gate_status": form["evidence_gate_status"],
            "claims": form["claims"],
            "missing_evidence": form["missing_evidence"],
        }
        by_item[record["experiment_item_id"]].append(signature)
    stable_items = sum(1 for values in by_item.values() if len({json.dumps(v, sort_keys=True) for v in values}) == 1)

    r0_summary = {
        "schema_version": "ohscanner.a-exp-01-r0-agent-review-summary-v1",
        "record_count": len(r0_records),
        "reviewer_kind": "agent_not_human",
        "human_review_eligibility": "ineligible_not_independent_human",
        "planned_human_reviews": 135,
        "executed_human_reviews": 0,
        "executed_agent_blinded_reviews": 135,
        "completed_agent_blinded_reviews": sum(r["review_status"] == "completed_agent_blinded_review" for r in r0_records),
        "failed_agent_blinded_reviews": sum(r["review_status"] != "completed_agent_blinded_review" for r in r0_records),
        "labels": dict(Counter(r["form"]["mechanism_label"] for r in r0_records)),
        "product_assessments": dict(Counter(r["form"]["product_assessment"] for r in r0_records)),
        "evidence_gate_status": dict(Counter(r["form"]["evidence_gate_status"] for r in r0_records)),
        "confidence": {
            "mean": round(sum(r["confidence"] for r in r0_records) / len(r0_records), 6),
            "counts": dict(Counter(str(r["confidence"]) for r in r0_records)),
        },
        "timing": {
            "active_seconds": None,
            "paused_seconds": None,
            "status": "unknown_not_measured_by_independent_human_reviewer",
        },
        "references": {
            "claims": claims_count,
            "references": refs_count,
            "claims_with_nonempty_refs": claims_count if not any(x["reason"] == "empty" for x in invalid_refs) else None,
            "illegal_or_out_of_scope_references": sum(x["reason"] != "empty" for x in invalid_refs),
            "unique_cited_ids": len(unique_refs),
            "invalid_reference_runs": len({x["run_id"] for x in invalid_refs}),
        },
        "independent_new_facts": {
            "new_fact_claims": 0,
            "all_claims": claims_count,
            "new_fact_claim_ratio": 0.0,
            "unique_cited_tool_result_evidence_ids": 0,
            "tool_result_evidence_ratio": 0.0,
        },
        "repetition_variance": {
            "items": len(by_item),
            "stable_assessment_items": stable_items,
            "unstable_assessment_items": len(by_item) - stable_items,
            "stable_mechanism_label_items": sum(
                len({v["mechanism_label"] for v in values}) == 1 for values in by_item.values()
            ),
            "note": "All three records use the same non-human reviewer and are not independent human repetitions.",
        },
        "records_sha256": r0_lock["records_sha256"],
        "lock": r0_lock,
        "invalid_references": invalid_refs,
    }
    dump(OUT / "r0_agent_review_summary.json", r0_summary)

    r1 = metrics["groups"]["R1"]
    r2 = metrics["groups"]["R2"]
    r2_actual_extra = {
        "schema_version": "ohscanner.a-exp-01-r2-extra-budget-actual-v1",
        "comparison": "R2 minus R1, actual recorded main runs",
        "planned_135_run_maxima": planned_budget["planned_total_135_runs"],
        "actual_total": {
            "provider_attempts_delta": r2["model_provider_attempts"] - r1["model_provider_attempts"],
            "tool_calls_delta": r2["tool_calls"] - r1["tool_calls"],
            "input_tokens_delta": r2["usage"]["input_tokens"] - r1["usage"]["input_tokens"],
            "output_tokens_delta": r2["usage"]["output_tokens"] - r1["usage"]["output_tokens"],
            "total_tokens_delta": r2["usage"]["total_tokens"] - r1["usage"]["total_tokens"],
            "reference_cost_usd_upper_bound_delta": round(
                r2["reference_cost_usd_upper_bound"] - r1["reference_cost_usd_upper_bound"], 12
            ),
            "mean_wall_ms_delta": round(
                r2["timing_wall_ms"]["mean"] - r1["timing_wall_ms"]["mean"], 6
            ),
            "run_failure_delta": r2["failed"] - r1["failed"],
            "tool_failed_calls": r2["tool_statuses"].get("failed", 0),
        },
        "actual_per_run_mean": {
            "provider_attempts_delta": round((r2["model_provider_attempts"] - r1["model_provider_attempts"]) / 135, 6),
            "tool_calls_delta": round((r2["tool_calls"] - r1["tool_calls"]) / 135, 6),
            "input_tokens_delta": round((r2["usage"]["input_tokens"] - r1["usage"]["input_tokens"]) / 135, 6),
            "output_tokens_delta": round((r2["usage"]["output_tokens"] - r1["usage"]["output_tokens"]) / 135, 6),
            "total_tokens_delta": round((r2["usage"]["total_tokens"] - r1["usage"]["total_tokens"]) / 135, 6),
            "reference_cost_usd_upper_bound_delta": round(
                (r2["reference_cost_usd_upper_bound"] - r1["reference_cost_usd_upper_bound"]) / 135, 12
            ),
            "mean_wall_ms_delta": round(r2["timing_wall_ms"]["mean"] - r1["timing_wall_ms"]["mean"], 6),
        },
        "interpretation": "R2 received two provider turns and four tool calls per run on average. Method effects cannot be separated from this additional budget. Reference cost is a pay-as-you-go upper bound, not observed Token Plan billing.",
    }
    dump(OUT / "r2_extra_budget_actual.json", r2_actual_extra)

    failures = []
    for run_file in sorted((RUN / "runs").rglob("*.json")):
        record = load(run_file)
        variant = run_file.parent.name
        if record.get("status") != "completed":
            failure = record.get("failure") or {}
            failures.append({
                "failure_kind": "run_failure",
                "source": str(run_file.relative_to(ROOT)).replace("\\", "/"),
                "variant": variant,
                "run_id": record["run_id"],
                "experiment_item_id": record["experiment_item_id"],
                "repetition": record["repetition"],
                "status": record.get("status"),
                "failure_code": failure.get("failure_code"),
                "message": failure.get("message"),
                "retries": failure.get("retries"),
                "timed_out": failure.get("timed_out"),
                "budget_exhausted": failure.get("budget_exhausted"),
            })
        for tool in record.get("tool_calls", []):
            if tool.get("status") != "ok":
                failures.append({
                    "failure_kind": "tool_failure",
                    "source": str(run_file.relative_to(ROOT)).replace("\\", "/"),
                    "variant": variant,
                    "run_id": record["run_id"],
                    "experiment_item_id": record["experiment_item_id"],
                    "repetition": record["repetition"],
                    "tool_call_id": tool.get("tool_call_id"),
                    "tool_id": tool.get("tool_id"),
                    "status": tool.get("status"),
                    "message": (tool.get("failure") or {}).get("message"),
                    "timed_out": tool.get("status") == "timed_out",
                    "budget_exhausted": tool.get("status") == "budget_exhausted",
                })
    failures_path = OUT / "all_failures.jsonl"
    with failures_path.open("w", encoding="utf-8", newline="\n") as fh:
        for failure in failures:
            fh.write(json.dumps(failure, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")

    failure_counts = Counter((f["variant"], f["failure_kind"], f.get("failure_code") or f.get("status")) for f in failures)
    validation_path = OUT / "validation/validation_summary.json"
    validation = load(validation_path) if validation_path.exists() else {"status": "not_run"}

    ablations = []
    for ablation in metrics["ablations"]:
        ablations.append({
            "ablation_id": ablation["ablation_id"],
            "planned": ablation["planned_runs"],
            "present": ablation["present_run_records"],
            "completed": ablation["completed"],
            "failed": ablation["failed"],
            "completion_rate": rate(ablation["completed"], ablation["planned_runs"]),
            "failure_rate": rate(ablation["failed"], ablation["planned_runs"]),
            "failure_codes": ablation["failure_codes"],
            "provider_attempts": ablation["model_provider_attempts"],
            "tool_calls": ablation["tool_calls"],
            "usage": ablation["usage"],
            "reference_cost_usd_upper_bound": ablation["reference_cost_usd_upper_bound"],
            "wall_ms": ablation["wall_ms"],
            "labels": ablation["labels"],
            "evidence_gate_status": ablation["evidence_gate_status"],
            "references": ablation["references"],
            "independent_new_facts": ablation["independent_new_facts"],
            "run_validation": ablation["run_validation"],
            "per_repetition": ablation["per_repetition"],
        })

    r0_human = {
        "planned": 135,
        "present": 0,
        "completed": 0,
        "failed_recorded_attempts": 0,
        "missing_or_unexecuted": 135,
        "completion_rate": 0.0,
        "missing_rate": 1.0,
        "failure_rate": None,
        "reason": "No independent human review session executed; failure rate is not interpretable from zero attempts.",
        "human_active_seconds": None,
        "human_paused_seconds": None,
    }

    comparison = {
        "R0_independent_human": r0_human,
        "R0_agent_blinded_supplement": r0_summary,
        "R1": group_view(r1),
        "R2": group_view(r2),
    }

    summary = {
        "schema_version": "ohscanner.a-exp-01-final-experiment-summary-v1",
        "experiment_id": "A-EXP-01",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo_identity": {
            "checkout": str(ROOT),
            "head": "8e97f152ef747c1e1d21ae179a048910f147e07a",
            "branch_at_start": "codex/full-runtime-performance-audit-20261014",
            "remote": "https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git",
        },
        "fixed_conditions": {
            "review_items": 45,
            "scope_occurrences": 45,
            "unique_candidates": 44,
            "fact_bundle_sha256": metrics["fact_bundle_sha256"],
            "evidence_obligation_contract_sha256": metrics["evidence_obligation_contract_sha256"],
            "seeds": [20261015, 20261016, 20261017],
            "repetitions": [1, 2, 3],
            "evidence_obligations": [
                "fixed target identity",
                "realistic entry/privilege boundary",
                "reachable sensitive operation",
                "trigger conditions",
                "concrete CIA impact",
                "auditable evidence",
            ],
        },
        "comparison": comparison,
        "ablations": ablations,
        "r2_extra_budget_actual": r2_actual_extra,
        "failure_summary": [
            {"variant": k[0], "failure_kind": k[1], "code_or_status": k[2], "count": v}
            for k, v in sorted(failure_counts.items())
        ],
        "failure_record_count": len(failures),
        "validation": validation,
        "precision_recall": metrics["precision_recall"],
        "truth_eligibility": {
            "status": "ineligible_unknown",
            "independent_reliable_truth_present": False,
            "complete_predictions_for_all_groups": False,
            "reason": "R0 independent human predictions are absent; the frozen truth set is explicitly not an independent labelled accuracy dataset; model agreement/history/synthetic controls are not truth.",
        },
        "limitations": [
            "R0 independent human arm was not executed. The 135 locked R0 records are non-human Codex-agent blinded assessments and cannot substitute for human outcomes or human cost.",
            "All three R0 agent repetitions use one agent and therefore do not provide independent human repetition variance.",
            "The 45 review items represent 45 scope occurrences but only 44 unique candidates; one candidate appears in two scopes and creates clustering.",
            "Public or historical vulnerability material may be present in model training data; no contamination-clean unseen set was supplied.",
            "Frozen/synthetic truth, historical review labels, and model agreement are not eligible ground truth.",
            "R2 receives extra provider turns, tool calls, tokens and wall time. Its comparison with R1 is budget-confounded.",
            "Provider cost is a USD pay-as-you-go list-price upper bound. Actual Token Plan credit consumption and billing currency are unknown.",
            "All missing, failed, invalid, partial and unknown outcomes remain in planned denominators; no best-run selection was used.",
        ],
    }
    dump(OUT / "final_experiment_report.json", summary)

    def fmt_pct(value):
        return "n/a" if value is None else f"{value * 100:.2f}%"

    def fmt_num(value):
        return "unknown" if value is None else f"{value:,}"

    lines = []
    lines.append("# A-EXP-01 R0/R1/R2 final experiment report")
    lines.append("")
    lines.append(f"Generated: {summary['generated_at_utc']}")
    lines.append("")
    lines.append("## Executive conclusion")
    lines.append("")
    lines.append("- The 45 review items, 135 planned runs per group, `fact_bundle_sha256`, six EvidenceObligations, seeds and repetition plan are fixed and identical across the main groups.")
    lines.append("- 135 blinded R0 records were produced and locked at SHA-256 `2f2075ebc310d1c145f8a0ecc0465da0eca286be1a137956ee88b8ed9d4a443b` before R1/R2 result inspection.")
    lines.append("- Those R0 records are explicitly `agent_not_human`; the independent human R0 arm remains 0/135. Therefore a three-arm human/model effect comparison and human-cost comparison are ineligible.")
    lines.append("- Precision, Recall, TP/FP/FN/TN are not computed. There is no independent reliable labelled accuracy dataset and R0 complete human predictions are absent.")
    lines.append("- R2 added real tool-derived evidence, but also used substantially more provider/tool budget. Method and budget effects cannot be separated.")
    lines.append("")
    lines.append("## Fixed binding")
    lines.append("")
    lines.append(f"- Review units: 45 review items / 45 scope occurrences / 44 unique candidates.")
    lines.append(f"- Fact bundle: `{metrics['fact_bundle_sha256']}`")
    lines.append(f"- EvidenceObligation contract: `{metrics['evidence_obligation_contract_sha256']}`")
    lines.append("- Seeds: `20261015`, `20261016`, `20261017`; repetitions: 1, 2, 3.")
    lines.append("- Obligations: fixed target identity; realistic entry/privilege boundary; reachable sensitive operation; trigger conditions; concrete CIA impact; auditable evidence.")
    lines.append(f"- Current checkout HEAD at experiment start: `{summary['repo_identity']['head']}`.")
    lines.append("")
    lines.append("## Completion, failure and cost")
    lines.append("")
    lines.append("| Arm | Planned | Present | Completed | Failed | Missing/unexecuted | Completion | Failure | Provider attempts | Tool calls | Total tokens | Reference cost upper bound | Human active / paused |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    lines.append("| R0 independent human | 135 | 0 | 0 | n/a | 135 | 0.00% | n/a | 0 | 0 | 0 | n/a | unknown / unknown |")
    lines.append(f"| R0 blinded agent supplement | 135 | 135 | {r0_summary['completed_agent_blinded_reviews']} | {r0_summary['failed_agent_blinded_reviews']} | 0 | {fmt_pct(r0_summary['completed_agent_blinded_reviews']/135)} | {fmt_pct(r0_summary['failed_agent_blinded_reviews']/135)} | 0 | 0 | 0 | n/a | unknown / unknown |")
    for name, g in (("R1", r1), ("R2", r2)):
        lines.append(
            f"| {name} | {g['planned_runs']} | {g['present_run_records']} | {g['completed']} | {g['failed']} | {g['missing_run_records']} | "
            f"{fmt_pct(g['completed']/g['planned_runs'])} | {fmt_pct(g['failed']/g['planned_runs'])} | {g['model_provider_attempts']} | "
            f"{g['tool_calls']} | {g['usage']['total_tokens']:,} | ${g['reference_cost_usd_upper_bound']:.6f} | unknown / unknown |"
        )
    lines.append("")
    lines.append("Human cost is unknown for every arm. Model wall time is machine runtime, not human active time. No timing was synthesized.")
    lines.append("")
    lines.append("## Citation quality and independent facts")
    lines.append("")
    lines.append("| Arm | Claims | Nonempty refs | Empty/missing-ref claims | Runs without claims | Illegal refs | Invalid-ref/record runs | Unique cited IDs | Tool-result new-fact claims | Tool-result evidence ratio |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    rr = r0_summary["references"]
    lines.append(f"| R0 agent supplement | {rr['claims']} | {rr['claims']} | 0 | 0 | {rr['illegal_or_out_of_scope_references']} | {rr['invalid_reference_runs']} | {rr['unique_cited_ids']} | 0 | 0.00% |")
    for name, g in (("R1", r1), ("R2", r2)):
        refs = g["references"]
        facts = g["independent_new_facts"]
        lines.append(
            f"| {name} | {refs['claims']} | {refs['claims_with_nonempty_refs']} | {refs['missing_or_empty_reference_claims']} | "
            f"{refs['runs_without_any_claims']} | {refs['illegal_reference_count']} | {refs['invalid_reference_runs']} | "
            f"{facts['unique_cited_evidence_ids']} | {facts['new_fact_claims']} ({facts['new_fact_claim_ratio']*100:.2f}%) | "
            f"{facts['tool_result_evidence_ratio']*100:.2f}% |"
        )
    lines.append("")
    lines.append("R1 added no tool-result facts. R2 cited persisted tool-result IDs for 557/1,115 claims and 463/548 unique cited evidence IDs. These are independently tool-added facts under the frozen reference contract, not truth labels.")
    lines.append("")
    lines.append("## R2 extra budget")
    lines.append("")
    ex = r2_actual_extra["actual_total"]
    lines.append("| Extra quantity, R2 minus R1 | Total over 135 runs | Mean per run |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Provider attempts | {ex['provider_attempts_delta']} | {r2_actual_extra['actual_per_run_mean']['provider_attempts_delta']:.2f} |")
    lines.append(f"| Tool calls | {ex['tool_calls_delta']} | {r2_actual_extra['actual_per_run_mean']['tool_calls_delta']:.2f} |")
    lines.append(f"| Input tokens | {ex['input_tokens_delta']:,} | {r2_actual_extra['actual_per_run_mean']['input_tokens_delta']:.2f} |")
    lines.append(f"| Output tokens | {ex['output_tokens_delta']:,} | {r2_actual_extra['actual_per_run_mean']['output_tokens_delta']:.2f} |")
    lines.append(f"| Total tokens | {ex['total_tokens_delta']:,} | {r2_actual_extra['actual_per_run_mean']['total_tokens_delta']:.2f} |")
    lines.append(f"| Reference cost upper bound | ${ex['reference_cost_usd_upper_bound_delta']:.6f} | ${r2_actual_extra['actual_per_run_mean']['reference_cost_usd_upper_bound_delta']:.6f} |")
    lines.append(f"| Mean wall time | {ex['mean_wall_ms_delta']/1000:.3f} s | {ex['mean_wall_ms_delta']/1000:.3f} s |")
    lines.append(f"| Additional run failures | {ex['run_failure_delta']} | n/a |")
    lines.append("")
    lines.append("R2 planned maxima were 1,080 tool calls, 1,080,000 input tokens, 216,000 output tokens and $101.25 reference cost; actual use was 540 tool calls, 1,523,527 input tokens, 358,280 output tokens and $0.974438. The planned maxima were not a prediction of actual usage. Four main-R2 tool calls failed; 20 non-ok tool calls across main and ablation runs are all retained in `all_failures.jsonl`.")
    lines.append("")
    lines.append("## Repetition variance")
    lines.append("")
    lines.append("| Arm / variant | Rep 1 completed / failed / hashes | Rep 2 completed / failed / hashes | Rep 3 completed / failed / hashes | Stability | Wall variance ms^2 |")
    lines.append("|---|---|---|---|---|---:|")
    lines.append("| R0 agent supplement | 45 / 0 / 45 | 45 / 0 / 45 | 45 / 0 / 45 | 45/45 assessment-stable, non-independent reviewer | unknown |")
    for name, g in (("R1", r1), ("R2", r2)):
        reps = " | ".join(f"{p['completed']} / {p['failed']} / {p['distinct_output_hashes']}" for p in g["per_repetition"])
        stable = g["item_stability"]
        lines.append(f"| {name} | {reps} | {stable['stable_mechanism_label_items']}/45 labels stable; {stable['stable_output_hash_items']}/45 output hashes stable | {g['timing_wall_ms']['variance']:.3f} |")
    lines.append("")
    lines.append("R1 per-repetition reference costs were $0.147294, $0.146927 and $0.147490. R2 costs were $0.326097, $0.327603 and $0.320738. R1 completed 43/42/43; R2 completed 39/44/40. R0 human repetition variance is unknown.")
    lines.append("")
    lines.append("## Three ablations")
    lines.append("")
    lines.append("| Ablation | Completed | Failed | Failure rate | Tool calls | Total tokens | Reference cost | New-fact claims | Invalid record runs | Rep completed R1/R2/R3 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for a in ablations:
        reps = "/".join(str(p["completed"]) for p in a["per_repetition"])
        facts = a["independent_new_facts"]
        lines.append(
            f"| {a['ablation_id']} | {a['completed']} | {a['failed']} | {fmt_pct(a['failure_rate'])} | {a['tool_calls']} | "
            f"{a['usage']['total_tokens']:,} | ${a['reference_cost_usd_upper_bound']:.6f} | "
            f"{facts['new_fact_claims']}/{facts['all_claims']} ({facts['new_fact_claim_ratio']*100:.2f}%) | "
            f"{a['run_validation']['invalid']} | {reps} |"
        )
    lines.append("")
    lines.append("Interpretation is descriptive only: removing AST reduced tool-derived new-fact share and produced 5 failures; removing historical patch access produced 22 failures and 17 invalid reference records; forcing one turn completed 135/135 but produced no tool-derived new facts. No ablation has independent truth, so none establishes accuracy improvement.")
    lines.append("")
    lines.append("## Metrics eligibility")
    lines.append("")
    lines.append("TP/FP/FN/TN, Precision and Recall: **ineligible / not computed**.")
    lines.append("")
    lines.append("- Independent reliable truth: absent/ineligible.")
    lines.append("- Complete predictions for the intended three arms: absent because R0 independent human runs are missing.")
    lines.append("- Model agreement, historical review labels and synthetic controls are not used as truth.")
    lines.append("- No zero FP/FN claim is made.")
    lines.append("")
    lines.append("## Failures")
    lines.append("")
    lines.append(f"`all_failures.jsonl` contains {len(failures)} failure records: 46 failed runs plus every non-ok tool call. Main R1 failures were 6 schema-invalid outputs and 1 missing-reference run. Main R2 failures were 7 agent failures and 5 missing/illegal-reference runs. Ablation failures are fully enumerated in the JSONL.")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("- `PYTHONPATH=. .venv-web/bin/python -m unittest discover -s tests -q`: exit 0; 684 tests run, 676 passed, 8 skipped, 0 failed in 128.660s.")
    lines.append("- `python scripts/check_docs_context_budget.py`: `python` is not on the Windows PowerShell PATH; the equivalent frozen interpreter `.venv-web/bin/python` exited 0 with `default=10835/13500, docs=17173/32500`.")
    lines.append("- `git diff --check`: exact command exited 0. CRLF normalization warnings were retained in the raw validation log; `git diff --check -- docs/项目现状与下一步.md` also exited 0.")
    lines.append("")
    lines.append("## Limitations and threats")
    lines.append("")
    for limitation in summary["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    lines.append("## Reproducibility")
    lines.append("")
    lines.append("- R0 record lock: `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_r0_agent_blind_nonhuman/R0_AGENT_REVIEW_LOCK.json`.")
    lines.append("- R1/R2 raw runs and tool results: `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/`.")
    lines.append("- Compact R1/R2 evidence: `research/evidence/cpp/a_exp_01_r1_r2_20261016/`.")
    lines.append("- This report's machine-readable summary and hashes: `final_experiment_report.json`, `artifact_manifest.json`.")
    lines.append("")
    (OUT / "FINAL_EXPERIMENT_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

    artifact_paths = [
        OUT / "FINAL_EXPERIMENT_REPORT.md",
        OUT / "EVIDENCE_INDEX.md",
        OUT / "final_experiment_report.json",
        OUT / "r0_agent_review_summary.json",
        OUT / "r2_extra_budget_actual.json",
        OUT / "all_failures.jsonl",
        R0DIR / "r0_agent_blind_reviews.jsonl",
        R0DIR / "R0_AGENT_REVIEW_LOCK.json",
        RUN / "metrics.json",
        RUN / "run_validation.json",
        OUT / "validation/validation_summary.json",
        OUT / "validation/unittest.stdout.txt",
        OUT / "validation/unittest_rerun_summary.txt",
        EXP / "run_20261016_r0_human_assignments/assignment_set_manifest.json",
        EXP / "run_20261016_r0_human_assignments/assignment_artifact_manifest.json",
        EXP / "run_20261016_r0_human_assignments/validate_human_submission.py",
        OUT / "validation/docs_budget.stdout.txt",
        OUT / "validation/git_diff_check.stdout.txt",
    ]
    manifest = {
        "schema_version": "ohscanner.a-exp-01-final-artifact-manifest-v1",
        "generated_at_utc": summary["generated_at_utc"],
        "artifacts": [
            {"path": str(p.relative_to(ROOT)).replace("\\", "/"), "sha256": sha256(p), "bytes": p.stat().st_size}
            for p in artifact_paths
        ],
    }
    dump(OUT / "artifact_manifest.json", manifest)
    print(json.dumps({
        "report": str((OUT / "FINAL_EXPERIMENT_REPORT.md").relative_to(ROOT)),
        "records": len(r0_records),
        "failures": len(failures),
        "r0_records_sha256": r0_lock["records_sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()






