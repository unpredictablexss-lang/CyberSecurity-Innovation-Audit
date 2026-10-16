"""Fail-closed root-cause accuracy accounting for independent labelled data."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence

CATEGORIES = ("vulnerable", "fixed", "safe", "unrelated")
PREDICTIONS = ("detected", "not_detected", "unknown")


def _truth_source_allowed(value: Any) -> bool:
    text = str(value or "").lower()
    return bool(text) and not any(
        marker in text for marker in ("model", "self", "detector", "rule")
    )


def evaluate_root_causes(
    predictions: Sequence[Mapping[str, Any]],
    truth: Sequence[Mapping[str, Any]],
    *,
    truth_manifest: Mapping[str, Any] | None = None,
    independent_holdout: bool = False,
) -> dict[str, Any]:
    """Aggregate by independent root cause; never turn unknowns into misses."""
    prediction_by_id = {
        str(item.get("sample_id")): item
        for item in predictions
        if isinstance(item, Mapping) and item.get("sample_id") is not None
    }
    truth_by_id = {
        str(item.get("sample_id")): item
        for item in truth
        if isinstance(item, Mapping) and item.get("sample_id") is not None
    }
    manifest_eligible = bool(
        truth_manifest and truth_manifest.get("eligible_for_metrics") is True
    )
    reasons: list[str] = []
    if not manifest_eligible:
        reasons.append("truth_manifest_not_eligible_for_metrics")
    if not independent_holdout:
        reasons.append("independent_holdout_not_certified")
    if not prediction_by_id:
        reasons.append("no_prediction_records")
    if not truth_by_id:
        reasons.append("no_truth_records")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    for sample_id in sorted(set(prediction_by_id) | set(truth_by_id)):
        pred = prediction_by_id.get(sample_id, {})
        item = truth_by_id.get(sample_id, {})
        category = str(item.get("category") or item.get("truth_category") or "unknown")
        category_counts[category] += 1
        root_cause = str(
            item.get("root_cause_id")
            or pred.get("root_cause_id")
            or item.get("root_cause_group")
            or "unknown-root-cause"
        )
        split = str(item.get("split") or pred.get("split") or "unknown")
        truth_verified = item.get("truth_verified") is True
        source_ok = _truth_source_allowed(
            item.get("truth_source") or item.get("ground_truth_source")
        )
        prediction = str(pred.get("prediction") or pred.get("predicted") or "unknown")
        if prediction not in PREDICTIONS:
            prediction = "unknown"
        reason = []
        if category not in CATEGORIES:
            reason.append("truth_category_unknown")
        if split != "holdout":
            reason.append("not_independent_holdout")
        if not truth_verified:
            reason.append("truth_not_independently_verified")
        if not source_ok:
            reason.append("truth_source_not_independent")
        if prediction == "unknown":
            reason.append("prediction_unknown")
        if sample_id not in truth_by_id:
            reason.append("truth_missing")
        if sample_id not in prediction_by_id:
            reason.append("prediction_missing")
        if reason:
            excluded.append({
                "sample_id": sample_id,
                "root_cause_id": root_cause,
                "category": category,
                "prediction": prediction,
                "reasons": sorted(set(reason)),
            })
            continue
        grouped[root_cause].append({
            "sample_id": sample_id,
            "category": category,
            "prediction": prediction,
        })

    rows: list[dict[str, Any]] = []
    totals = Counter()
    for root_cause in sorted(grouped):
        items = grouped[root_cause]
        detected = any(item["prediction"] == "detected" for item in items)
        positive = any(item["category"] == "vulnerable" for item in items)
        if positive and detected:
            outcome = "TP"
        elif positive:
            outcome = "FN"
        elif detected:
            outcome = "FP"
        else:
            outcome = "TN"
        totals[outcome] += 1
        rows.append({
            "root_cause_id": root_cause,
            "outcome": outcome,
            "sample_count": len(items),
            "sample_ids": [item["sample_id"] for item in items],
            "categories": sorted({item["category"] for item in items}),
        })

    tp, fp, fn, tn = (totals[key] for key in ("TP", "FP", "FN", "TN"))
    eligible = manifest_eligible and independent_holdout and not excluded and bool(rows)
    precision = tp / (tp + fp) if eligible and tp + fp else None
    recall = tp / (tp + fn) if eligible and tp + fn else None
    return {
        "schema_version": 1,
        "kind": "ohscanner.root-cause-metrics.v1",
        "status": "eligible" if eligible else "blocked_unknown_or_unreliable_truth",
        "eligible_for_metrics": eligible,
        "independent_holdout": independent_holdout,
        "unit": "independent_root_cause",
        "counts": {
            "TP": tp if eligible else None,
            "FP": fp if eligible else None,
            "FN": fn if eligible else None,
            "TN": tn if eligible else None,
        },
        "unscored_root_cause_counts": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": precision,
        "recall": recall,
        "root_causes": rows,
        "category_counts": dict(sorted(category_counts.items())),
        "excluded_unknown_or_unscored": excluded,
        "reasons": sorted(set(reasons)) if reasons else [],
        "interpretation": (
            "Precision/Recall are computed only from independently verified holdout "
            "root causes with reliable non-model truth and complete predictions."
            if eligible else
            "No Precision/Recall is published; unknown/partial/failed/unexecuted "
            "observations remain unknown and are not converted to misses."
        ),
    }