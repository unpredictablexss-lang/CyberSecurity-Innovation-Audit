"""Persistence for manual candidate review annotations.

Exports a triage report into an editable JSON review template and merges a
human-filled review file back into the packet ReviewState. This keeps the
"who reviewed what and why" record durable without changing any Finding status
or producing a vulnerability verdict.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from src.triage.review import TriageReport


_REVIEW_FIELDS = [
    "review_status",
    "input_control",
    "destination_capacity",
    "length_origin",
    "guard_evidence",
    "reachability",
    "security_impact",
    "runtime_validation",
]


def export_review_template(triage_report: TriageReport, out: Path) -> None:
    """Write one editable JSON entry per packet, keyed by candidate_id."""
    entries: List[Dict[str, Any]] = []
    for packet in triage_report.packets:
        review = packet.review
        entries.append(
            {
                "candidate_id": packet.candidate_id,
                "file": packet.file,
                "line": packet.line,
                "function": packet.function,
                "call_name": packet.call_name,
                **{field: getattr(review, field) for field in _REVIEW_FIELDS},
                "reviewer": "",
                "notes": "",
                "next_action": "",
            }
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def merge_review_annotations(
    triage_report: TriageReport,
    review_file: Path,
) -> TriageReport:
    """Merge a human-edited review JSON array back into packet ReviewState.

    Only review fields are updated; candidate identity fields (file/line/call)
    are never overwritten. Unknown candidate_ids are skipped, and reviewer /
    notes / next_action are appended to reviewer_notes for traceability.
    """
    data = json.loads(review_file.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("review file must contain a JSON array")

    by_id = {packet.candidate_id: packet for packet in triage_report.packets}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        candidate_id = str(entry.get("candidate_id", ""))
        packet = by_id.get(candidate_id)
        if packet is None:
            continue

        review = packet.review
        for field in _REVIEW_FIELDS:
            value = entry.get(field)
            if value is not None:
                setattr(review, field, str(value))

        reviewer = str(entry.get("reviewer", "") or "").strip()
        next_action = str(entry.get("next_action", "") or "").strip()
        notes = str(entry.get("notes", "") or "").strip()
        if reviewer:
            review.reviewer_notes.append(f"reviewer: {reviewer}")
        if next_action:
            review.reviewer_notes.append(f"next_action: {next_action}")
        if notes:
            review.reviewer_notes.append(notes)

    return triage_report
