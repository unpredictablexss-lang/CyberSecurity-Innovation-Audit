"""Assemble a draft VulnerabilityCase from evidence.

This is the entry point of the Candidate -> Evidence -> Case pipeline. The first
version only ever produces ``report_status = draft`` with ``confidence =
unassessed``; it never auto-promotes a candidate to a validated or reportable
vulnerability. States are: draft, investigation, validated_component,
validated_target, reportable, refuted.
"""

from typing import List

from src.core.case import VulnerabilityCase, make_case_id
from src.core.evidence import Evidence


_CASE_STATES = {
    "draft",
    "investigation",
    "validated_component",
    "validated_target",
    "reportable",
    "refuted",
}


def assemble_case_draft(
    candidate_id: str,
    evidence: List[Evidence],
) -> VulnerabilityCase:
    if not candidate_id.strip():
        raise ValueError("candidate_id must not be empty")

    case_id = make_case_id(f"draft:{candidate_id}", "", candidate_id)
    return VulnerabilityCase(
        case_id=case_id,
        title=f"Draft case for {candidate_id}",
        root_cause="",
        cwe="unassessed",
        severity="unassessed",
        cve=None,
        primary_location=None,
        related_findings=[candidate_id],
        source_to_sink_trace=[],
        trigger_conditions="",
        poc=None,
        runtime_evidence=[],
        affected_modules=[],
        affected_versions=[],
        patch=None,
        patch_validation="not_started",
        confidence="unassessed",
        report_status="draft",
        evidence=list(evidence),
    )
