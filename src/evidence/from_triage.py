"""Convert human review annotations into the project Evidence schema.

One CandidateReviewPacket can produce multiple evidence entries (one per
reviewed dimension). This records the "who reviewed what and why" record in a
standard shape without promoting a candidate to a vulnerability.
"""

from typing import List

from src.core.case import make_evidence_id
from src.core.evidence import Evidence
from src.triage.review import CandidateReviewPacket


def evidence_from_review_packet(
    packet: CandidateReviewPacket,
) -> List[Evidence]:
    evidences: List[Evidence] = []
    review = packet.review
    location = f"{packet.file}:{packet.line}"

    def add(field: str, proposition: str) -> None:
        value = getattr(review, field)
        if not value or value in {"unreviewed", "unknown", "not_started"}:
            return
        evidences.append(
            Evidence(
                evidence_id=make_evidence_id(
                    f"review:{packet.candidate_id}:{field}", value
                ),
                type="human_review",
                source="manual_review",
                location=location,
                content=f"{field}={value}",
                proposition=proposition,
                confidence=1.0,
            )
        )

    add("review_status", f"Manual review set status to {review.review_status}")
    add("input_control", "Manual review assessed input control")
    add("destination_capacity", "Manual review assessed destination capacity")
    add("length_origin", "Manual review assessed length origin")
    add("guard_evidence", "Manual review assessed guard evidence")
    add("reachability", "Manual review assessed reachability")
    add("security_impact", "Manual review assessed security impact")
    add("runtime_validation", "Manual review recorded runtime validation state")

    for note in review.reviewer_notes:
        evidences.append(
            Evidence(
                evidence_id=make_evidence_id(
                    f"review:{packet.candidate_id}:note", note
                ),
                type="human_review",
                source="manual_review",
                location=location,
                content=note,
                proposition="Manual review note",
                confidence=1.0,
            )
        )

    return evidences
