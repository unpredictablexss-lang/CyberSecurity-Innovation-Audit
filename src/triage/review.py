import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.triage.callsite import ParsedCall, parse_call_at_line


OBLIGATION_TEMPLATES = {
    "memcpy": [
        "destination has at least length writable bytes",
        "source has at least length readable bytes",
        "length computation is in range and does not overflow or truncate",
        "source and destination overlap rules are satisfied",
    ],
    "strcpy": [
        "destination capacity is at least strlen(source) + 1",
        "source is NUL-terminated and readable through the terminator",
        "source and destination do not overlap",
    ],
    "strcat": [
        "destination capacity is at least strlen(destination) + strlen(source) + 1",
        "destination is already NUL-terminated within its object",
        "source is NUL-terminated and readable",
        "source and destination do not overlap",
    ],
    "sprintf": [
        "destination capacity is large enough for the complete formatted output plus NUL",
        "format string and argument types are consistent",
        "all string-like arguments are valid for the formatting operation",
    ],
    "gets": [
        "no bounded destination length is available to gets",
        "the call must be treated as intrinsically unsafe if reachable",
    ],
}


@dataclass
class ReviewState:
    review_status: str = "unreviewed"
    input_control: str = "unknown"
    destination_capacity: str = "unknown"
    length_origin: str = "unknown"
    guard_evidence: str = "unknown"
    reachability: str = "unknown"
    security_impact: str = "unknown"
    runtime_validation: str = "not_started"
    reviewer_notes: List[str] = field(default_factory=list)


@dataclass
class CandidateReviewPacket:
    candidate_id: str
    rule_id: str
    file: str
    line: int
    function: Optional[str]
    call_name: str
    call_parse_status: str
    call_start_line: int
    call_end_line: int
    call_expression: str
    call_arguments: List[str]
    context_status: str
    context: Optional[str]
    obligations: List[str]
    review: ReviewState

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageReport:
    source_report: str
    target: str
    candidate_count: int
    packet_count: int
    packets: List[CandidateReviewPacket]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_report": self.source_report,
            "target": self.target,
            "candidate_count": self.candidate_count,
            "packet_count": self.packet_count,
            "packets": [packet.to_dict() for packet in self.packets],
            "interpretation": (
                "Triage packets structure review obligations only. They do not "
                "validate a vulnerability or change the source Finding status."
            ),
        }


def _call_name_from_rule(rule_id: str) -> str:
    prefix = "cpp.dangerous_call."
    if not rule_id.startswith(prefix):
        return "unknown"
    return rule_id[len(prefix) :]


def _candidate_id(target: Path, finding: Dict[str, Any]) -> str:
    file_path = Path(finding["file_path"])
    try:
        relative = file_path.resolve().relative_to(target.resolve()).as_posix()
    except (OSError, ValueError):
        relative = file_path.as_posix()

    identity = "|".join(
        [
            relative,
            str(finding.get("line")),
            str(finding.get("rule_id")),
            str(finding.get("evidence", "")),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _read_source_lines(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def build_triage_report(scan_report_path: Path) -> TriageReport:
    data = json.loads(scan_report_path.read_text(encoding="utf-8"))
    target = Path(data["target"]).resolve()
    findings = data.get("findings", [])

    packets: List[CandidateReviewPacket] = []
    source_cache: Dict[Path, List[str]] = {}

    for finding in findings:
        source_path = Path(finding["file_path"]).resolve()
        call_name = _call_name_from_rule(str(finding.get("rule_id", "")))

        parsed = ParsedCall(
            name=call_name,
            arguments=[],
            expression=str(finding.get("evidence", "")),
            start_line=int(finding["line"]),
            end_line=int(finding["line"]),
            status="source_unavailable",
        )

        if source_path.is_file() and call_name != "unknown":
            if source_path not in source_cache:
                source_cache[source_path] = _read_source_lines(source_path)
            lines = source_cache[source_path]
            parsed = parse_call_at_line(
                lines,
                line_number=int(finding["line"]),
                call_name=call_name,
            )

        packets.append(
            CandidateReviewPacket(
                candidate_id=_candidate_id(target, finding),
                rule_id=str(finding.get("rule_id", "")),
                file=str(source_path),
                line=int(finding["line"]),
                function=finding.get("function"),
                call_name=call_name,
                call_parse_status=parsed.status,
                call_start_line=parsed.start_line,
                call_end_line=parsed.end_line,
                call_expression=parsed.expression,
                call_arguments=parsed.arguments,
                context_status=str(finding.get("context_status", "unknown")),
                context=finding.get("context"),
                obligations=list(OBLIGATION_TEMPLATES.get(call_name, [])),
                review=ReviewState(),
            )
        )

    return TriageReport(
        source_report=str(scan_report_path.resolve()),
        target=str(target),
        candidate_count=int(data.get("finding_count", len(findings))),
        packet_count=len(packets),
        packets=packets,
    )


def render_markdown(report: TriageReport) -> str:
    lines = [
        "# Candidate Triage Packets",
        "",
        "> Structured review aid only. These packets do not validate vulnerabilities.",
        "",
        "## Summary",
        "",
        f"- Source report: {report.source_report}",
        f"- Target: {report.target}",
        f"- Candidate count: {report.candidate_count}",
        f"- Packet count: {report.packet_count}",
        "",
    ]

    for packet in report.packets:
        lines.extend(
            [
                f"## {packet.candidate_id}: {packet.call_name}",
                "",
                f"- Rule: {packet.rule_id}",
                f"- Location: {packet.file}:{packet.line}",
                f"- Function: {packet.function or 'unresolved'}",
                f"- Call parse status: {packet.call_parse_status}",
                f"- Call lines: {packet.call_start_line}-{packet.call_end_line}",
                f"- Context status: {packet.context_status}",
                f"- Review status: {packet.review.review_status}",
                "",
                "**Call expression**",
                "",
                "~~~c",
                packet.call_expression,
                "~~~",
                "",
                "**Arguments**",
                "",
            ]
        )

        if packet.call_arguments:
            for index, argument in enumerate(packet.call_arguments, start=1):
                lines.append(f"{index}. {argument}")
        else:
            lines.append("- unresolved")

        lines.extend(["", "**Security obligations to review**", ""])
        if packet.obligations:
            for obligation in packet.obligations:
                lines.append(f"- [ ] {obligation}")
        else:
            lines.append("- [ ] no template available; manual review required")

        lines.extend(
            [
                "",
                "**Review fields**",
                "",
                f"- input_control: {packet.review.input_control}",
                f"- destination_capacity: {packet.review.destination_capacity}",
                f"- length_origin: {packet.review.length_origin}",
                f"- guard_evidence: {packet.review.guard_evidence}",
                f"- reachability: {packet.review.reachability}",
                f"- security_impact: {packet.review.security_impact}",
                f"- runtime_validation: {packet.review.runtime_validation}",
                "",
                "**Context**",
                "",
                "~~~c",
                packet.context or "(unavailable)",
                "~~~",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_triage_reports(
    report: TriageReport,
    json_output: Path,
    markdown_output: Path,
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(report), encoding="utf-8")
