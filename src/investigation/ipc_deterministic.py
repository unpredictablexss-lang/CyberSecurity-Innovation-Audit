"""Deterministic, source-bound fact extraction for IPC/interface candidates.

This module packages facts already established by the pinned report and Git
source objects. It does not rerun a detector, infer reachability, prove guard
dominance, judge attacker control, or change evidence/status fields.
"""
from hashlib import sha1, sha256
from typing import Any, Callable, Mapping, Optional, Sequence
import json

from .contracts import Fact, FactBundle, GateCheck, stable_id

_SEMANTIC_GATE_AUTHORITY = {
    "entry_reachability": "build",
    "callee_and_policy": "source",
    "guard_dominance": "source",
    "attacker_control": "human",
    "cia_impact": "runtime",
}
_OBLIGATION_GATE_MAP = {
    "satisfied": "met",
    "missing": "not_met",
    "unknown": "unknown",
    "not_applicable": "not_applicable",
}


class InvestigationIntegrityError(ValueError):
    """Raised when candidate/source/report evidence cannot be bound safely."""


def _sha256(data: bytes) -> str:
    return sha256(data).hexdigest()


def _git_blob_ids(data: bytes):
    framed = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return {sha1(framed).hexdigest(), sha256(framed).hexdigest()}


def _workbench_identity(report, run, diagnostic):
    return _sha256(json.dumps([
        report["repository"],
        report["commit"],
        report["snapshot_sha256"],
        run["tool"],
        run["tool_version"],
        diagnostic["diagnostic_id"],
    ]).encode("utf-8"))


def _diagnostic_identity(detector_id, diagnostic, source_sha256):
    payload = "|".join((
        source_sha256,
        diagnostic["file"],
        str(diagnostic["line"]),
        diagnostic.get("rule_id") or "",
        diagnostic["message"],
    ))
    return detector_id + ":" + _sha256(payload.encode("utf-8"))[:16]


def _require_sha(value, name):
    if not isinstance(value, str) or len(value) != 64:
        raise InvestigationIntegrityError(f"{name} must be a SHA-256 hex digest")
    try:
        int(value, 16)
    except ValueError as error:
        raise InvestigationIntegrityError(f"{name} must be a SHA-256 hex digest") from error


def _find_candidate(report, candidate_id):
    for run in report.get("detector_runs", []):
        for diagnostic in run.get("diagnostics", []):
            identity = _workbench_identity(report, run, diagnostic)
            if identity == candidate_id:
                return run, diagnostic
    raise InvestigationIntegrityError("candidate not found in the fixed report")


def _same_candidate_fields(left, right):
    fields = (
        "diagnostic_id", "file", "line", "column", "rule_id", "message",
        "source_sha256",
    )
    return all(left.get(field) == right.get(field) for field in fields)


def _validate_primary_source(report, diagnostic, source):
    if not isinstance(source, Mapping):
        raise InvestigationIntegrityError("source must be an object")
    required = {"file", "commit", "sha256", "text"}
    missing = required - set(source)
    if missing:
        raise InvestigationIntegrityError(
            "source missing fields: " + ", ".join(sorted(missing))
        )
    if source["file"] != diagnostic["file"]:
        raise InvestigationIntegrityError("source file does not match candidate")
    if source["commit"] != report["commit"]:
        raise InvestigationIntegrityError("source commit does not match report")
    data = source["text"].encode("utf-8")
    actual_sha = _sha256(data)
    if source["sha256"] != actual_sha:
        raise InvestigationIntegrityError("source SHA-256 does not match source text")
    diagnostic_sha = diagnostic.get("source_sha256") or ""
    if diagnostic_sha and diagnostic_sha != actual_sha:
        raise InvestigationIntegrityError("candidate source SHA-256 mismatch")
    line = diagnostic.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise InvestigationIntegrityError("candidate line is invalid")
    if line > len(source["text"].splitlines()):
        raise InvestigationIntegrityError("candidate line is outside source")
    blob = source.get("blob")
    blob_verified = bool(blob) and blob in _git_blob_ids(data)
    if blob and not blob_verified:
        raise InvestigationIntegrityError("source blob ID does not match source bytes")
    return actual_sha, blob, blob_verified


def _validate_source_evidence(record, candidate_id, report, report_sha256, loader):
    if not isinstance(record, Mapping):
        raise InvestigationIntegrityError("source evidence must be an object")
    if record.get("kind") != "source_excerpt":
        raise InvestigationIntegrityError("unsupported supplemental evidence kind")
    required = {
        "id", "candidate_id", "repository", "commit", "git_tree",
        "snapshot_sha256", "report_sha256", "file", "blob", "source_sha256",
        "start_line", "end_line", "text", "excerpt_sha256",
    }
    missing = required - set(record)
    if missing:
        raise InvestigationIntegrityError(
            "source evidence missing fields: " + ", ".join(sorted(missing))
        )
    if record["candidate_id"] != candidate_id:
        raise InvestigationIntegrityError("source evidence belongs to another candidate")
    for key in ("repository", "commit", "git_tree", "snapshot_sha256"):
        if record[key] != report.get(key):
            raise InvestigationIntegrityError(f"source evidence {key} mismatch")
    if record["report_sha256"] != report_sha256:
        raise InvestigationIntegrityError("source evidence report hash mismatch")
    source = loader(record["file"])
    if source.get("blob") != record["blob"] or source.get("sha256") != record["source_sha256"]:
        raise InvestigationIntegrityError("source evidence source object mismatch")
    lines = source["text"].splitlines(keepends=True)
    start, end = record["start_line"], record["end_line"]
    if (
        not isinstance(start, int) or isinstance(start, bool)
        or not isinstance(end, int) or isinstance(end, bool)
        or not 1 <= start <= end <= len(lines)
    ):
        raise InvestigationIntegrityError("source evidence line range is invalid")
    excerpt = "".join(lines[start - 1:end])
    if excerpt != record["text"] or _sha256(excerpt.encode("utf-8")) != record["excerpt_sha256"]:
        raise InvestigationIntegrityError("source evidence excerpt hash mismatch")
    return source, excerpt


def _fact(kind, authority, statement, value, candidate_id, evidence_refs=(), reproducibility=None):
    body = {
        "candidate_id": candidate_id,
        "kind": kind,
        "statement": statement,
        "value": value,
        "evidence_refs": list(evidence_refs),
        "reproducibility": dict(reproducibility or {}),
    }
    return Fact(
        fact_id=stable_id("ohscanner-investigation-fact-v1", body),
        kind=kind,
        authority=authority,
        statement=statement,
        value=value,
        evidence_refs=tuple(evidence_refs),
        reproducibility=dict(reproducibility or {}),
    )


def _gate(name, status, explanation, evidence_refs=(), obligation_kind=None):
    return GateCheck(
        name=name,
        status=status,
        explanation=explanation,
        evidence_refs=tuple(evidence_refs),
        obligation_kind=obligation_kind,
    )


def build_ipc_fact_bundle(
    *,
    report: Mapping[str, Any],
    candidate_id: str,
    source: Mapping[str, Any],
    report_sha256: str,
    report_bytes: Optional[bytes] = None,
    candidate_record: Optional[Mapping[str, Any]] = None,
    source_evidence: Sequence[Mapping[str, Any]] = (),
    source_loader: Optional[Callable[[str], Mapping[str, Any]]] = None,
) -> FactBundle:
    """Build a deterministic fact bundle without changing any source result."""
    if not isinstance(report, Mapping):
        raise InvestigationIntegrityError("report must be an object")
    _require_sha(report_sha256, "report_sha256")
    report_integrity = "unknown"
    if report_bytes is not None:
        if _sha256(report_bytes) != report_sha256:
            raise InvestigationIntegrityError("report bytes SHA-256 mismatch")
        try:
            decoded_report = json.loads(report_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvestigationIntegrityError("report bytes are not valid JSON") from error
        if decoded_report != report:
            raise InvestigationIntegrityError("report object differs from verified report bytes")
        report_integrity = "met"
    run, raw_diagnostic = _find_candidate(report, candidate_id)
    diagnostic = dict(raw_diagnostic)
    if candidate_record is not None:
        if not isinstance(candidate_record, Mapping):
            raise InvestigationIntegrityError("candidate_record must be an object")
        if not _same_candidate_fields(raw_diagnostic, candidate_record):
            raise InvestigationIntegrityError("candidate record differs from fixed report")
        diagnostic.update(candidate_record)
    if not isinstance(diagnostic, Mapping):
        raise InvestigationIntegrityError("candidate diagnostic must be an object")

    if diagnostic.get("provider") != run["tool"]:
        raise InvestigationIntegrityError("candidate detector provider mismatch")
    source_sha, blob, blob_verified = _validate_primary_source(report, diagnostic, source)
    run_schema = run.get("schema_version")
    diagnostic_id = diagnostic.get("diagnostic_id") or ""
    identity_verified = False
    if run_schema == 2 and source_sha:
        expected_diagnostic = _diagnostic_identity(run["tool"], diagnostic, source_sha)
        if diagnostic_id != expected_diagnostic:
            raise InvestigationIntegrityError("candidate diagnostic identity mismatch")
        identity_verified = True

    evidence_record = diagnostic.get("evidence") or {}
    obligations_raw = evidence_record.get("obligations")
    if obligations_raw is not None and not isinstance(obligations_raw, list):
        raise InvestigationIntegrityError("obligations must be an array when recorded")
    obligation_inventory = "recorded" if isinstance(obligations_raw, list) else "unknown"
    obligations = tuple(
        {
            "kind": item["kind"],
            "description": item["description"],
            "status": item["status"],
        }
        for item in (obligations_raw or [])
    )

    facts = [
        _fact(
            "candidate_identity",
            "detector",
            "The fixed report contains this diagnostic identity.",
            {
                "diagnostic_id": diagnostic_id,
                "workbench_candidate_id": candidate_id,
                "detector_id": run["tool"],
                "detector_version": run["tool_version"],
                "rule_id": diagnostic.get("rule_id"),
                "file": diagnostic.get("file"),
                "line": diagnostic.get("line"),
                "column": diagnostic.get("column"),
                "symbol": diagnostic.get("symbol"),
                "identity_recomputed": identity_verified,
            },
            candidate_id,
            (diagnostic_id,),
            {"operation": "recompute diagnostic identity"},
        ),
        _fact(
            "source_binding",
            "git_object",
            "The candidate is bound to the recorded fixed source object.",
            {
                "repository": report["repository"],
                "commit": report["commit"],
                "git_tree": report.get("git_tree"),
                "snapshot_sha256": report["snapshot_sha256"],
                "report_sha256": report_sha256,
                "file": source["file"],
                "blob": blob,
                "source_sha256": source_sha,
                "blob_verified": blob_verified,
                "binding_status": "verified" if blob_verified else "unknown",
            },
            candidate_id,
            tuple(filter(None, (diagnostic_id, blob, source_sha))),
            {"operation": "hash source bytes and Git blob framing"},
        ),
        _fact(
            "detector_observation",
            "detector",
            "The detector recorded a candidate; this is not a vulnerability conclusion.",
            {
                "status": run.get("status"),
                "schema_version": run_schema,
                "evidence_type": diagnostic.get("evidence_type"),
                "severity": diagnostic.get("severity"),
                "candidate_cwe": diagnostic.get("candidate_cwe"),
                "consequence_impact": diagnostic.get("consequence_impact"),
                "consequence_cwe": diagnostic.get("consequence_cwe"),
                "message": diagnostic.get("message"),
                "limitations": list(run.get("limitations", [])),
            },
            candidate_id,
            (diagnostic_id,),
            {"operation": "copy fixed detector fields without reinterpretation"},
        ),
        _fact(
            "coverage",
            "detector",
            "Coverage state is copied from the fixed detector run and sidecar.",
            {
                "run_status": run.get("status"),
                "analysis_status": evidence_record.get("analysis_status"),
                "parsing": list(run.get("parsing", [])),
                "coverage": evidence_record.get("source_binding", {}),
            },
            candidate_id,
            (diagnostic_id,),
            {"operation": "copy run parsing and evidence-sidecar coverage"},
        ),
        _fact(
            "obligation_inventory",
            "detector",
            "Evidence obligations are preserved exactly when the run recorded them.",
            {
                "inventory": obligation_inventory,
                "obligations": [dict(item) for item in obligations],
            },
            candidate_id,
            (diagnostic_id,),
            {"operation": "copy obligation list without status edits"},
        ),
    ]

    loader = source_loader or (lambda _file: source)
    for record in source_evidence:
        evidence_source, excerpt = _validate_source_evidence(
            record, candidate_id, report, report_sha256, loader
        )
        facts.append(_fact(
            "source_excerpt",
            "human",
            "A human-selected fixed source excerpt is recorded for review context.",
            {
                "evidence_id": record["id"],
                "file": record["file"],
                "start_line": record["start_line"],
                "end_line": record["end_line"],
                "excerpt_sha256": record["excerpt_sha256"],
                "source_sha256": evidence_source["sha256"],
                "note": record.get("note", ""),
            },
            candidate_id,
            ("source_evidence:" + record["id"],),
            {
                "operation": "verify fixed source range and excerpt SHA-256",
                "excerpt": excerpt,
            },
        ))

    gate_results = []

    def add_gate(gate, authority, evidence_refs=()):
        gate_results.append(gate)
        facts.append(_fact(
            "evidence_gate",
            authority,
            gate.explanation,
            {"name": gate.name, "status": gate.status},
            candidate_id,
            evidence_refs,
            {"operation": "deterministic evidence-gate projection"},
        ))

    report_gate = _gate(
        "report_integrity",
        report_integrity,
        "Report bytes were recomputed against the committed report hash."
        if report_integrity == "met"
        else "Report integrity was prevalidated by the workbench, but raw bytes were not supplied here.",
        (report_sha256,),
    )
    add_gate(report_gate, "git_object", (report_sha256,))
    source_gate = _gate(
        "source_integrity",
        "met" if blob_verified else "unknown",
        "Source bytes and Git blob identity match."
        if blob_verified
        else "Source SHA-256 is known, but Git blob identity is absent or unverified.",
        tuple(filter(None, (source_sha, blob))),
    )
    add_gate(source_gate, "git_object", (source_sha,))
    binding_gate = _gate(
        "source_binding",
        "met" if blob_verified and identity_verified else "partial",
        "Candidate, source object, report and detector identity are mutually bound."
        if blob_verified and identity_verified
        else "Available fields are consistent, but at least one identity component is unverified.",
        tuple(filter(None, (candidate_id, source_sha, blob))),
    )
    add_gate(binding_gate, "detector", (candidate_id,))
    identity_gate = _gate(
        "candidate_identity",
        "met" if identity_verified else "unknown",
        "Diagnostic identity was recomputed from source-bound fields."
        if identity_verified
        else "Legacy or partially bound diagnostic identity was not recomputed.",
        (candidate_id,),
    )
    add_gate(identity_gate, "detector", (candidate_id,))
    record_gate = _gate(
        "record_format",
        "met",
        "The fact bundle passed deterministic structure and hash validation.",
        (candidate_id,),
    )
    add_gate(record_gate, "detector", (candidate_id,))
    analysis_state = evidence_record.get("analysis_status")
    coverage_status = (
        "met" if run.get("status") == "completed" and analysis_state == "analyzed"
        else "partial" if analysis_state == "partial"
        else "unknown"
    )
    coverage_gate = _gate(
        "analysis_coverage",
        coverage_status,
        "The candidate source was completely analyzed."
        if coverage_status == "met"
        else "Analysis coverage is partial or unknown; no safety inference is allowed.",
        (diagnostic_id,),
    )
    add_gate(coverage_gate, "detector", (diagnostic_id,))

    obligation_by_kind = {item["kind"]: item for item in obligations}
    gate_specs = [
        ("entry_reachability", "entry_reachability"),
        ("callee_and_policy", "callee_and_policy"),
        ("guard_dominance", None),
        ("attacker_control", None),
        ("cia_impact", None),
        ("descriptor_identity_mismatch", "descriptor_identity_mismatch"),
        ("descriptor_identity_unresolved", "descriptor_identity_unresolved"),
        ("dispatch_binding", "dispatch_binding"),
        ("consequence", "consequence"),
        ("security_impact", "security_impact"),
        ("parse_completeness_impact", "parse_completeness_impact"),
    ]
    semantic_gates = []
    for name, obligation_kind in gate_specs:
        if name.startswith("descriptor_") or name in {
            "dispatch_binding", "consequence",
            "parse_completeness_impact",
        }:
            if obligation_kind not in obligation_by_kind:
                continue
        item = obligation_by_kind.get(obligation_kind) if obligation_kind else None
        status = _OBLIGATION_GATE_MAP[item["status"]] if item else "unknown"
        explanation = (
            item["description"] if item else
            "No deterministic source-bound proof is available for this semantic gate."
        )
        gate = _gate(name, status, explanation, (candidate_id,), obligation_kind)
        semantic_gates.append(gate)
        add_gate(gate, "unknown", (candidate_id,))

    gate_fact_by_name = {
        fact.value["name"]: fact.fact_id
        for fact in facts
        if fact.kind == "evidence_gate"
    }
    next_checks = []
    for gate in semantic_gates[:5]:
        if gate.status in {"met", "not_applicable"}:
            continue
        next_checks.append({
            "check_id": stable_id("ohscanner-next-check-v1", {
                "candidate_id": candidate_id,
                "gate": gate.name,
            }),
            "question": (
                "Establish " + gate.name.replace("_", " ")
                + " with source/build/runtime evidence."
            ),
            "required_authority": _SEMANTIC_GATE_AUTHORITY.get(gate.name, "human"),
            "status": "missing" if gate.status == "not_met" else "unknown",
            "evidence_refs": [gate_fact_by_name[gate.name]],
        })

    limitations = list(dict.fromkeys(run.get("limitations", [])))
    if obligation_inventory == "unknown":
        limitations.append(
            "Obligation inventory is unknown for this candidate; an empty list must not be read as no obligations."
        )
    limitations.extend([
        "AST/pattern interpretation does not prove ownership, dominance, concurrency, attacker control or impact.",
        "No draft or review text is used to satisfy a semantic evidence gate.",
    ])

    analysis_status = (
        "failed" if run.get("status") == "failed"
        else "blocked" if run.get("status") == "blocked"
        else "partial" if analysis_state == "partial" or obligation_inventory == "unknown"
        else "complete"
    )
    return FactBundle(
        candidate_identity={
            "candidate_id": candidate_id,
            "diagnostic_id": diagnostic_id,
            "detector_id": run["tool"],
            "detector_version": run["tool_version"],
            "rule_id": diagnostic.get("rule_id"),
            "file": diagnostic.get("file"),
            "line": diagnostic.get("line"),
            "column": diagnostic.get("column"),
            "symbol": diagnostic.get("symbol"),
        },
        source_binding={
            "repository": report["repository"],
            "commit": report["commit"],
            "git_tree": report.get("git_tree"),
            "snapshot_sha256": report["snapshot_sha256"],
            "report_sha256": report_sha256,
            "file": source["file"],
            "blob": blob,
            "source_sha256": source_sha,
            "status": "verified" if blob_verified else "unknown",
        },
        detector_observation={
            "detector_id": run["tool"],
            "detector_version": run["tool_version"],
            "run_status": run.get("status"),
            "evidence_type": diagnostic.get("evidence_type"),
            "candidate_cwe": diagnostic.get("candidate_cwe"),
            "consequence_impact": diagnostic.get("consequence_impact"),
            "consequence_cwe": diagnostic.get("consequence_cwe"),
            "message": diagnostic.get("message"),
        },
        facts=tuple(facts),
        obligations=obligations,
        gate_checks=tuple(gate_results),
        limitations=tuple(limitations),
        next_checks=tuple(next_checks),
        analysis_status=analysis_status,
        obligation_inventory=obligation_inventory,
    )