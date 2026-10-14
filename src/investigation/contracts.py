"""Contracts for deterministic IPC facts and non-promoting investigation drafts.

These types are intentionally separate from the scanner's public Detector
contract. They describe review support records and cannot change scan findings,
evidence obligations, reviews, cases, or vulnerability status.
"""
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Mapping, Optional, Tuple
import json
import re

FACT_BUNDLE_SCHEMA = "ohscanner.ipc-fact-bundle-v1"
DRAFT_SCHEMA = "ohscanner.investigation-draft-v1"

GATE_STATUSES = frozenset({
    "met", "not_met", "unknown", "partial", "not_applicable",
})
FACT_AUTHORITIES = frozenset({
    "git_object", "detector", "human", "historical", "model_draft", "unknown",
})
CLAIM_KINDS = frozenset({
    "hypothesis", "observation", "missing_evidence", "recommended_probe",
    "risk_statement",
})
PRODUCER_KINDS = frozenset({"human", "llm", "agent", "import"})
MISSING_EVIDENCE_STATUSES = frozenset({
    "missing", "unknown", "partial", "blocked",
})
REQUIRED_AUTHORITIES = frozenset({
    "source", "build", "runtime", "human", "vendor", "historical",
})
_HEX64 = re.compile(r"[a-f0-9]{64}")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def stable_id(prefix: str, value: Any) -> str:
    digest = sha256(prefix.encode("utf-8") + b"\0" + canonical_json(value)).hexdigest()
    return digest


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _sha64(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return value


def _exact_keys(value: Any, required: set, optional: set, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    keys = set(value)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ValueError(f"{name} missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"{name} has unsupported fields: {', '.join(sorted(extra))}")
    return value


def _string_list(value: Any, name: str, *, allow_empty: bool = True) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    result = tuple(_string(item, name) for item in value)
    if not allow_empty and not result:
        raise ValueError(f"{name} must not be empty")
    if len(result) != len(set(result)):
        raise ValueError(f"{name} must not contain duplicates")
    return result


@dataclass(frozen=True)
class Fact:
    fact_id: str
    kind: str
    authority: str
    statement: str
    value: Mapping[str, Any] = field(default_factory=dict)
    evidence_refs: Tuple[str, ...] = ()
    reproducibility: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        _sha64(self.fact_id, "fact_id")
        _string(self.kind, "fact.kind")
        if self.authority not in FACT_AUTHORITIES:
            raise ValueError("unsupported fact authority")
        _string(self.statement, "fact.statement")
        if not isinstance(self.value, Mapping):
            raise ValueError("fact.value must be an object")
        if not isinstance(self.reproducibility, Mapping):
            raise ValueError("fact.reproducibility must be an object")
        _string_list(self.evidence_refs, "fact.evidence_refs")

    def to_dict(self):
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "authority": self.authority,
            "statement": self.statement,
            "value": dict(self.value),
            "evidence_refs": list(self.evidence_refs),
            "reproducibility": dict(self.reproducibility),
        }


@dataclass(frozen=True)
class GateCheck:
    name: str
    status: str
    explanation: str
    evidence_refs: Tuple[str, ...] = ()
    obligation_kind: Optional[str] = None

    def __post_init__(self):
        _string(self.name, "gate.name")
        if self.status not in GATE_STATUSES:
            raise ValueError("invalid gate status")
        _string(self.explanation, "gate.explanation")
        _string_list(self.evidence_refs, "gate.evidence_refs")
        if self.obligation_kind is not None:
            _string(self.obligation_kind, "gate.obligation_kind")

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "explanation": self.explanation,
            "evidence_refs": list(self.evidence_refs),
            "obligation_kind": self.obligation_kind,
        }


@dataclass(frozen=True)
class FactBundle:
    candidate_identity: Mapping[str, Any]
    source_binding: Mapping[str, Any]
    detector_observation: Mapping[str, Any]
    facts: Tuple[Fact, ...]
    obligations: Tuple[Mapping[str, Any], ...]
    gate_checks: Tuple[GateCheck, ...]
    limitations: Tuple[str, ...]
    next_checks: Tuple[Mapping[str, Any], ...]
    analysis_status: str = "complete"
    obligation_inventory: str = "recorded"

    def __post_init__(self):
        for name, value in (
            ("candidate_identity", self.candidate_identity),
            ("source_binding", self.source_binding),
            ("detector_observation", self.detector_observation),
        ):
            if not isinstance(value, Mapping):
                raise ValueError(f"{name} must be an object")
        if self.analysis_status not in {"complete", "partial", "blocked", "failed"}:
            raise ValueError("invalid fact-bundle analysis status")
        if self.obligation_inventory not in {"recorded", "unknown"}:
            raise ValueError("invalid obligation inventory status")
        ids = [fact.fact_id for fact in self.facts]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate fact_id")
        for obligation in self.obligations:
            if not isinstance(obligation, Mapping):
                raise ValueError("obligation must be an object")
            _string(obligation.get("kind"), "obligation.kind")
            _string(obligation.get("description"), "obligation.description")
            if obligation.get("status") not in {
                "unknown", "missing", "satisfied", "not_applicable"
            }:
                raise ValueError("invalid obligation status")
        for item in self.next_checks:
            if not isinstance(item, Mapping):
                raise ValueError("next_checks entries must be objects")
            _string(item.get("check_id"), "next_check.check_id")
            _string(item.get("question"), "next_check.question")
        _string_list(self.limitations, "limitations")

    def _body(self):
        return {
            "schema_version": FACT_BUNDLE_SCHEMA,
            "candidate_identity": dict(self.candidate_identity),
            "source_binding": dict(self.source_binding),
            "detector_observation": dict(self.detector_observation),
            "facts": [fact.to_dict() for fact in self.facts],
            "obligations": [dict(item) for item in self.obligations],
            "gate_checks": [gate.to_dict() for gate in self.gate_checks],
            "limitations": list(self.limitations),
            "next_checks": [dict(item) for item in self.next_checks],
            "analysis_status": self.analysis_status,
            "obligation_inventory": self.obligation_inventory,
            "interpretation": (
                "Mechanical source-bound facts and open evidence gates only. "
                "No candidate status, obligation status, safety conclusion, or "
                "vulnerability verdict is changed."
            ),
        }

    @property
    def fact_bundle_sha256(self):
        return sha256(canonical_json(self._body())).hexdigest()

    def to_dict(self):
        data = self._body()
        data["fact_bundle_sha256"] = self.fact_bundle_sha256
        return data


@dataclass(frozen=True)
class InvestigationDraft:
    draft_id: str
    candidate_id: str
    producer: Mapping[str, Any]
    input_context: Mapping[str, Any]
    claims: Tuple[Mapping[str, Any], ...]
    assumptions: Tuple[str, ...]
    missing_evidence: Tuple[Mapping[str, Any], ...]
    recommended_probes: Tuple[Mapping[str, Any], ...]
    limitations: Tuple[str, ...]
    review_recommendations: Tuple[str, ...]
    supersedes_draft_id: Optional[str] = None
    created_at: Optional[str] = None
    status: str = "draft_only"
    can_promote: bool = False

    def __post_init__(self):
        _string(self.draft_id, "draft_id")
        _string(self.candidate_id, "candidate_id")
        if self.status != "draft_only" or self.can_promote is not False:
            raise ValueError("investigation drafts cannot change or promote status")
        for name, value in (
            ("producer", self.producer),
            ("input_context", self.input_context),
        ):
            if not isinstance(value, Mapping):
                raise ValueError(f"{name} must be an object")
        for item in self.claims:
            _exact_keys(
                item,
                {"claim_id", "kind", "text", "evidence_refs"},
                {"status"},
                "claim",
            )
            _string(item["claim_id"], "claim.claim_id")
            if item["kind"] not in CLAIM_KINDS:
                raise ValueError("unsupported claim kind")
            _string(item["text"], "claim.text")
            _string_list(item["evidence_refs"], "claim.evidence_refs", allow_empty=False)
            if item.get("status", "draft") != "draft":
                raise ValueError("claim status must remain draft")
        for item in self.missing_evidence:
            _exact_keys(
                item,
                {"item_id", "question", "required_authority", "status", "evidence_refs", "next_probe"},
                set(),
                "missing_evidence",
            )
            if item["required_authority"] not in REQUIRED_AUTHORITIES:
                raise ValueError("unsupported required authority")
            if item["status"] not in MISSING_EVIDENCE_STATUSES:
                raise ValueError("invalid missing-evidence status")
            _string_list(item["evidence_refs"], "missing_evidence.evidence_refs", allow_empty=False)
        for item in self.recommended_probes:
            _exact_keys(
                item,
                {"probe_id", "operation", "rationale", "evidence_refs", "authorization"},
                {"status"},
                "recommended_probe",
            )
            if item["authorization"] not in {"read_only", "controlled_validation"}:
                raise ValueError("unsupported probe authorization")
            if item.get("status", "suggested") != "suggested":
                raise ValueError("recommended probe status must remain suggested")
            _string_list(item["evidence_refs"], "recommended_probe.evidence_refs", allow_empty=False)
        _string_list(self.assumptions, "assumptions")
        _string_list(self.limitations, "limitations")
        _string_list(self.review_recommendations, "review_recommendations")
        if self.supersedes_draft_id is not None:
            _string(self.supersedes_draft_id, "supersedes_draft_id")
        if self.created_at is not None:
            _string(self.created_at, "created_at")

    def to_dict(self):
        return {
            "schema_version": DRAFT_SCHEMA,
            "draft_id": self.draft_id,
            "candidate_id": self.candidate_id,
            "producer": dict(self.producer),
            "input_context": dict(self.input_context),
            "claims": [dict(item) for item in self.claims],
            "assumptions": list(self.assumptions),
            "missing_evidence": [dict(item) for item in self.missing_evidence],
            "recommended_probes": [dict(item) for item in self.recommended_probes],
            "limitations": list(self.limitations),
            "review_recommendations": list(self.review_recommendations),
            "supersedes_draft_id": self.supersedes_draft_id,
            "created_at": self.created_at,
            "status": self.status,
            "can_promote": self.can_promote,
            "interpretation": (
                "Untrusted investigation draft only. It is not evidence, a "
                "review verdict, a vulnerability status, or authorization to "
                "execute a probe."
            ),
        }