"""Patch-derived security obligations used to compare vulnerable/fixed code.

Obligations are review aids and evaluation labels. They never assert that a
candidate is a vulnerability and do not modify historical sample ground truth.
"""

from dataclasses import asdict, dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Dict, Tuple


OBLIGATION_STATUSES = {"proposed", "verified"}


def _safe_reference(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("evidence reference must not be empty")
    if any(ord(char) < 32 for char in value):
        raise ValueError("evidence reference contains control characters")
    if value.startswith("/") or "\\" in value or ".." in PurePosixPath(value).parts:
        raise ValueError("local evidence reference must be canonical and relative")
    return value


@dataclass(frozen=True)
class PatchObligation:
    obligation_id: str
    statement: str
    guard_relation: str
    effect: str
    evidence_refs: Tuple[str, ...] = ()
    status: str = "proposed"
    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.obligation_id):
            raise ValueError("obligation_id must be a safe identifier")
        for name in ("statement", "guard_relation", "effect"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if self.status not in OBLIGATION_STATUSES:
            raise ValueError("unsupported obligation status")
        refs = tuple(_safe_reference(item) for item in self.evidence_refs)
        limitations = tuple(self.limitations)
        if not all(isinstance(item, str) and item.strip() for item in limitations):
            raise ValueError("limitations must be non-empty strings")
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "limitations", limitations)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence_refs"] = list(self.evidence_refs)
        data["limitations"] = list(self.limitations)
        return data


@dataclass(frozen=True)
class PatchObligationSet:
    sample_id: str
    root_instance_id: str
    root_cause_group: str
    obligations: Tuple[PatchObligation, ...]
    development_participation: bool = False
    holdout_eligible: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("sample_id", "root_instance_id", "root_cause_group"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
                raise ValueError(f"{name} must be a safe identifier")
        obligations = tuple(self.obligations)
        if not obligations:
            raise ValueError("at least one patch obligation is required")
        ids = [item.obligation_id for item in obligations]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate patch obligation_id")
        if self.development_participation and self.holdout_eligible:
            raise ValueError("development participation makes a sample holdout-ineligible")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "sample_id": self.sample_id,
            "root_instance_id": self.root_instance_id,
            "root_cause_group": self.root_cause_group,
            "obligations": [item.to_dict() for item in self.obligations],
            "development_participation": self.development_participation,
            "holdout_eligible": self.holdout_eligible,
            "notes": self.notes,
            "interpretation": (
                "Patch obligations describe checks that distinguish a reviewed fix; "
                "they are not vulnerability verdicts."
            ),
        }


def load_patch_obligations(path: Path) -> PatchObligationSet:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("patch obligation sidecar requires schema_version 1")
    raw_obligations = data.get("obligations")
    if not isinstance(raw_obligations, list):
        raise ValueError("patch obligation sidecar requires an obligations list")
    obligations = []
    for item in raw_obligations:
        if not isinstance(item, dict):
            raise ValueError("patch obligation must be a JSON object")
        obligations.append(PatchObligation(
            obligation_id=item.get("obligation_id", ""),
            statement=item.get("statement", ""),
            guard_relation=item.get("guard_relation", ""),
            effect=item.get("effect", ""),
            evidence_refs=tuple(item.get("evidence_refs", []) or []),
            status=item.get("status", "proposed"),
            limitations=tuple(item.get("limitations", []) or []),
        ))
    return PatchObligationSet(
        sample_id=data.get("sample_id", ""),
        root_instance_id=data.get("root_instance_id", ""),
        root_cause_group=data.get("root_cause_group", ""),
        obligations=tuple(obligations),
        development_participation=bool(data.get("development_participation", False)),
        holdout_eligible=bool(data.get("holdout_eligible", False)),
        notes=str(data.get("notes", "")),
    )
