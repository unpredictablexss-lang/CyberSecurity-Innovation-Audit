"""M0 first-party detector contract. Independent of third-party tool adapters."""

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Mapping, Optional, Protocol, Tuple
import hashlib
import re


def safe_relative_path(value: str) -> str:
    """Reject absolute, traversal, backslash, empty and noncanonical paths."""
    if (not isinstance(value, str) or not value or "\\" in value
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("invalid source-relative path")
    path = PurePosixPath(value)
    if (path.is_absolute() or value.startswith("/") or ":" in value
            or any(part in (".", "..", "") for part in value.split("/"))
            or path.as_posix() != value):
        raise ValueError("source path must be canonical and relative")
    return value


@dataclass(frozen=True)
class SourceUnit:
    path: str
    language: str
    text: str
    sha256: str
    parse_status: str = "not_run"
    parse_issues: Tuple[str, ...] = ()

    def __post_init__(self):
        safe_relative_path(self.path)
        if self.language not in ("c", "cpp", "js", "ts", "arkts"):
            raise ValueError("unsupported language")
        if self.parse_status not in ("complete", "partial", "failed", "not_run"):
            raise ValueError("invalid parse status")
        if hashlib.sha256(self.text.encode("utf-8")).hexdigest() != self.sha256:
            raise ValueError("source content hash mismatch")


@dataclass(frozen=True)
class ScanRequest:
    request_id: str
    repository: str
    commit: str
    snapshot_sha256: str
    target_id: str
    profile_id: str = "m0-synthetic"
    provenance: str = "fixture"

    def __post_init__(self):
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.request_id, self.repository, self.commit,
                                 self.target_id, self.profile_id)):
            raise ValueError("missing scan identity")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ValueError("invalid declared repository name")
        if self.target_id != "current-component:" + self.repository:
            raise ValueError("target/repository mismatch")
        if not re.fullmatch(r"[a-f0-9]{64}", self.snapshot_sha256):
            raise ValueError("invalid snapshot SHA-256")
        if self.provenance not in ("fixture", "git_object"):
            raise ValueError("unknown source provenance")
        if self.provenance == "git_object" and (
                not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", self.commit)
                or self.profile_id != "light-ast"):
            raise ValueError("Git source inputs need a full commit SHA and light-ast profile")


@dataclass(frozen=True)
class ScanContext:
    request: ScanRequest
    units: Tuple[SourceUnit, ...]
    shared_facts: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self):
        paths = [unit.path for unit in self.units]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate source unit")
        if paths != sorted(paths):
            raise ValueError("source units must be sorted")


@dataclass(frozen=True)
class EvidenceObligation:
    """A check still required before this finding could be a security claim.

    M1.5 doesn't manufacture CFG/taint/guard dominance proof.
    """
    kind: str
    description: str
    status: str = "unknown"

    def __post_init__(self):
        if not self.kind.strip() or not self.description.strip():
            raise ValueError("evidence obligation needs kind and description")
        if self.status not in ("unknown", "missing", "satisfied", "not_applicable"):
            raise ValueError("invalid evidence obligation status")


@dataclass(frozen=True)
class DetectorFinding:
    file: str
    line: int
    rule_id: str
    message: str
    evidence_type: str = "pattern"
    column: Optional[int] = None
    candidate_cwe: Optional[str] = None
    symbol: Optional[str] = None
    evidence_obligations: Tuple[EvidenceObligation, ...] = ()
    # Optional candidate consequence, carried by the coverage sidecar only.
    # ToolDiagnostic/ToolRunResult v1 remain unchanged.
    consequence_impact: Optional[str] = None
    consequence_cwe: Optional[str] = None
    source_sha256: str = ""
    # A-CCR-03 layered identity inputs. These are optional and fail closed:
    # a missing field never falls back to message, line, or legacy ID.
    rule_version: Optional[str] = None
    rule_lineage_id: Optional[str] = None
    symbol_identity: Optional[str] = None
    ast_fingerprint: Optional[str] = None
    identity_quality: str = "unknown"

    def __post_init__(self):
        safe_relative_path(self.file)
        if self.source_sha256 and not re.fullmatch(r"[a-f0-9]{64}", self.source_sha256):
            raise ValueError("invalid finding source SHA-256")
        for key, value in (
            ("rule_version", self.rule_version),
            ("rule_lineage_id", self.rule_lineage_id),
            ("symbol_identity", self.symbol_identity),
            ("ast_fingerprint", self.ast_fingerprint),
        ):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError("invalid " + key)
        if self.identity_quality not in ("complete", "partial", "failed", "unknown"):
            raise ValueError("invalid identity quality")
        if not all(isinstance(item, EvidenceObligation) for item in self.evidence_obligations):
            raise ValueError("invalid evidence obligation")
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("invalid line number")
        if not self.rule_id or not self.message:
            raise ValueError("finding requires a rule and explanation")
        if self.consequence_cwe is not None and not re.fullmatch(r"CWE-[0-9]+", self.consequence_cwe):
            raise ValueError("invalid consequence CWE identifier")
        for value in (self.consequence_impact, self.consequence_cwe):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError("candidate consequence must be non-empty when provided")


@dataclass(frozen=True)
class DetectorRun:
    detector_id: str
    version: str
    status: str
    analyzed_files: Tuple[str, ...] = ()
    findings: Tuple[DetectorFinding, ...] = ()
    limitations: Tuple[str, ...] = ()
    # Optional per-file adapter metadata. A blocked run may still contain
    # completed files and tentative candidates from partially analyzed files.
    # Never reinterpret these as a fully completed ToolRunResult v1 scope.
    file_outcomes: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self):
        if self.status not in ("completed", "failed", "blocked"):
            raise ValueError("invalid detector run status")
        if not self.detector_id or not self.version:
            raise ValueError("missing detector identity")
        if len(self.analyzed_files) != len(set(self.analyzed_files)):
            raise ValueError("duplicate analyzed file")
        for path in self.analyzed_files:
            safe_relative_path(path)
        seen = set()
        for path, outcome in self.file_outcomes:
            safe_relative_path(path)
            if path in seen or outcome not in ("complete", "partial", "not_analyzed", "failed"):
                raise ValueError("invalid or duplicate detector per-file outcome")
            seen.add(path)
        # Execution completion and per-file analysis depth are independent.
        # The runner validates these outcomes against supplied source units.


class Detector(Protocol):
    detector_id: str
    version: str
    supported_languages: Tuple[str, ...]
    required_facts: Tuple[str, ...]

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        ...
