"""M0 first-party detector contract. Independent of third-party tool adapters."""

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Mapping, Optional, Protocol, Tuple
import hashlib
import re


def safe_relative_path(value: str) -> str:
    """Reject absolute, traversal, backslash, empty and noncanonical paths."""
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
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
class DetectorFinding:
    file: str
    line: int
    rule_id: str
    message: str
    evidence_type: str = "pattern"
    column: Optional[int] = None
    candidate_cwe: Optional[str] = None
    symbol: Optional[str] = None

    def __post_init__(self):
        safe_relative_path(self.file)
        if isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1:
            raise ValueError("invalid line number")
        if not self.rule_id or not self.message:
            raise ValueError("finding requires a rule and explanation")


@dataclass(frozen=True)
class DetectorRun:
    detector_id: str
    version: str
    status: str
    analyzed_files: Tuple[str, ...] = ()
    findings: Tuple[DetectorFinding, ...] = ()
    limitations: Tuple[str, ...] = ()

    def __post_init__(self):
        if self.status not in ("completed", "failed", "blocked"):
            raise ValueError("invalid detector run status")
        if not self.detector_id or not self.version:
            raise ValueError("missing detector identity")
        if len(self.analyzed_files) != len(set(self.analyzed_files)):
            raise ValueError("duplicate analyzed file")
        for path in self.analyzed_files:
            safe_relative_path(path)


class Detector(Protocol):
    detector_id: str
    version: str
    supported_languages: Tuple[str, ...]
    required_facts: Tuple[str, ...]

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        ...
