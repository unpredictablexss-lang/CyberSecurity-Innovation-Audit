"""M1.5 minimal, syntax-only fact interface for independently developed detectors.

This is NOT CFG, compiler-level name resolution, guard dominance or taint.
Never infer missing proof from a function/call outline.
"""

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass(frozen=True)
class FunctionFact:
    file: str
    name: str
    start_line: int
    end_line: int
    parse_status: str
    type_resolution: str = "not_computed"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class CallFact:
    file: str
    expression: str
    line: int
    arguments: tuple[str, ...]
    parse_status: str
    resolved_target: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        data["arguments"] = list(self.arguments)
        return data


@dataclass(frozen=True)
class GuardFact:
    """A claim supplied by a future analyzer, NOT synthesized by M1.5."""
    file: str
    line: int
    condition: str
    guarded_region: Optional[str] = None
    dominance_status: str = "unknown"
    proof_ref: Optional[str] = None

    def to_dict(self):
        return asdict(self)


def build_syntax_facts(ast_by_file: dict) -> dict:
    """Map existing AST summaries into a small schema that teams can depend on."""
    result = {}
    for path, index in sorted(ast_by_file.items()):
        status = index.get("parse_status", "failed")
        result[path] = {
            "schema_version": 1,
            "parse_status": status,
            "functions": [
                FunctionFact(path, item["name"], item["start_line"],
                             item["end_line"], status).to_dict()
                for item in index.get("functions", [])
            ],
            "calls": [
                CallFact(path, item["name"], item["line"],
                         tuple(item.get("arguments", ())), status).to_dict()
                for item in index.get("calls", [])
            ],
            "guards": [],  # No guard dominance analysis has been implemented.
            "limitations": [
                "AST syntax-only; function type and call targets not resolved.",
                "Guard dominance, aliasing, value range and lifetime facts not computed.",
            ],
        }
    return result
