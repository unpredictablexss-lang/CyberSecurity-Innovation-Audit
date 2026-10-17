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


@dataclass(frozen=True)
class SymbolFact:
    file: str
    name: str
    kind: str
    qualified_name: str
    type_text: str = ""
    resolution_status: str = "unknown"

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class CfgEdgeFact:
    file: str
    source_block: str
    target_block: str
    condition: str = ""
    dominance_status: str = "unknown"
    proof_ref: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class RangeFact:
    file: str
    symbol: str
    minimum: Optional[int]
    maximum: Optional[int]
    unit: str = "unknown"
    confidence: str = "unknown"
    proof_ref: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class CallEdgeFact:
    file: str
    caller: str
    callee: str
    line: int
    resolution_status: str = "unresolved"
    depth: int = 0
    proof_ref: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class TaintFact:
    file: str
    source: str
    sink: str
    flow_status: str = "unknown"
    attacker_control: str = "unknown"
    proof_ref: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class UnknownFact:
    file: str
    subject: str
    reason: str
    missing_fact: str
    coverage_status: str = "unknown"

    def to_dict(self):
        return asdict(self)


def build_fact_view_v2(ast_by_file: dict, external_facts: Optional[dict] = None) -> dict:
    """Auditable v2 fact view for A/B analyzers.

    The builder never fabricates CFG, range or taint proof. External analyzers
    may supply reviewed facts through ``external_facts``; unresolved facts stay
    explicit unknowns.
    """
    external = external_facts or {}
    result = {}
    for path, index in sorted(ast_by_file.items()):
        status = index.get("parse_status", "failed")
        symbols = []
        for item in index.get("functions", []):
            symbols.append(SymbolFact(
                path, item["name"], "function", item.get("qualified", item["name"]),
                item.get("type_text", ""), "syntax_only",
            ).to_dict())
        for item in index.get("variables", []):
            symbols.append(SymbolFact(
                path, item["name"], "variable", item.get("qualified", item["name"]),
                item.get("type_text", ""), "syntax_only",
            ).to_dict())
        call_edges = [
            CallEdgeFact(
                path,
                item.get("caller", ""),
                item["name"],
                item["line"],
                "unresolved",
            ).to_dict()
            for item in index.get("calls", [])
        ]
        unknowns = [
            UnknownFact(
                path,
                "call_target",
                "AST syntax-only; target resolution was not computed.",
                "resolved_call_edge",
                "unknown",
            ).to_dict(),
            UnknownFact(
                path,
                "guard_dominance",
                "No complete CFG/dominance proof is available.",
                "cfg_edge_and_dominance",
                "unknown",
            ).to_dict(),
        ]
        if status != "complete":
            unknowns.append(UnknownFact(
                path, "source_semantics",
                "Parse status is not complete; semantic facts are unavailable.",
                "complete_parse", "partial" if status == "partial" else "unknown",
            ).to_dict())
        result[path] = {
            "schema_version": 2,
            "parse_status": status,
            "symbols": symbols,
            "cfg_edges": list(external.get(path, {}).get("cfg_edges", [])),
            "ranges": list(external.get(path, {}).get("ranges", [])),
            "call_edges": list(external.get(path, {}).get("call_edges", call_edges)),
            "taint": list(external.get(path, {}).get("taint", [])),
            "unknowns": list(external.get(path, {}).get("unknowns", unknowns)),
            "limitations": [
                "Syntax facts do not prove ownership, aliasing, attacker control or security impact.",
                "Missing CFG/range/taint facts remain unknown and are never inferred as safe.",
            ],
        }
    return result

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
