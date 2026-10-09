"""Minimal bounds/length/Parcel research slice.

This module is an offline shape probe, not a production OHScanner detector and
not a second scanner framework. It answers only whether a length value with a
Parcel-style source reaches a copy-size sink before or after a simple upper-bound
guard shape. It does not prove guard dominance, attacker control, allocation
capacity, integer overflow, reachability, or security impact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence, Tuple


@dataclass(frozen=True)
class ExperimentUnit:
    path: str
    text: str
    parse_status: str


@dataclass(frozen=True)
class SliceFact:
    kind: str
    path: str
    line: int
    symbol: str
    detail: str
    evidence_type: str = "syntax"


@dataclass(frozen=True)
class SliceObservation:
    path: str
    parse_status: str
    facts: Tuple[SliceFact, ...]
    candidate_shapes: int
    guard_shape: bool
    limitations: Tuple[str, ...]


_SOURCE_RE = re.compile(
    r"\b(?:uint32_t|size_t|uint64_t)\s+(?P<symbol>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<source>[A-Za-z_]\w*)\s*\.\s*ReadUint32\s*\(\s*\)"
)
_SINK_RE = re.compile(r"\b(?:std\s*::\s*)?memcpy\s*\(")
_GUARD_TEMPLATE = (
    r"\bif\s*\(\s*{symbol}\s*(?:>|>=)\s*(?P<bound>[A-Za-z_]\w*)\s*\)"
)


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _analyze_unit(unit: ExperimentUnit, use_guard_shape: bool) -> SliceObservation:
    if unit.parse_status != "complete":
        return SliceObservation(
            path=unit.path,
            parse_status=unit.parse_status,
            facts=(),
            candidate_shapes=0,
            guard_shape=False,
            limitations=(
                "Parse coverage is incomplete; this unit remains unknown and is not a safe control.",
            ),
        )

    facts = []
    sources = []
    for match in _SOURCE_RE.finditer(unit.text):
        symbol = match.group("symbol")
        sources.append((match.start(), symbol, match.group("source")))
        facts.append(
            SliceFact(
                kind="length_source",
                path=unit.path,
                line=_line(unit.text, match.start()),
                symbol=symbol,
                detail=f"{match.group('source')}.ReadUint32() assigned to {symbol}",
            )
        )

    candidate_shapes = 0
    guard_shape = False
    for source_position, symbol, _source in sources:
        guard_pattern = re.compile(_GUARD_TEMPLATE.format(symbol=re.escape(symbol)))
        guard_match = guard_pattern.search(unit.text, source_position)
        for sink_match in _SINK_RE.finditer(unit.text, source_position):
            line_text = unit.text.splitlines()[_line(unit.text, sink_match.start()) - 1]
            if not re.search(rf"\b{re.escape(symbol)}\b", line_text):
                continue
            facts.append(
                SliceFact(
                    kind="copy_size_sink",
                    path=unit.path,
                    line=_line(unit.text, sink_match.start()),
                    symbol=symbol,
                    detail=f"copy-size use of {symbol} in a memcpy-shaped call",
                )
            )
            observed_guard = (
                guard_match is not None
                and source_position < guard_match.start() < sink_match.start()
            )
            if observed_guard:
                guard_shape = True
                facts.append(
                    SliceFact(
                        kind="upper_bound_guard_shape",
                        path=unit.path,
                        line=_line(unit.text, guard_match.start()),
                        symbol=symbol,
                        detail=f"simple {symbol} upper-bound guard precedes sink",
                    )
                )
            if use_guard_shape and observed_guard:
                continue
            candidate_shapes += 1

    return SliceObservation(
        path=unit.path,
        parse_status=unit.parse_status,
        facts=tuple(sorted(facts, key=lambda item: (item.path, item.line, item.kind, item.symbol))),
        candidate_shapes=candidate_shapes,
        guard_shape=guard_shape,
        limitations=(
            "Syntax ordering is not CFG dominance; early returns, aliases, loops, and exceptions are not modeled.",
            "Parcel ReadUint32 is treated as an experiment label only; attacker control and destination capacity are unproved.",
            "No integer-overflow, truncation, allocation-size, or runtime validation is performed.",
        ),
    )


def evaluate_slice(
    units: Sequence[ExperimentUnit],
    use_guard_shape: bool = True,
) -> Tuple[SliceObservation, ...]:
    return tuple(
        sorted(
            (_analyze_unit(unit, use_guard_shape) for unit in units),
            key=lambda item: item.path,
        )
    )

def _load_fixture_units() -> Tuple[ExperimentUnit, ...]:
    from tests.detectors.fixture_support import BOUNDS_FIXTURES, load_units

    return tuple(
        ExperimentUnit(
            path=unit.path,
            text=unit.text,
            parse_status=unit.parse_status,
        )
        for unit in load_units(BOUNDS_FIXTURES)
    )


if __name__ == "__main__":
    import json

    rows = []
    for mode, use_guard in (("base_source_sink", False), ("plus_guard_shape", True)):
        observations = evaluate_slice(_load_fixture_units(), use_guard_shape=use_guard)
        rows.append(
            {
                "mode": mode,
                "observations": [
                    {
                        "path": item.path,
                        "parse_status": item.parse_status,
                        "candidate_shapes": item.candidate_shapes,
                        "guard_shape": item.guard_shape,
                        "fact_count": len(item.facts),
                    }
                    for item in observations
                ],
            }
        )
    print(json.dumps({"experiment": "bounds_length_parcel_minimal_slice", "modes": rows}, indent=2))
