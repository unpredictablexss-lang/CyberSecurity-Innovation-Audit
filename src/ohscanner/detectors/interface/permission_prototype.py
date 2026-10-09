"""Local research prototype over explicitly authored synthetic graph facts.

Not the proposed Detector v1 API, not a C++/ArkTS parser, not a vulnerability
validator. No imports of main internals, scanner execution, or network access.
"""
from collections import deque
from pathlib import PurePosixPath
import re


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonempty text")
    return value


def _validate(case):
    if not isinstance(case, dict) or case.get("research_schema") != "interface-graph-fixture-v0":
        raise ValueError("unsupported private research schema")
    for key in ("case_id", "repository", "profile", "entry"):
        _text(case.get(key), key)
    commit = case.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be full SHA")
    path = _text(case.get("file"), "file")
    if "\\" in path or ":" in path or PurePosixPath(path).is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("file must be repository-relative")
    if case.get("parse_status") not in {"complete", "partial", "failed", "not_run"}:
        raise ValueError("invalid parsing status")
    if not isinstance(case.get("synthetic"), bool) or not isinstance(case.get("graph_complete"), bool):
        raise ValueError("explicit synthetic/graph_complete flags required")
    nodes = case.get("nodes")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 500:
        raise ValueError("nodes must contain 1..500 nodes")
    index = {}
    edge_count = 0
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("invalid node")
        identifier = _text(node.get("id"), "node id")
        if identifier in index:
            raise ValueError("duplicate node")
        if node.get("kind") not in {"entry", "step", "guard", "sink", "return", "identity_change"}:
            raise ValueError("unsupported node kind")
        if node["kind"] in {"guard", "sink"}:
            for key in ("subject", "permission", "resource"):
                _text(node.get(key), key)
        edges = node.get("edges")
        if not isinstance(edges, list):
            raise ValueError("explicit edges required")
        if any(not isinstance(edge, dict) for edge in edges):
            raise ValueError("edge must be an object")
        if node["kind"] == "return" and edges:
            raise ValueError("return cannot have successors")
        if node["kind"] == "guard":
            if sorted(str(edge.get("granted")) for edge in edges) != ["False", "True"]:
                raise ValueError("guard requires explicit grant and denial branches")
            if any(type(edge.get("granted")) is not bool for edge in edges):
                raise ValueError("grant facts must be boolean")
        index[identifier] = node
        edge_count += len(edges)
    if edge_count > 2000 or case["entry"] not in index or index[case["entry"]]["kind"] != "entry":
        raise ValueError("invalid entry or excessive edges")
    for node in nodes:
        for edge in node["edges"]:
            if not isinstance(edge.get("to"), str) or edge["to"] not in index:
                raise ValueError("dangling edge")
    return index


def analyze(case, max_states=1024):
    """Track grants per (caller, permission, resource) along fixture paths.

    Unknown facts block conclusions. Empty results say nothing about source code
    safety. The graph is caller supplied and only synthetic graphs are accepted
    for analysis until a reviewed source-to-CFG integration exists.
    """
    index = _validate(case)
    if type(max_states) is not int or not 1 <= max_states <= 10000:
        raise ValueError("max_states must be 1..10000")
    result = {"case_id": case["case_id"], "repository": case["repository"],
              "commit": case["commit"], "profile": case["profile"], "file": case["file"],
              "synthetic": case["synthetic"], "status": "completed", "coverage": "complete",
              "assessment": "no_uncovered_sink_in_fixture", "candidates": [],
              "confidence": "unassessed", "runtime_validation": "not_run",
              "validated_vulnerability": 0,
              "limitations": ["Authored graph facts only; no source parsing, path feasibility, "
                              "cross-language mapping, vulnerability or safety verdict."]}
    if not case["synthetic"] or case["parse_status"] != "complete" or not case["graph_complete"]:
        result.update(status="blocked", coverage="unknown", assessment="unknown")
        result["limitations"].append("Missing complete synthetic graph; real source integration pending.")
        return result
    queue = deque([(case["entry"], frozenset(), (case["entry"],))])
    visited = set()
    witnesses = {}
    while queue:
        identifier, grants, trace = queue.popleft()
        state = (identifier, grants)
        if state in visited:
            continue
        if len(visited) >= max_states:
            result.update(status="blocked", coverage="unknown", assessment="unknown", candidates=[])
            result["limitations"].append("State budget exhausted; partial findings withheld.")
            return result
        visited.add(state)
        node = index[identifier]
        if node["kind"] == "identity_change":
            grants = frozenset()
        obligation = tuple(node.get(key) for key in ("subject", "permission", "resource"))
        if node["kind"] == "sink" and obligation not in grants:
            witnesses.setdefault(identifier, {"sink": identifier, "trace": list(trace),
                "missing_obligation": dict(zip(("subject", "permission", "resource"), obligation)),
                "status": "candidate", "evidence_type": "control_flow",
                "evidence_origin": "synthetic_authored_graph", "confidence": "unassessed",
                "message": "Fixture path reaches modeled sink without matching caller authorization."})
        for edge in node["edges"]:
            next_grants = grants
            if node["kind"] == "guard":
                # A denial must revoke an earlier grant for the same obligation.
                next_grants = (grants | {obligation}) if edge["granted"] else (grants - {obligation})
            queue.append((edge["to"], frozenset(next_grants), trace + (edge["to"],)))
    result["candidates"] = [witnesses[key] for key in sorted(witnesses)]
    if witnesses:
        result["assessment"] = "candidate"
    result["explored_states"] = len(visited)
    return result
