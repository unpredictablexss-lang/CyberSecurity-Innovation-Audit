"""M1 shared frontend: reuse the existing Tree-sitter C/C++ parser.

JS/TS/ArkTS are indexed as source text only; no syntax, type, bridge or
permission evidence is inferred for them in this milestone.
"""

from collections import Counter
from hashlib import sha256
import json

from src.parser.ast import parse_source
from .contracts import SourceUnit
from .git_source import GitSource
from .language import parse_script_text


def index_sources(sources: tuple[GitSource, ...]):
    units = []
    ast_summary = {}
    for source in sources:
        text = source.data.decode("utf-8")
        status = "not_run"
        issues = []
        if source.language in ("c", "cpp"):
            try:
                index = parse_source(text, language=source.language)
                status = index.parse_status
                issues = [json.dumps(item, sort_keys=True) for item in index.parse_issues]
                ast_summary[source.path] = {
                    "parse_status": status,
                    "functions": [item.__dict__ for item in index.functions],
                    "calls": [item.__dict__ for item in index.calls],
                    "variables": [item.__dict__ for item in index.variables],
                }
            except (RuntimeError, ValueError) as error:
                status = "failed"
                issues = [type(error).__name__ + ": " + str(error)[:300]]
                ast_summary[source.path] = {"parse_status": "failed",
                                            "functions": [], "calls": [], "variables": []}
        else:
            index = parse_script_text(text, source.language)
            status = index["parse_status"]
            issues = [json.dumps(item, sort_keys=True) for item in index["parse_issues"]]
            ast_summary[source.path] = {
                "parse_status": status,
                "functions": index["functions"],
                "calls": index["calls"],
                "variables": index["variables"],
            }
        units.append(SourceUnit(
            path=source.path, language=source.language, text=text,
            sha256=sha256(source.data).hexdigest(),
            parse_status=status, parse_issues=tuple(issues),
        ))
    counts = dict(sorted(Counter(unit.parse_status for unit in units).items()))
    languages = dict(sorted(Counter(unit.language for unit in units).items()))
    return tuple(units), ast_summary, {"parsing_status": counts, "languages": languages}
