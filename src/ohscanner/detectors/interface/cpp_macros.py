"""Token-based limited macro expansion with original-line provenance.

Only unambiguous nonvariadic definitions, no stringify/token paste/conditional
selection. This is not a full C++ preprocessor or trusted TU configuration.
"""
import hashlib
import re

from src.ohscanner.detectors.interface.ipc_repository import macro_catalog
from src.ohscanner.detectors.interface.cpp_permission import analyze_cpp

TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\s+|.', re.S)


def expand(source, headers, max_rounds=8):
    if not isinstance(source, bytes) or not isinstance(headers, dict):
        raise ValueError("source bytes and explicit header sources required")
    if len(headers) > 50 or any(not isinstance(v, bytes) for v in headers.values()) or sum(len(v) for v in headers.values()) > 8_000_000:
        raise ValueError("header source budget exceeded or invalid bytes")
    if type(max_rounds) is not int or not 1 <= max_rounds <= 8:
        raise ValueError("invalid expansion budget")
    catalog = macro_catalog(headers)
    content = source.decode("utf-8", errors="strict")
    if re.search(r'\bR"', content):
        return {"source": source, "line_map": {}, "expansions": [], "unknown": ["raw_string_tokenization_not_supported"]}
    # A char-origin map is bounded by the 2MB input/expanded-source limit.
    if len(source) > 2_000_000:
        raise ValueError("source too large")
    origins, line = [], 1
    for char in content:
        origins.append(line)
        line += char == "\n"
    evidence, unknown = [], []
    if re.search(r"(?m)^\s*#\s*(define|undef)\b", content):
        return {"source": source, "line_map": {}, "expansions": [], "unknown": ["source_local_define_or_undef_not_supported"]}
    for round_number in range(max_rounds):
        tokens = [(m.group(), m.start(), m.end()) for m in TOKEN.finditer(content)]
        replacements = []
        occupied = -1
        for i, (token, start, end) in enumerate(tokens):
            if start < occupied or token not in catalog:
                continue
            # Never expand a token appearing in a preprocessor directive.
            line_start = content.rfind("\n", 0, start)+1
            if content[line_start:start].lstrip().startswith("#"):
                continue
            definitions = catalog[token]["definitions"]
            if any(d["conditional_context"] for d in definitions):
                unknown.append(token+":conditional_definition_requires_build_profile")
                continue
            signatures = {(d["body"], tuple(d["parameters"]) if d["parameters"] is not None else None) for d in definitions}
            if len(signatures) != 1:
                unknown.append(token+":ambiguous_definition_variants")
                continue
            body, params = next(iter(signatures))
            if "#" in body or params is not None and "..." in params:
                unknown.append(token+":variadic_stringify_or_token_paste")
                continue
            arguments = []
            if params is not None:
                j = i+1
                while j < len(tokens) and tokens[j][0].isspace():
                    j += 1
                if j >= len(tokens) or tokens[j][0] != "(":
                    continue
                nesting, current = 0, []
                closed = False
                for j in range(j+1, len(tokens)):
                    value = tokens[j][0]
                    if value == ")" and nesting == 0:
                        if current or params:
                            arguments.append("".join(current).strip())
                        end = tokens[j][2]
                        closed = True
                        break
                    if value == "," and nesting == 0:
                        arguments.append("".join(current).strip())
                        current = []
                    else:
                        nesting += value in {"(", "[", "{"}
                        nesting -= value in {")", "]", "}"}
                        current.append(value)
                if not closed or len(arguments) != len(params):
                    unknown.append(token+":argument_shape_unknown")
                    continue
            bindings = dict(zip(params or (), arguments))
            substituted = "".join(bindings.get(m.group(), m.group()) for m in TOKEN.finditer(body))
            replacements.append((start, end, substituted, token, definitions))
            occupied = end
        if not replacements:
            break
        for start, end, replacement, token, definitions in reversed(replacements):
            original_line = origins[start]
            evidence.append({"macro": token, "original_line": original_line, "round": round_number+1,
                             "definition_locations": [{k: d[k] for k in ("file", "line", "source_sha256")} for d in definitions]})
            content = content[:start]+replacement+content[end:]
            origins = origins[:start]+[original_line]*len(replacement)+origins[end:]
        if len(content.encode()) > 2_000_000:
            raise ValueError("macro expansion size budget exceeded")
    else:
        unknown.append("macro_recursion_or_round_budget_exceeded")
    line_map = {}
    line = 1
    for char, original in zip(content, origins):
        line_map.setdefault(line, original)
        line += char == "\n"
    return {"source": content.encode(), "line_map": line_map, "expansions": evidence,
            "unknown": sorted(set(unknown))}


def analyze_with_macros(source, model, headers):
    if hashlib.sha256(source).hexdigest() != model.get("source_sha256"):
        raise ValueError("model/source hash mismatch before macro expansion")
    transformed = expand(source, headers)
    expanded_hash = hashlib.sha256(transformed["source"]).hexdigest()
    result = analyze_cpp(transformed["source"], {**model, "source_sha256": expanded_hash})
    for collection in ("calls", "guard_observations", "candidates"):
        for record in result[collection]:
            record["expanded_line"] = record["line"]
            record["line"] = transformed["line_map"].get(record["line"], record["line"])
            if "trace" in record:
                record["trace"] = [re.sub(r"if:(\d+):", lambda m: "if:"+str(transformed["line_map"].get(int(m[1]), int(m[1])))+":", step) for step in record["trace"]]
    result.update(source_sha256=model["source_sha256"], expanded_source_sha256=expanded_hash,
                  macro_expansions=transformed["expansions"], macro_unknown=transformed["unknown"])
    if transformed["unknown"]:
        result.update(status="blocked", assessment="unknown", candidates=[])
    result["limitations"].append("Limited explicit-header macro expansion; not full include/conditional compilation.")
    return result
