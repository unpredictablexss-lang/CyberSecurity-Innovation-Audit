"""Bounded macro expansion over explicitly supplied sources, with line provenance.

Ported from the round1 interface line (`draft/oh-interface-detectors-round1`,
`src/ohscanner/detectors/interface/cpp_macros.py`) -- the one part of that scheme
the v0.2 baseline did not absorb. It is ported rather than reinvented because the
refusal semantics are the reason it is worth having at all.

What it is: a token-level expander over macros whose definitions were handed to it
explicitly, carrying a per-character map back to the original line. What it is
not: a C++ preprocessor. `#include` is never followed, conditional definitions are
recorded rather than selected, and raw strings, variadic / stringify / token-paste
definitions and conflicting definition variants are refused rather than guessed.

Why the baseline wants it. `analysis.normalize_syntax` neutralizes a macro
argument that carries a statement so the file parses, but a guard that lives
*inside* a macro body stays invisible: AUTH-02/AUTH-03 then report an unguarded
sensitive path that the source does in fact guard. That is a false positive, the
direction the competition penalizes. Expanding the macro puts the real `return`
into the interpreted control flow.

Two deliberate deviations from the ported source:

1. An invocation is replaced whole, argument list included. round1 replaced only
   the macro-name token, so `#define CHECK(x) Allowed(x)` invoked as `CHECK(c)`
   became `Allowed(c)(c)` -- a call to the result of a call.
2. Refusals are split into *fatal* (the source could not be tokenized, or a
   `#undef` makes the catalogue unusable, so the caller must fall back to the
   unexpanded bytes) and *refused* (one macro was left as written). round1
   collapsed both into `unknown` and blocked the whole file, so a single
   ambiguous `LOG` cost the file every other expansion it could have had.

The catalogue is normally built for a whole scan (`catalog_for_units`), which is
also why a source-local `#define` is not fatal here: the source's own definitions
are already in the catalogue. `#undef` still is, because the catalogue has no way
to represent "defined up to here, not after".
"""
import hashlib
import re
from collections import defaultdict

MAX_ROUNDS = 8
MAX_SOURCE_BYTES = 2_000_000
MAX_EXPANDED_BYTES = 2_000_000

# Every character is consumed by exactly one alternative, so a token list can be
# turned back into the original string and per-character line origins line up.
TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\s+|.', re.S)

_RAW_STRING = re.compile(r'\bR"')
_LOCAL_DEFINE = re.compile(r"(?m)^\s*#\s*define\b")
_LOCAL_UNDEF = re.compile(r"(?m)^\s*#\s*undef\b")
_COMMENT_OR_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
_CONTROL_FLOW = re.compile(r"\b(?:return|break|continue|goto)\b|\bif\s*\(")

_HEADER_SUFFIX = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".inc")


def macro_catalog(sources):
    """Collect every `#define` variant, keyed by macro name.

    `sources` maps a path to its bytes. Comments are blanked (newlines kept) so a
    commented-out `#define` cannot define anything, and each variant records the
    file, physical line, parameter list, enclosing conditional context and the
    digest of the file it came from -- an expansion can always be traced back to
    the definition it used.

    Conditional context is recorded, never selected: a definition under
    `#ifdef FEATURE` is reported as conditional and the expander refuses it rather
    than assuming the feature is on.

    The one conditional that is *not* recorded is the including file's own guard
    (`#ifndef FOO_H` / `#define FOO_H`). It is the most common conditional in
    OpenHarmony headers by a wide margin, it does not select anything -- the header
    is either included once or not at all -- and treating it as a build-profile
    choice refuses nearly every macro defined in a header. The frame is dropped
    only when the pattern is syntactic: the frame's `#ifndef NAME` and a `#define
    NAME` inside it, with nothing between.
    """
    definitions = defaultdict(list)
    for path, data in sources.items():
        original = data.decode("utf-8", errors="replace")
        cleaned = _COMMENT_OR_LITERAL.sub(
            lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0))
            if m.group(0).startswith(("/*", "//")) else m.group(0), original)
        digest = hashlib.sha256(data).hexdigest()
        logical, start, frames = "", 1, []
        for number, line in enumerate(cleaned.splitlines(), 1):
            if not logical:
                start = number
            continued = line.rstrip().endswith("\\")
            logical += line.rstrip().removesuffix("\\") + " "
            if continued:
                continue
            directive = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", logical)
            if directive:
                command, argument = directive.groups()
                if command in {"if", "ifdef", "ifndef"}:
                    frames.append({"condition": command + argument.strip(), "is_guard": False,
                                   "guard_name": argument.strip() if command == "ifndef" else None})
                elif command in {"elif", "else"} and frames:
                    frames[-1].update(condition=command + argument.strip(), guard_name=None)
                elif command == "endif" and frames:
                    frames.pop()
            match = re.match(r"\s*#\s*define\s+(\w+)(\([^)]*\))?\s+(.*)", logical)
            if match:
                name, params, body = match.groups()
                if frames and frames[-1]["guard_name"] == name:
                    frames[-1].update(is_guard=True, guard_name=None)
                definitions[name].append({
                    "file": path, "line": start, "body": body.strip(),
                    "parameters": [p.strip() for p in params[1:-1].split(",")] if params else None,
                    "conditional_context": [f["condition"] for f in frames if not f["is_guard"]],
                    "source_sha256": digest,
                })
            logical = ""
    return {name: tuple(variants) for name, variants in definitions.items()}


def catalog_for_units(units, max_sources, max_bytes):
    """Catalogue the definitions a scan can see, headers first.

    A guard macro lives in a header far more often than in a translation unit, so
    headers are admitted before `.cpp` bodies when the budget bites. Selection is
    deterministic (headers first, then path order) and the truncation is reported
    rather than silent: an uncatalogued macro is simply left unexpanded, which
    degrades to the pre-expansion behaviour instead of guessing.

    Returns `(catalog, sources_used, bytes_used, truncated)`.
    """
    ordered = sorted(units, key=lambda u: (not u.path.endswith(_HEADER_SUFFIX), u.path))
    sources, total, truncated = {}, 0, False
    for unit in ordered:
        if unit.language not in ("c", "cpp"):
            continue
        data = unit.text.encode("utf-8")
        if len(sources) >= max_sources or total + len(data) > max_bytes:
            truncated = True
            break
        sources[unit.path] = data
        total += len(data)
    return macro_catalog(sources), len(sources), total, truncated


class Expansion:
    """The result of expanding one source against a catalogue.

    `source` is what the caller should tokenize. When `fatal` is non-empty it is
    the original bytes and nothing was applied; otherwise it carries every
    unambiguous expansion and `line_map` translates an expanded line number back
    to the line it was written on.
    """

    __slots__ = ("source", "line_map", "expansions", "refused", "fatal")

    def __init__(self, source, line_map, expansions, refused, fatal):
        self.source = source
        self.line_map = line_map
        self.expansions = tuple(expansions)
        self.refused = tuple(refused)
        self.fatal = tuple(fatal)

    @property
    def applied(self):
        return not self.fatal and bool(self.expansions)

    @property
    def unknown(self):
        """round1's single notion: reasons this source was not fully expanded."""
        return self.fatal + tuple(reason for _, reason in self.refused)

    @property
    def carried_control_flow(self):
        """Expansions that put a statement -- a guard, typically -- into the body."""
        return tuple(e for e in self.expansions if e["carries_control_flow"])

    def original_line(self, line):
        return self.line_map.get(line, line)


def _origin_lines(content):
    origins, line = [], 1
    for char in content:
        origins.append(line)
        line += char == "\n"
    return origins


def _line_map(content, origins):
    result, line = {}, 1
    for char, original in zip(content, origins):
        result.setdefault(line, original)
        line += char == "\n"
    return result


def _expand_text(content, catalog, max_rounds, allow_local_defines):
    """Core loop. Returns `(text, origins, fatal, evidence, refused)`.

    `text` is None when a fatal reason was hit; otherwise `origins[i]` is the
    original line of `text[i]`.
    """
    fatal, refused, evidence = [], [], []
    if len(content.encode("utf-8", "surrogatepass")) > MAX_SOURCE_BYTES:
        return None, [], ["source_too_large"], evidence, refused
    if _RAW_STRING.search(content):
        return None, [], ["raw_string_tokenization_not_supported"], evidence, refused
    if _LOCAL_UNDEF.search(content):
        return None, [], ["source_local_undef_not_supported"], evidence, refused
    if not allow_local_defines and _LOCAL_DEFINE.search(content):
        return None, [], ["source_local_define_not_supported"], evidence, refused

    origins = _origin_lines(content)
    original, original_origins = content, origins
    seen = {content}
    for round_number in range(max_rounds):
        tokens = [(m.group(), m.start(), m.end()) for m in TOKEN.finditer(content)]
        replacements, occupied = [], -1
        for index, (token, start, end) in enumerate(tokens):
            if start < occupied or token not in catalog:
                continue
            # A macro name in a preprocessor directive is never an invocation.
            line_start = content.rfind("\n", 0, start) + 1
            if content[line_start:start].lstrip().startswith("#"):
                continue
            definitions = catalog[token]
            if any(d["conditional_context"] for d in definitions):
                refused.append((token, "conditional_definition_requires_build_profile"))
                continue
            signatures = {(d["body"], tuple(d["parameters"]) if d["parameters"] is not None else None)
                          for d in definitions}
            if len(signatures) != 1:
                refused.append((token, "ambiguous_definition_variants"))
                continue
            body, params = next(iter(signatures))
            if "#" in body or (params is not None and "..." in params):
                refused.append((token, "variadic_stringify_or_token_paste"))
                continue
            arguments, consumed_end = [], end
            if params is not None:
                cursor = index + 1
                while cursor < len(tokens) and tokens[cursor][0].isspace():
                    cursor += 1
                if cursor >= len(tokens) or tokens[cursor][0] != "(":
                    continue        # the name is used, but not as an invocation
                nesting, current, closed = 0, [], False
                for cursor in range(cursor + 1, len(tokens)):
                    value = tokens[cursor][0]
                    if value == ")" and nesting == 0:
                        if current or params:
                            arguments.append("".join(current).strip())
                        consumed_end, closed = tokens[cursor][2], True
                        break
                    if value == "," and nesting == 0:
                        arguments.append("".join(current).strip())
                        current = []
                    else:
                        nesting += value in {"(", "[", "{"}
                        nesting -= value in {")", "]", "}"}
                        current.append(value)
                if not closed or len(arguments) != len(params):
                    refused.append((token, "argument_shape_unknown"))
                    continue
            bindings = dict(zip(params or (), arguments))
            substituted = "".join(bindings.get(m.group(), m.group()) for m in TOKEN.finditer(body))
            if substituted == content[start:consumed_end]:
                # `LOOP(x)` defined as `LOOP(x)`: rewriting it changes nothing, so
                # it is not an expansion. Refusing here keeps the round budget for
                # genuine (mutual) recursion instead of burning it on a no-op.
                refused.append((token, "self_referential_definition"))
                continue
            replacements.append((start, consumed_end, substituted, token, definitions))
            occupied = consumed_end
        if not replacements:
            break
        for start, end, replacement, token, definitions in reversed(replacements):
            original_line = origins[start]
            evidence.append({
                "macro": token,
                "original_line": original_line,
                "round": round_number + 1,
                "expanded": replacement,
                "carries_control_flow": bool(_CONTROL_FLOW.search(replacement)),
                "definition_locations": [{key: d[key] for key in ("file", "line", "source_sha256")}
                                         for d in definitions],
            })
            content = content[:start] + replacement + content[end:]
            origins = origins[:start] + [original_line] * len(replacement) + origins[end:]
        if len(content.encode("utf-8", "surrogatepass")) > MAX_EXPANDED_BYTES:
            return None, [], ["macro_expansion_size_budget_exceeded"], evidence, refused
        if content in seen:
            # `A(a)` defined as `B(a)` defined as `A(a)`: the rewrite never settles.
            # Handing the parser one arbitrary step of an infinite expansion would be
            # neither the source nor its expansion, so the file is left as written.
            refused.append(("*", "macro_recursion_or_round_budget_exceeded"))
            return original, original_origins, fatal, [], refused
        seen.add(content)
    else:
        refused.append(("*", "macro_recursion_or_round_budget_exceeded"))
        return original, original_origins, fatal, [], refused
    return content, origins, fatal, evidence, refused


def _run(source, catalog, max_rounds, allow_local_defines):
    text, origins, fatal, evidence, refused = _expand_text(
        source.decode("utf-8", errors="strict"), catalog, max_rounds, allow_local_defines)
    if text is None:
        return Expansion(source, {}, [], refused, fatal)
    return Expansion(text.encode("utf-8"), _line_map(text, origins), evidence, refused, fatal)


def expand_with_catalog(source, catalog, max_rounds=MAX_ROUNDS):
    """Expand `source` (bytes) against a catalogue already built for the scan."""
    return _run(source, catalog, max_rounds, allow_local_defines=True)


def expand(source, headers, max_rounds=MAX_ROUNDS):
    """round1-compatible entry point: bytes plus an explicit header mapping.

    Unlike `expand_with_catalog` this refuses a source-local `#define`, because a
    caller that supplied headers is asserting that the mapping is complete.
    """
    return _run(source, macro_catalog(headers), max_rounds, allow_local_defines=False)
