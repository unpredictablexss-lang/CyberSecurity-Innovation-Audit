"""Bounded disjunctive interpretation of structured C/C++ IPC functions.

Private detector analysis, not a replacement shared IR. It reuses the project's
Tree-sitter dependency to recover branches absent from the public AST outline.
No compiler CFG, overload resolution or exploitability proof. Macros are expanded
by `cpp_macros` under an explicit catalogue: a guard written inside a macro body
becomes real interpreted control flow, and everything the expander refused is
reported rather than assumed.
"""
from dataclasses import dataclass, field, replace
import re
from typing import Optional

from tree_sitter import Language, Parser
import tree_sitter_cpp
import tree_sitter_c

from .cpp_macros import Expansion, catalog_for_units, expand_with_catalog
from .entry_index import EntryIndex
from .models import IpcPolicy, consequence_for


def parses_clean(source, grammar):
    """Whether the private pipeline -- normalization included -- parses this cleanly.

    The normalization step is part of the pipeline, so the check has to run on the
    same text the parser will actually see; comparing raw bytes would report a file
    as unparseable that the pipeline handles.
    """
    return not Parser(Language(grammar)).parse(normalize_syntax(source)).root_node.has_error


def walk(node, kind=None):
    stack = [node]
    while stack:
        current = stack.pop()
        if kind is None or current.type == kind:
            yield current
        stack.extend(reversed(current.named_children))


def terminal(text):
    return re.split(r"::|->|\.", text)[-1].strip()


@dataclass(frozen=True)
class Value:
    kind: str = "unknown"
    key: str = ""
    subject: str = ""
    permission: str = ""
    predicate: tuple = ()
    terms: tuple = ()


UNKNOWN = Value()

# Descriptor-comparison outcomes that do establish the guard. The other two
# ("mismatch", "unresolved") are recorded as seen but never as a guard.
_DESCRIPTOR_ACCEPTED = frozenset({"unqualified", "self", "interface"})

# How a mismatch branch has to end before the check it belongs to counts as a
# guard: `relay_guard()` accepts a one-hop same-file relay only when the callee's
# token comparison leaves the transaction on mismatch. A branch that merely logs
# falls through to the dispatcher the check was supposed to protect.
_RELAY_LEAVES = ("return_statement", "throw_statement")


@dataclass
class State:
    env: dict = field(default_factory=dict)
    auth: frozenset = frozenset()
    descriptor: frozenset = frozenset()
    owner: frozenset = frozenset()
    lower: frozenset = frozenset()
    upper: frozenset = frozenset()
    size_lower: frozenset = frozenset()
    caller_class: frozenset = frozenset()
    identity_issues: tuple = ()
    # Descriptor comparisons seen on this path whose interface identity could not
    # be accepted as this transaction's guard: ((outcome, name, where_compared,
    # what_the_stub_states), ...). A record of what was seen, so a candidate can
    # say "present but mismatched/unresolved" instead of "absent".
    descriptor_issues: tuple = ()
    reset: bool = False
    trace: tuple = ()
    flow: str = "normal"
    returned: Value = UNKNOWN

    def fork(self, **kwargs):
        return replace(self, env=dict(self.env), **kwargs)


@dataclass(frozen=True)
class Function:
    file: str
    name: str
    qualified: str
    owner: str
    node: object
    body: object
    source: bytes
    params: tuple
    parcel_params: tuple

    def text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte].decode("utf-8")


@dataclass(frozen=True)
class Observation:
    family: str
    rule: str
    file: str
    line: int
    symbol: str
    message: str
    trace: tuple
    root_key: tuple
    entry_grade: str = "allowlist"   # "allowlist" | "dispatch"
    dispatch_note: str = ""
    impact: str = ""                 # consequence class, e.g. information_disclosure
    impact_cwe: str = ""             # consequence CWE; distinct from the mechanism CWE
    impact_basis: str = ""           # the call that drove the classification
    # "" | "mismatch" | "unresolved". Set only on descriptor-boundary findings
    # where a comparison was seen but its interface identity was not accepted, so
    # the finding carries the matching proof obligation.
    descriptor_identity: str = ""


def normalize_syntax(source):
    """Model only known format-string tokens, statement-carrying macro arguments
    and unresolved member dispatch.

    Byte lengths/newlines remain unchanged. Original source is retained for
    evidence. This is not macro expansion or resolution of member pointers.
    """
    pattern = (rb'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27'
               rb'|(?P<fmt>\b(?:PRI|SCN)[diouxX](?:LEAST|FAST)?(?:8|16|32|64|MAX|PTR)\b)')
    def fmt(match):
        token=match.group('fmt')
        if token is None:
            return match.group(0)
        # A format macro only means anything next to a string literal: it is the
        # width token that completes `"%{public}" PRIu32`. Requiring a literal on
        # both sides, as this rule first did, misses the commonest spelling in
        # OpenHarmony -- the macro *ends* the literal sequence, because it sits
        # last before the comma: `COMM_LOGE(TAG, "count=%{public}" PRIu32, n)`.
        # `SCNd64` in `sscanf_s(p, "pkg_%" SCNd64 "_%" SCNd64, ...)` was missed
        # twice over: the width family was not matched at all, and the first
        # occurrence ends its sequence. Either way tree-sitter sees a bare
        # identifier between/after string literals and drops the whole
        # translation unit to partial, which the complete-ast pass then skips.
        index=match.start()-1
        while index>=0 and source[index] in b" \t\r\n":
            index-=1
        if index<0 or source[index:index+1]!=b'"':
            return match.group(0)
        return b'""'+b' '*(len(token)-2)
    normalized=re.sub(pattern,fmt,source,flags=re.S)
    # `(this->*Ident)(args)` parses once the member-pointer operator is read as a
    # plain member access, which keeps the receiver visible.
    normalized=re.sub(rb'\(this\s*->\s*\*\s*[A-Za-z_]\w*\)(?=\s*\()',
                      lambda m:m.group(0).replace(b'*',b' ',1),normalized)
    # `(this->*(iter->second))(args)`, `(this->*(funcIter->second))(parcel)`: the
    # target is itself an expression, so there is nothing to keep. Blanking the
    # operator preserves every byte offset and leaves a plain call. The target is
    # unresolved here, which is exactly what the dispatch index resolves instead.
    normalized=re.sub(rb'this\s*->\s*\*\s*(?=\()',lambda m:b' '*len(m.group(0)),normalized)
    normalized=_blank_macro_statement_arguments(normalized)
    return normalized


_STATEMENT_KEYWORD = re.compile(rb"(?:return|break|continue)\b")
_MACRO_CALL = re.compile(rb"\b[A-Z][A-Z0-9_]{2,}\s*\(")


def _blank_macro_statement_arguments(source):
    """Neutralize macro arguments that carry a statement, keeping every offset.

    OpenHarmony macros such as

        ENGINE_CHECK(ret == INT_CALL_SUCCESS, return ret, "Failed to GetNewVersionInfo");

    embed a `return` statement in an argument list. Tree-sitter cannot parse that,
    so the whole enclosing function is dropped as partial and none of its handlers
    are ever analysed. The offending argument is replaced by a single `0` padded
    with spaces (line breaks preserved), which is byte-for-byte the same length.

    What this costs: the macro's effect is not modelled, so an early return inside
    such a macro is not part of the CFG. That is recorded as a limitation rather
    than silently assumed away.
    """
    out = bytearray(source)
    for match in _MACRO_CALL.finditer(source):
        open_index = match.end() - 1
        close_index = _matching_paren(source, open_index)
        if close_index is None:
            continue
        for start, end in _top_level_arguments(source, open_index, close_index):
            if not _STATEMENT_KEYWORD.match(source[start:end].lstrip()):
                continue
            span = source[start:end]
            if b"\n" in span:
                blank = bytearray(b" " * len(span))
                for index, byte in enumerate(span):
                    if byte == 0x0A:
                        blank[index] = 0x0A
                for index, byte in enumerate(blank):
                    if byte != 0x0A:
                        blank[index] = 0x30
                        break
                out[start:end] = blank
            else:
                out[start:end] = b"0" + b" " * (len(span) - 1)
    return bytes(out)


def _matching_paren(source, open_index):
    """Index of the `)` closing the `(` at `open_index`, skipping literals/comments."""
    depth, index, length = 0, open_index, len(source)
    while index < length:
        byte = source[index]
        if byte in (0x22, 0x27):
            index = _skip_quoted(source, index, byte)
            continue
        if byte == 0x2F and index + 1 < length:
            if source[index + 1] == 0x2F:
                newline = source.find(b"\n", index)
                if newline < 0:
                    return None
                index = newline
                continue
            if source[index + 1] == 0x2A:
                close = source.find(b"*/", index)
                if close < 0:
                    return None
                index = close + 2
                continue
        if byte == 0x28:
            depth += 1
        elif byte == 0x29:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _skip_quoted(source, index, quote):
    index += 1
    while index < len(source):
        if source[index] == 0x5C:
            index += 2
            continue
        if source[index] == quote:
            return index + 1
        index += 1
    return len(source)


def _top_level_arguments(source, open_index, close_index):
    """Comma-separated argument spans between the parentheses, outermost level only."""
    arguments, start = [], open_index + 1
    depth, index = 0, open_index + 1
    while index < close_index:
        byte = source[index]
        if byte in (0x22, 0x27):
            index = _skip_quoted(source, index, byte)
            continue
        if byte == 0x2F and index + 1 < close_index:
            if source[index + 1] == 0x2F:
                newline = source.find(b"\n", index)
                index = close_index if newline < 0 or newline >= close_index else newline
                continue
            if source[index + 1] == 0x2A:
                close = source.find(b"*/", index)
                index = close_index if close < 0 else close + 2
                continue
        if byte in (0x28, 0x5B, 0x7B):
            depth += 1
        elif byte in (0x29, 0x5D, 0x7D):
            depth -= 1
        elif byte == 0x2C and depth == 0:
            arguments.append((start, index))
            start = index + 1
        index += 1
    arguments.append((start, close_index))
    return arguments


class Interpreter:
    def __init__(self, units, policy: IpcPolicy):
        self.policy = policy
        self.functions = []
        self.observations = []
        self.limitations = set()
        self.seen_permissions = set()
        self.root = None
        self.active = ()
        self.capacities = {}
        self.root_grade = "allowlist"
        self.root_note = ""
        self.index = None
        self.line_maps = {}
        self.macro_sources = 0
        self.macro_truncated = False
        self.macro_expanded = 0
        self.macro_control_flow = 0
        self.macro_files_expanded = set()
        self.macro_files_unexpanded = set()
        self.macro_refusal_reasons = {}
        self.macro_catalog = self._build_macro_catalog(units)
        for unit in units:
            grammar = tree_sitter_c.language() if unit.language == "c" else tree_sitter_cpp.language()
            raw=unit.text.encode("utf-8")
            source=raw
            if self.macro_catalog is not None:
                expansion=expand_with_catalog(raw,self.macro_catalog)
                # A macro written for one context can be nonsense in another, so an
                # expansion that turns a parseable file into a partial one is
                # dropped. This keeps private parse coverage monotone: expansion
                # can add files the parser reaches, never remove any.
                if expansion.applied and parses_clean(raw,grammar) and not parses_clean(expansion.source,grammar):
                    expansion=Expansion(raw,{},(),expansion.refused,("expansion_worsened_the_parse",))
                source=expansion.source
                self._record_expansion(unit,expansion)
            normalized=normalize_syntax(source)
            if normalized!=raw:
                self.limitations.add("Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: "+unit.path)
            tree = Parser(Language(grammar)).parse(normalized)
            if tree.root_node.has_error:
                self.limitations.add("Partial source: only error-free functions can be inspected in " + unit.path)
            for node in walk(tree.root_node, "function_definition"):
                dec = node.child_by_field_name("declarator")
                while dec is not None and dec.type not in ("function_declarator",):
                    dec = dec.child_by_field_name("declarator")
                if dec is None:
                    continue
                name_node = dec.child_by_field_name("declarator")
                if name_node is None:
                    continue
                q = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
                owner = q.rsplit("::", 1)[0] if "::" in q else ""
                if not owner:
                    parent = node.parent
                    while parent is not None:
                        if parent.type in ("class_specifier", "struct_specifier"):
                            n = parent.child_by_field_name("name")
                            owner = source[n.start_byte:n.end_byte].decode() if n else ""
                            break
                        parent = parent.parent
                params, parcels = [], []
                plist = dec.child_by_field_name("parameters")
                for param in plist.named_children if plist else ():
                    pd = param.child_by_field_name("declarator")
                    while pd is not None and pd.child_by_field_name("declarator") is not None:
                        pd = pd.child_by_field_name("declarator")
                    if pd is None:
                        continue
                    ids = list(walk(pd, "identifier"))
                    pname_node = ids[-1] if ids else pd
                    pname = source[pname_node.start_byte:pname_node.end_byte].decode()
                    params.append(pname)
                    if re.search(r"\b(?:MessageParcel|Parcel)\b",source[param.start_byte:param.end_byte].decode()):
                        parcels.append(pname)
                body = node.child_by_field_name("body")
                if body and not node.has_error:
                    self.functions.append(Function(unit.path, terminal(q), q, owner, node, body,
                                                   source, tuple(params), tuple(parcels[:1])))
        self._build_index(units)

    def _build_macro_catalog(self, units):
        """Catalogue the scan's own `#define`s, headers first.

        Building the catalogue from the whole scan rather than from a hand-supplied
        header list is what makes a source-local `#define` harmless: the file's own
        definitions are already in it. Returns None when expansion is disabled, in
        which case every unit is parsed exactly as it is written.
        """
        if not self.policy.expand_macros or self.policy.max_macro_sources <= 0:
            return None
        catalog, sources, total, truncated = catalog_for_units(
            units, self.policy.max_macro_sources, self.policy.max_macro_source_bytes)
        self.macro_sources = sources
        self.macro_truncated = truncated
        if truncated:
            self.limitations.add(
                "Macro catalogue truncated at " + str(sources) + " source(s): a macro defined only in a "
                "file that was not catalogued stays unexpanded, and a guard inside it is not seen.")
        return catalog

    def _record_expansion(self, unit, expansion):
        """Keep the line map and count what expansion did and did not do.

        Nothing here decides a finding. It records how much of the source reached
        the interpreter in expanded form, so the number can be reported rather than
        assumed.
        """
        self.line_maps[unit.path] = expansion.line_map
        if expansion.fatal:
            self.macro_files_unexpanded.add(unit.path)
            for reason in expansion.fatal:
                self.macro_refusal_reasons[reason] = self.macro_refusal_reasons.get(reason, 0) + 1
            return
        for _, reason in expansion.refused:
            self.macro_refusal_reasons[reason] = self.macro_refusal_reasons.get(reason, 0) + 1
        if not expansion.applied:
            return
        self.macro_files_expanded.add(unit.path)
        self.macro_expanded += len(expansion.expansions)
        self.macro_control_flow += len(expansion.carried_control_flow)

    def _macro_summary(self):
        """One sentence saying what the expander was able to do, or None.

        Counts only. The per-file detail belongs in the research report; the
        detector result carries the shape of the limitation, not a coverage claim.
        """
        if self.macro_catalog is None:
            return None
        if not (self.macro_expanded or self.macro_files_unexpanded or self.macro_refusal_reasons):
            return None
        reasons = ",".join(name + "=" + str(count)
                           for name, count in sorted(self.macro_refusal_reasons.items()))
        return ("Macro expansion: " + str(self.macro_expanded) + " invocation(s) expanded in "
                + str(len(self.macro_files_expanded)) + " file(s), " + str(self.macro_control_flow)
                + " of them carrying control flow; " + str(len(self.macro_files_unexpanded))
                + " file(s) left unexpanded"
                + ((" (" + reasons + ")") if reasons else "")
                + ". The catalogue is the scan's own sources, never #include; where a macro was expanded, "
                  "quoted conditions come from the expanded form while a finding's line is mapped back to "
                  "the original file.")

    def _build_index(self, units):
        """Source-derived entry/dispatch index. Never fatal: an index failure
        degrades entry discovery back to the name allowlist and says so."""
        try:
            self.index = EntryIndex(units, self.policy)
        except Exception as error:                      # noqa: BLE001 - degrade, never crash
            self.index = None
            self.limitations.add("Entry index unavailable (" + type(error).__name__
                                 + "); entry discovery fell back to the name allowlist.")
        self.functions_by_owner_name = {}
        for fn in self.functions:
            owner = fn.owner.rsplit("::", 1)[-1] if fn.owner else ""
            self.functions_by_owner_name.setdefault((owner, fn.name), []).append(fn)

    def bounded(self, states):
        # Keep a conservative merged state when the disjunction exceeds budget.
        # Intersect guards/ranges, union only identical provenance; never truncate
        # an unprotected path while retaining protected ones.
        if len(states) <= self.policy.max_paths:
            return states
        self.limitations.add("Path budget exceeded: conservative state join; path precision reduced.")
        result = []
        for flow in sorted({s.flow for s in states}):
            group = [s for s in states if s.flow == flow]
            env = {}
            for key in set().union(*(s.env.keys() for s in group)):
                values = {s.env.get(key, UNKNOWN) for s in group}
                env[key] = values.pop() if len(values) == 1 else UNKNOWN
            def intersection(attr):
                return frozenset.intersection(*(getattr(s, attr) for s in group))
            result.append(State(env=env, auth=intersection("auth"),
                                descriptor=intersection("descriptor"), owner=intersection("owner"),
                                lower=intersection("lower"), upper=intersection("upper"), size_lower=intersection("size_lower"), caller_class=intersection("caller_class"),
                                identity_issues=tuple(issue for s in group for issue in s.identity_issues),
                                descriptor_issues=tuple(dict.fromkeys(
                                    issue for s in group for issue in s.descriptor_issues)),
                                reset=any(s.reset for s in group), flow=flow,
                                trace=((0, "conservative path join"),)))
        return result

    def emit(self, family, rule, fn, node, state, message, call=None):
        impact, impact_cwe, basis = consequence_for(rule, (call,) if call else ())
        # A descriptor-boundary candidate that saw a comparison it could not accept
        # says so here, in the finding and in its obligations, rather than reading
        # as though no comparison existed.
        descriptor_identity = ""
        if rule == "ipc.relay.descriptor-boundary" and state.descriptor_issues:
            descriptor_identity, note = self.descriptor_note(state.descriptor_issues)
            message = message + " " + note
        # node was read out of the expanded text; the reader needs the line the code
        # was actually written on. `fn.file` may differ from the current root when a
        # handler delegates into another file, so the map is chosen by file.
        line_map = self.line_maps.get(fn.file) or {}
        line = node.start_point[0] + 1
        trace = state.trace if not line_map else tuple(
            (line_map.get(step[0], step[0]),) + tuple(step[1:]) for step in state.trace)
        self.observations.append(Observation(family, rule, fn.file,
            line_map.get(line, line), fn.qualified, message, trace,
            (self.root.file, self.root.qualified), self.root_grade, self.root_note,
            impact, impact_cwe, basis, descriptor_identity))

    def resolve(self, fn, name):
        # No arbitrary receiver or global name-only cross-class resolution.
        receiver = name.rsplit("->", 1)[0] if "->" in name else None
        if "." in name or (receiver is not None and receiver != "this"):
            return None
        prefix = name.rsplit("::", 1)[0] if "::" in name else fn.owner
        matches = [f for f in self.functions if f.file == fn.file
                   and f.name == terminal(name) and f.owner == prefix]
        return matches[0] if len(matches) == 1 else None

    def delegated(self, callee):
        """One hop from a handler into the service singleton it delegates to.

        OpenHarmony stubs hand the request to the service implementation, which
        lives in another file: `DelayedSingleton<XxxService>::GetInstance()->Method()`
        or an object macro standing for exactly that expression. The receiver type
        must be source-backed (an object macro, or an explicit `Type::GetInstance()`)
        and the target must resolve to exactly one definition; anything else stays
        unresolved rather than becoming a general cross-file name resolver.
        """
        if self.index is None:
            return None
        target = self.index.resolve_receiver(callee)
        if not target or "::" not in target:
            return None
        owner, name = target.rsplit("::", 1)
        matches = self.functions_by_owner_name.get((owner.rsplit("::", 1)[-1], name), [])
        return matches[0] if len(matches) == 1 else None

    def authorized(self, state, name):
        expected = dict(self.policy.expected_permissions).get(name)
        if expected:return expected in state.auth
        if name in ("GetRemoteHapTokenInfo","DeleteRemoteHapTokenInfo","UpdateRemoteHapTokenInfo"):
            return bool(state.auth or state.caller_class.intersection({"TOKEN_NATIVE"}))
        return bool(state.auth)

    def action(self, fn, node, state, name, args, depth=0):
        if self.root is None:
            return
        root_key = (self.root.file, self.root.qualified)
        sensitive = name in self.policy.sensitive_calls or name in self.policy.object_sensitive_calls
        if sensitive:
            for issue_fn,issue_node,issue_rule,issue_message in state.identity_issues:
                self.emit("AUTH-03",issue_rule,issue_fn,issue_node,state,issue_message,call=name)
        if sensitive and not self.authorized(state, name):
            if self.root_grade == "dispatch" and "dispatcher-guard-observed" in self.root_note:
                # A guard runs before dispatch, so this is a guard-coverage question
                # (does it dominate this transaction?), not an absent-authorization
                # one. Same path, same evidence, classified where the uncertainty is.
                self.emit("AUTH-04", "ipc.auth.guard-coverage", fn, node, state,
                          "Sensitive modeled call " + name + " has no matched caller authorization on "
                          "this path, but the dispatcher performs an authorization call before dispatch; "
                          "its dominance over this transaction is not established.", call=name)
            else:
                self.emit("AUTH-02", "ipc.auth.missing", fn, node, state,
                          "Sensitive modeled call " + name + " has a structured path without a recognized caller authorization.",
                          call=name)
        if name in self.policy.caller_class_sensitive_calls and not state.caller_class:
            self.emit("AUTH-03","ipc.auth.caller-class",fn,node,state,
                      "Sensitive token/privacy operation lacks a caller-class/system-application boundary: "+name,
                      call=name)
        if name in ("StartBackgroundRunningForInner","StopBackgroundRunningForInner") and args:
            if args[0].key not in state.owner:
                self.emit("AUTH-03","ipc.auth.object-owner",fn,node,state,
                          "Background-task target UID is not bound to calling UID.", call=name)
        if name in self.policy.object_sensitive_calls:
            resources = {v.key for v in args if v.kind == "request"}
            if resources and not resources.issubset(state.owner):
                self.emit("AUTH-03", "ipc.auth.object-owner", fn, node, state,
                          "Caller/resource relation is not established for " + name + ": " + ", ".join(sorted(resources)),
                          call=name)
        if name in self.policy.capability_calls and not state.auth:
            if args and args[0].key not in ("nullptr", "NULL", "0"):
                self.emit("CAP-01", "ipc.capability.export", fn, node, state,
                          "Capability export " + name + " lacks a recognized caller authorization on this path.",
                          call=name)
        if name in self.policy.copy_calls and args:
            index = 3 if name in ("memcpy_s", "memmove_s") else 2
            if len(args) > index and args[index].kind == "request":
                length = args[index].key
                cap = args[1].key if index == 3 else self.capacities.get(args[0].key)
                upper = any(key == length and (cap is not None and bound in (cap,"sizeof("+args[0].key+")"))
                            for key, bound in state.upper)
                if not upper or length not in state.lower:
                    self.emit("DATA-01", "ipc.parcel.copy-range", fn, node, state,
                              "Parcel-derived copy length " + length + " lacks matched nonnegative/destination-capacity bounds.",
                              call=name)
        if self.root.name in self.policy.entry_names and name not in self.policy.entry_names and (sensitive or name.startswith("On")
                or name in self.policy.capability_calls or name in self.policy.copy_calls):
            parcel_keys = {v.key for v in state.env.values() if v.kind == "parcel"}
            if parcel_keys and not parcel_keys.intersection(state.descriptor):
                helper = self.resolve(fn, name)
                relay = self.relay_guard(fn, node, args, helper, state, depth) if helper else None
                if relay is None:
                    self.emit("AUTH-01", "ipc.relay.descriptor-boundary", fn, node, state,
                              "IPC dispatch/callback reaches " + name + " without a matched interface-descriptor guard; relay/exposure still requires review.",
                              call=name)
                elif relay[0] == "seen":
                    issue = relay[1]
                    if issue not in state.descriptor_issues:
                        state.descriptor_issues = state.descriptor_issues + (issue,)
                    self.emit("AUTH-01", "ipc.relay.descriptor-boundary", fn, node, state,
                              "IPC dispatch/callback reaches " + name + ", whose interface-descriptor comparison is present but not accepted for this transaction; relay/exposure still requires review.",
                              call=name)

    def interface_of(self, name):
        """The declaration of a written class name, or "" when the shard lacks it."""
        info = self.index.resolve_class(name) if self.index is not None else None
        if info is None:
            return "declaration not in the analysed sources"
        return "declared at " + info.file + ":" + str(info.line)

    def descriptor_expectation(self, fn, callee, state):
        """Which interface a `GetDescriptor()` call names, and whether it is this one.

        `X::GetDescriptor()` yields the descriptor of interface X, so X's identity
        decides whether the comparison guards *this* transaction. The qualifier is
        evidence, not a filter -- discarding it as UNKNOWN is what made a real
        check look absent, and accepting any qualifier would let a guard against
        an unrelated interface count as one.

        Four outcomes, each recorded with the source it came from:

        * ``unqualified``/``self``  -- the stub's own descriptor; every design
          fixture is written this way and stays accepted.
        * ``interface``  -- X is named by the enclosing class's own base clause as
          the interface it implements (`IRemoteStub<X>`). Source-derived; the class
          name is never used to guess an interface.
        * ``mismatch``  -- the base clause states an interface and X is another
          one, so the guard validates a different interface than this transaction.
        * ``unresolved``  -- the sources do not state which interface this class
          implements. Unknown, which is neither a working guard nor a mismatch.
        """
        qualifier = callee.rsplit("::", 1)[0].strip() if "::" in callee else ""
        owner_name = terminal(fn.owner)
        if not qualifier:
            return Value("descriptor_expected", fn.owner, subject="unqualified",
                         terms=("unqualified call", "no interface named"))
        inner = qualifier[qualifier.find("<") + 1:qualifier.rfind(">")] if qualifier.endswith(">") else ""
        name = terminal(inner if inner else qualifier)
        if name in (owner_name, "IRemoteStub", "IPCObjectStub"):
            return Value("descriptor_expected", name, subject="self",
                         terms=("qualified with " + name, "the enclosing class"))
        interfaces = (self.index.implemented_interfaces(fn.owner)
                      if self.index is not None and fn.owner else ())
        stated = ", ".join(sorted(item.name + " (stated at " + item.file + ":" + str(item.line) + ")"
                                  for item in interfaces))
        where = name + " " + self.interface_of(name)
        if any(item.name == name for item in interfaces):
            return Value("descriptor_expected", name, subject="interface",
                         terms=(where, "this class implements " + stated))
        if interfaces:
            return Value("descriptor_expected", name, subject="mismatch",
                         terms=(where, "this class implements " + stated))
        return Value("descriptor_expected", name, subject="unresolved",
                     terms=(where, "no interface is stated for " + (owner_name or "this function")))

    def descriptor_note(self, issues):
        """Why a comparison that was read does not count as a guard.

        A descriptor candidate claims no matched interface-descriptor guard was
        found. When a comparison *is* present but targets another interface, or its
        identity is not in the analysed sources, the reason belongs in the finding;
        otherwise the message reads as if no comparison existed at all.
        """
        mismatch = sorted({item for item in issues if item[0] == "mismatch"})
        unresolved = sorted({item for item in issues if item[0] != "mismatch"})
        parts = ["a comparison against " + item[1] + " is present but mismatched (" + item[2]
                 + "; " + item[3] + ")" for item in mismatch]
        parts += ["a comparison against " + item[1] + " is present but its interface identity is not "
                  "determined (" + item[2] + "; " + item[3] + ")" for item in unresolved]
        return ("mismatch" if mismatch else "unresolved"), "Guard seen, not accepted: " + "; ".join(parts) + "."

    def relay_guard(self, fn, node, args, helper, state, depth):
        """What a one-hop same-file relay out of an entry lands on.

        `OnRemoteRequest` handing the request to `OnRemoteRequestInner(code, data,
        reply, option)` proves nothing by itself: that callee may not compare the
        token at all, may compare another interface, may compare and carry on, or
        may compare only after it already routed the request. The relay is read as
        guarded only when

        * every argument is one of this entry's own parameters, so the request is
          handed over rather than replaced;
        * a top-level statement of the callee compares `ReadInterfaceToken()`
          against an accepted descriptor identity and *leaves* on mismatch;
        * that statement precedes the `switch` that routes the request.

        Returns ``("guarded", where)``, ``("seen", issue)`` when a comparison is
        present but not accepted for this transaction, or None when nothing here
        establishes a guard -- and then the call site stays a candidate.
        """
        if helper.body is None or helper.file != fn.file:
            return None
        passed = node.child_by_field_name("arguments")
        carried = [fn.text(item) for item in passed.named_children] if passed else []
        if not carried or any(name not in fn.params for name in carried):
            return None
        statements = list(helper.body.named_children)
        probe = state.fork()
        probe.env.update(dict(zip(helper.params, args)))
        check = index = comparison = None
        for position, item in enumerate(statements):
            # Locals hold the token as often as the call site does, so bind the
            # declarations met on the way to the check the way the body walk binds
            # them: `token = data.ReadInterfaceToken(); if (token != ...)`.
            for declaration in (item.named_children if item.type == "declaration" else ()):
                if declaration.type != "init_declarator":
                    continue
                declarator = declaration.child_by_field_name("declarator")
                names = list(walk(declarator, "identifier")) if declarator else []
                self.assign(probe, helper.text(names[-1] if names else declarator),
                            self.value(helper, declaration.child_by_field_name("value"), probe, depth))
            if item.type != "if_statement":
                continue
            read = self.value(helper, item.child_by_field_name("condition"), probe, depth)
            if read.kind == "predicate" and read.predicate[:1] == ("descriptor",):
                check, index, comparison = item, position, read
                break
        if check is None:
            return None
        expected = comparison.predicate[3]
        line_map = self.line_maps.get(helper.file) or {}
        line = check.start_point[0] + 1
        where = helper.qualified + " at " + helper.file + ":" + str(line_map.get(line, line))
        if expected.subject not in _DESCRIPTOR_ACCEPTED:
            return ("seen", (expected.subject, expected.key) + tuple(expected.terms))
        # The predicate is true when the operands are equal, so on an equality
        # test it is the `else` branch that sees the mismatch, and on `!=` the
        # consequence. That branch has to leave for the check to be a guard.
        mismatch = (check.child_by_field_name("alternative") if comparison.predicate[2]
                    else check.child_by_field_name("consequence"))
        if mismatch is not None and mismatch.type == "else_clause":
            mismatch = mismatch.named_children[-1] if mismatch.named_children else None
        block = mismatch if mismatch is not None and mismatch.type == "compound_statement" else None
        leaving = block.named_children if block is not None else ([mismatch] if mismatch is not None else [])
        if not any(item.type in _RELAY_LEAVES for item in leaving):
            return None
        if not any(item.type == "switch_statement" for item in statements[index + 1:]):
            return None
        return ("guarded", where)

    def value(self, fn, node, state, depth):
        if node is None:
            return UNKNOWN
        text = fn.text(node)
        if node.type in ("parenthesized_expression", "condition_clause"):
            child = node.child_by_field_name("value")
            return self.value(fn, child or (node.named_children[-1] if node.named_children else None), state, depth)
        if node.type in ("identifier", "field_identifier"):
            return state.env.get(text, Value("constant", text))
        if node.type in ("number_literal", "true", "false", "null", "nullptr", "string_literal", "concatenated_string"):
            return Value("constant", text)
        if node.type == "call_expression":
            callee = fn.text(node.child_by_field_name("function"));name = terminal(callee)
            an = node.child_by_field_name("arguments")
            args = [self.value(fn, a, state, depth) for a in an.named_children] if an else []
            receiver = re.split(r"->|\.", callee)[0] if re.search(r"->|\.", callee) else ""
            if name in self.policy.caller_token_calls | self.policy.caller_uid_calls:
                return Value("self" if state.reset else "caller", text, "uid" if name in self.policy.caller_uid_calls else "token")
            if name in self.policy.self_calls:
                return Value("self", text, "uid" if name in ("getuid","geteuid") else "token")
            if name == "ResetCallingIdentity":
                state.reset = True
                return Value("saved_identity", text)
            if name == "SetCallingIdentity":
                # Restoration cannot establish the original caller unless the
                # corresponding identity token's provenance is available.
                state.reset = not (args and args[0].kind == "saved_identity")
                return UNKNOWN
            if name == "ReadInterfaceToken":
                rv = state.env.get(receiver, UNKNOWN)
                return Value("descriptor_read", rv.key) if rv.kind == "parcel" else UNKNOWN
            if name == "GetDescriptor":
                return self.descriptor_expectation(fn, callee, state)
            if name in ("GetTokenTypeFlag", "GetTokenType") and args and args[0].kind=="caller" and args[0].subject=="token":
                return Value("caller_type",args[0].key)
            if name=="GetNativeTokenInfo" and len(args)>1 and args[0].kind=="caller" and args[0].subject=="token":
                state.env[args[1].key]=Value("caller_info",args[1].key)
            if name=="compare" and args:
                receiver_node=node.child_by_field_name("function")
                receiver_arg=receiver_node.child_by_field_name("argument") if receiver_node else None
                rv=self.value(fn,receiver_arg,state,depth)
                if rv.kind=="caller_process" and args[0].key=='"hdcd"':
                    return Value("permission_result",text,"caller","<caller-native-process:hdcd>")
            if name in ("IsSystemAppCalling","CheckCallerIsSystemApp"):
                return Value("predicate",predicate=("caller_class","system_app",True))
            if name in ("IsPrivilegedCalling","IsAccessTokenCalling"):
                return Value("predicate",predicate=("auth","<caller-service-role>",True))
            if name=="GetDataSize" and state.env.get(receiver,UNKNOWN).kind=="parcel":
                return Value("parcel_size",re.sub(r"\s+","",text))
            if name=="RewindRead" and args:
                self.check_subtractions(fn,node,state,args[0])
            if name in self.policy.owner_calls:
                return Value("owner", args[0].key if args else receiver)
            if name in self.policy.parcel_reads:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    return Value("request", text, "unsigned" if name.startswith("ReadU") else "signed")
            if callee.lstrip().startswith("(this->*") and self.root.name in self.policy.entry_names and not state.descriptor:
                self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                          "Unresolved member-pointer IPC dispatch lacks interface-descriptor validation; callee remains unknown.")
            helper = self.resolve(fn, callee)
            if helper is None:
                helper = self.delegated(callee)
            self.action(fn, node, state, name, args, depth)
            if helper and self.root.name in self.policy.entry_names and not state.descriptor:
                relay = self.relay_guard(fn, node, args, helper, state, depth)
                if relay is None:
                    self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                        "IPC entry reaches a locally resolved handler without interface-descriptor validation: "+helper.qualified)
                elif relay[0] == "seen":
                    if relay[1] not in state.descriptor_issues:
                        state.descriptor_issues = state.descriptor_issues + (relay[1],)
                    self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                        "IPC entry relays to "+helper.qualified+", whose interface-descriptor comparison is present but not accepted for this transaction.")
                # relay[0] == "guarded": the relayed-to function is the guard, so
                # this call site is not itself an unguarded boundary.
            if helper and depth < self.policy.max_call_depth and helper not in self.active:
                local = state.fork();local.env = dict(zip(helper.params, args))
                old = self.active;self.active = old + (helper,)
                ends = self.block(helper, helper.body, [local], depth + 1)
                self.active = old
                returned = [s.returned for s in ends if s.flow == "return"]
                # A helper is summarized only when all its returns agree. A
                # conditional boolean return gets its guards bound to truth.
                values = set(returned)
                if len(values) == 1 and len(returned) == len(ends):
                    return values.pop()
                good = [s for s in ends if s.flow == "return" and s.returned.key in ("true", "1")]
                bad = [s for s in ends if s.flow == "return" and s.returned.key in ("false", "0")]
                if good and bad and len(good)+len(bad) == len(ends):
                    common = frozenset.intersection(*(s.auth for s in good)) - state.auth
                    if common:
                        return Value("predicate", predicate=("auth", sorted(common)[0], True))
                self.limitations.add("Unresolved multi-outcome helper return: " + helper.qualified)
                return UNKNOWN
            if name in self.policy.boolean_permissions | self.policy.result_permissions:
                self.seen_permissions.add((self.root.file,self.root.qualified))
                subjects = [a.kind for a in args if a.kind in ("caller", "self", "request")]
                subject = subjects[0] if subjects else ("caller" if callee=="TelephonyPermission::CheckPermission" else "unknown")
                if name in self.policy.result_permissions and any(a.kind=="caller" and a.subject=="uid" for a in args):
                    subject="caller_uid"
                    state.identity_issues += ((fn,node,"ipc.auth.identity-domain",
                        "AccessToken authorization consumes a caller UID rather than a caller TokenID: "+text),)
                perm = next((a.key for a in args if a.kind == "constant" and ('\"' in a.key or 'PERMISSION' in a.key)), "<unspecified>")
                if subject == "self":
                    state.identity_issues += ((fn,node,"ipc.auth.service-identity",
                              "Authorization predicate uses service identity before a modeled sensitive effect: "+text),)
                if subject == "request":
                    state.identity_issues += ((fn,node,"ipc.auth.request-identity",
                              "Authorization predicate consumes request-derived identity before a modeled sensitive effect: "+text),)
                kind = "permission_bool" if name in self.policy.boolean_permissions else "permission_result"
                return Value(kind, text, subject, perm)
            if helper and (depth >= self.policy.max_call_depth or helper in self.active):
                self.limitations.add("Call depth/recursion budget reached at " + helper.qualified)
            return Value("unknown", text)
        if node.type == "binary_expression":
            left = self.value(fn,node.child_by_field_name("left"),state,depth)
            right = self.value(fn,node.child_by_field_name("right"),state,depth)
            op = fn.text(node.child_by_field_name("operator"))
            if op in ("==", "!=", "<", "<=", ">", ">="):
                if left.kind == "descriptor_read" and right.kind == "descriptor_expected" or right.kind == "descriptor_read" and left.kind == "descriptor_expected":
                    rd = left if left.kind == "descriptor_read" else right
                    expected = right if left.kind == "descriptor_read" else left
                    if op in ("==","!="):
                        return Value("predicate",predicate=("descriptor",rd.key,op=="==",expected))
                pv,cv = (left,right) if left.kind in ("permission_bool","permission_result") else (right,left)
                if pv.kind in ("permission_bool","permission_result") and op in ("==","!="):
                    success = cv.key in ("0", "PERMISSION_GRANTED", "AccessTokenKit::PERMISSION_GRANTED", "true") or terminal(cv.key)=="PERMISSION_GRANTED"
                    failure = (pv.kind=="permission_bool" and cv.key=="false") or (pv.kind=="permission_result" and terminal(cv.key)=="PERMISSION_DENIED")
                    if (success or failure) and pv.subject == "caller":
                        return Value("predicate",predicate=("auth",pv.permission,(success and op=="==") or (failure and op=="!=")))
                if left.kind=="parcel_size" and op in ("<",">="):
                    return Value("predicate",predicate=("size_lower",(left.key,right.key),op==">="))
                if op in ("==","!=") and ((left.kind=="caller_type" and terminal(right.key) in ("TOKEN_NATIVE","TOKEN_SHELL","TOKEN_HAP")) or (right.kind=="caller_type" and terminal(left.key) in ("TOKEN_NATIVE","TOKEN_SHELL","TOKEN_HAP"))):
                    role=right.key if left.kind=="caller_type" else left.key
                    if terminal(role)=="TOKEN_HAP":
                        return Value("predicate",predicate=("caller_class","not_hap",op=="!="))
                    return Value("predicate",predicate=("caller_class",terminal(role),op=="=="))
                if op in ("==","!=") and {left.kind,right.kind} == {"caller","owner"} and (left if left.kind=="caller" else right).subject=="uid":
                    ov = left if left.kind == "owner" else right
                    return Value("predicate",predicate=("owner",ov.key,op=="=="))
                if op in ("==","!=") and ((left.kind=="caller" and left.subject=="uid" and right.key in self.policy.trusted_uids) or (right.kind=="caller" and right.subject=="uid" and left.key in self.policy.trusted_uids)):
                    return Value("predicate",predicate=("auth","<trusted-uid>",op=="=="))
                if left.kind == "request" and right.kind != "request":
                    if op=="<" and right.key=="0":
                        return Value("predicate",predicate=("lower",left.key,False))
                    if op in ("<", "<="):
                        return Value("predicate",predicate=("upper",(left.key,right.key),True))
                    if (op==">=" and right.key=="0") or (op==">" and right.key in ("0","-1")):
                        return Value("predicate",predicate=("lower",left.key,True))
                if left.kind == "request" and right.kind != "request" and op in (">",">="):
                    return Value("predicate",predicate=("upper",(left.key,right.key),False))
            if left.kind == "request" or right.kind == "request":
                return Value("request",re.sub(r"\s+","",text), "arithmetic",terms=(op,left,right))
            if op=="-" and (left.kind=="parcel_size" or left.terms):
                return Value("arithmetic",re.sub(r"\s+","",text),terms=(op,left,right))
            return UNKNOWN
        if node.type == "unary_expression":
            val=self.value(fn,node.child_by_field_name("argument"),state,depth)
            op=fn.text(node.child_by_field_name("operator"))
            if op=="!" and val.predicate:
                kind,key,truth=val.predicate
                return Value("predicate",predicate=(kind,key,not truth))
            if op=="!" and val.kind=="permission_bool" and val.subject=="caller":
                return Value("predicate",predicate=("auth",val.permission,False))
            if op=="-" and val.kind=="constant":
                return Value("constant","-"+val.key)
            return val
        if node.type in ("cast_expression","type_descriptor"):
            return self.value(fn,node.child_by_field_name("value"),state,depth)
        if node.type == "new_expression":
            typ=fn.text(node.child_by_field_name("type"))
            if typ=="HCameraDevice":
                self.action(fn,node,state,"CreateCameraDevice",[])
            for child in node.named_children:self.value(fn,child,state,depth)
            return UNKNOWN
        if node.type=="field_expression" and fn.text(node.child_by_field_name("field"))=="processName":
            base=self.value(fn,node.child_by_field_name("argument"),state,depth)
            if base.kind=="caller_info":return Value("caller_process",base.key)
        if node.type=="field_expression" and fn.text(node.child_by_field_name("field")) in ("uid_","ownerUid"):
            arg=node.child_by_field_name("argument");base=self.value(fn,arg,state,depth)
            if base.kind=="request":return Value("owner",base.key)
        if node.type == "field_expression" and fn.text(node.child_by_field_name("field"))=="type" and "AccessTokenIDInner" in text:
            names=[fn.text(n) for n in walk(node,"identifier")]
            if any(state.env.get(n,UNKNOWN).kind=="caller" and state.env.get(n,UNKNOWN).subject=="token" for n in names):
                return Value("caller_type",text)
        if node.type == "sizeof_expression":
            return Value("constant",text)
        if node.type == "assignment_expression":
            left=fn.text(node.child_by_field_name("left"))
            value=self.value(fn,node.child_by_field_name("right"),state,depth)
            self.assign(state,left,value)
            return state.env[left]
        if node.type in ("subscript_expression","subscript_argument_list"):
            for sub in node.named_children:self.value(fn,sub,state,depth)
            return UNKNOWN
        # Visit nested calls without treating comments or strings as executable.
        for child in node.named_children:self.value(fn,child,state,depth)
        return Value("unknown",text)

    def check_subtractions(self,fn,node,state,value):
        if not value.terms or value.terms[0]!="-":return
        _,left,right=value.terms
        self.check_subtractions(fn,node,state,left)
        valid=(left.kind=="parcel_size" and (left.key,right.key) in state.size_lower) or ((right.key,left.key) in state.upper)
        if not valid:
            self.emit("DATA-01","ipc.parcel.position-underflow",fn,node,state,
                      "Parcel read-position subtraction lacks a matched size/length bound: "+value.key)

    def assign(self,state,name,value):
        # Reassignment invalidates guard facts about the old value.
        old=state.env.get(name)
        if old:
            state.lower=state.lower-{old.key}
            state.upper=frozenset((k,b) for k,b in state.upper if k!=old.key)
            state.owner=state.owner-{old.key}
        if value.kind=="request":
            value=replace(value,key=name)
            if value.subject=="unsigned":state.lower=state.lower|{name}
        state.env[name]=value

    def refine(self,fn,node,state,truth,depth):
        if node is None:return [state.fork()]
        if node.type in ("parenthesized_expression","condition_clause"):
            child=node.child_by_field_name("value") or (node.named_children[-1] if node.named_children else None)
            return self.refine(fn,child,state,truth,depth)
        if node.type=="unary_expression" and fn.text(node.child_by_field_name("operator"))=="!":
            return self.refine(fn,node.child_by_field_name("argument"),state,not truth,depth)
        if node.type=="binary_expression":
            op=fn.text(node.child_by_field_name("operator"));left=node.child_by_field_name("left");right=node.child_by_field_name("right")
            if op in ("&&","||"):
                if (op=="&&" and truth) or (op=="||" and not truth):
                    first=self.refine(fn,left,state,truth,depth)
                    return self.bounded([t for s in first for t in self.refine(fn,right,s,truth,depth)])
                short=self.refine(fn,left,state,truth,depth)
                longer=[t for s in self.refine(fn,left,state,not truth,depth) for t in self.refine(fn,right,s,truth,depth)]
                return self.bounded(short+longer)
        out=state.fork();val=self.value(fn,node,out,depth)
        if val.kind=="constant" and val.key in ("true","false","0","1"):
            if (val.key in ("true","1"))!=truth:return []
        pred=val.predicate
        if val.kind=="permission_bool" and val.subject=="caller":pred=("auth",val.permission,True)
        if pred:
            kind,key,when=pred[0],pred[1],pred[2]
            # A descriptor comparison against an identity that is not this
            # transaction's interface is recorded as seen, on both branches: it is
            # why no guard was accepted here. Accepting it would let an unrelated
            # interface's descriptor stand in for this one.
            accepted=True
            if kind=="descriptor" and len(pred)>3 and pred[3].subject not in _DESCRIPTOR_ACCEPTED:
                accepted=False
                issue=(pred[3].subject,pred[3].key)+tuple(pred[3].terms)
                if issue not in out.descriptor_issues:
                    out.descriptor_issues=out.descriptor_issues+(issue,)
            if truth==when and accepted:
                attr={"auth":"auth","descriptor":"descriptor","owner":"owner","lower":"lower","upper":"upper","size_lower":"size_lower","caller_class":"caller_class"}[kind]
                setattr(out,attr,getattr(out,attr)|{key})
        out.trace=(out.trace+((node.start_point[0]+1,fn.text(node)+" => "+str(truth)),))[-20:]
        return [out]

    def block(self,fn,node,states,depth):
        if node is None:return states
        if node.type in ("compound_statement","case_statement"):
            for child in node.named_children:
                if node.type=="case_statement" and child==node.child_by_field_name("value"):continue
                states=self.statement(fn,child,states,depth)
            return states
        return self.statement(fn,node,states,depth)

    def statement(self,fn,node,states,depth):
        done=[s for s in states if s.flow!="normal"];active=[s for s in states if s.flow=="normal"]
        if not active:return states
        kind=node.type
        if kind=="compound_statement":return done+self.block(fn,node,active,depth)
        if kind=="if_statement":
            cond=node.child_by_field_name("condition");yes=node.child_by_field_name("consequence");no=node.child_by_field_name("alternative")
            result=[]
            for s in active:
                result+=self.block(fn,yes,self.refine(fn,cond,s,True,depth),depth)
                ns=self.refine(fn,cond,s,False,depth)
                if no and no.type=="else_clause":
                    no=no.named_children[-1] if no.named_children else None
                result+=self.block(fn,no,ns,depth)
            return self.bounded(done+result)
        if kind=="switch_statement":
            body=node.child_by_field_name("body");cases=[c for c in body.named_children if c.type=="case_statement"] if body else []
            result=[]
            for s in active:
                # Independent case entries plus real C/C++ fall-through. A
                # preceding case's guard cannot protect another entry case.
                for index in range(len(cases)):
                    branch=[s.fork(trace=s.trace+((cases[index].start_point[0]+1,"switch entry"),))]
                    for case in cases[index:]:
                        branch=self.block(fn,case,branch,depth)
                    result.extend(t.fork(flow="normal") if t.flow=="break" else t for t in branch)
                if not any(fn.text(c).lstrip().startswith("default") for c in cases):result.append(s.fork())
            return self.bounded(done+result)
        if kind in ("for_statement","while_statement","do_statement","for_range_loop"):
            self.limitations.add("Loops are conservatively explored zero/one iterations; no induction or termination proof.")
            result=[];body=node.child_by_field_name("body")
            for s in active:
                result.append(s.fork())
                one=self.block(fn,body,[s.fork()],depth)
                result.extend(t.fork(flow="normal") if t.flow in ("break","continue") else t for t in one)
            return self.bounded(done+result)
        if kind in ("return_statement","throw_statement"):
            for s in active:
                expr=node.named_children[0] if node.named_children else None
                s.returned=self.value(fn,expr,s,depth);s.flow="return"
            return done+active
        if kind in ("break_statement","continue_statement"):
            return done+[s.fork(flow="break" if kind=="break_statement" else "continue") for s in active]
        if kind in ("goto_statement","try_statement","preproc_if","preproc_ifdef"):
            self.limitations.add("Unsupported control construct: "+kind+"; guards not proved through it.")
            for s in active:
                s.auth=frozenset();s.descriptor=frozenset();s.owner=frozenset()
        for s in active:
            if kind=="declaration":
                for dec in node.named_children:
                    if dec.type=="init_declarator":
                        d=dec.child_by_field_name("declarator")
                        ids=list(walk(d,"identifier")) if d else []
                        name=fn.text(ids[-1] if ids else d)
                        self.assign(s,name,self.value(fn,dec.child_by_field_name("value"),s,depth))
                    elif dec.type=="array_declarator":
                        name=fn.text(dec.child_by_field_name("declarator"));size=fn.text(dec.child_by_field_name("size"))
                        self.capacities[name]=size
                        # sizeof(buf) is a matching bound independently of element size.
                        self.capacities["sizeof("+name+")"]=size
            elif kind=="expression_statement":
                for expr in node.named_children:
                    if expr.type=="binary_expression" and fn.text(expr.child_by_field_name("operator")) in ("&&","||"):
                        # Evaluate both *paths*, never blindly execute both operands.
                        forks=self.refine(fn,expr,s,True,depth)+self.refine(fn,expr,s,False,depth)
                        if forks:
                            s.auth=frozenset.intersection(*(t.auth for t in forks))
                            s.descriptor=frozenset.intersection(*(t.descriptor for t in forks))
                    else:self.value(fn,expr,s,depth)
            else:
                self.value(fn,node,s,depth)
        return self.bounded(done+active)

    def _entry_roots(self):
        """Entry roots: the legacy name allowlist, then source-derived dispatch handlers.

        The allowlist is kept as the lower-grade fallback, so nothing that was
        analysed before stops being analysed. Dispatch-derived handlers are added
        only when the index bound them to exactly one definition.
        """
        roots, seen = [], set()
        for fn in self.functions:
            if not ((fn.name in self.policy.entry_names or fn.name in self.policy.transport_entries or (fn.name.endswith("Inner") and "Stub" in fn.owner)) and fn.parcel_params or fn.qualified in self.policy.service_entries):
                continue
            roots.append((fn, "allowlist", ""))
            seen.add((fn.file, fn.qualified))
        if self.index is None:
            return roots
        for owner, name, _ambiguity in self.index.root_bindings():
            matches = self.functions_by_owner_name.get((owner, name), [])
            if len(matches) != 1:
                self.limitations.add("Dispatch handler not uniquely resolved: " + owner
                                     + "::" + name + "; not used as an entry")
                continue
            fn = matches[0]
            if (fn.file, fn.qualified) in seen:
                continue
            seen.add((fn.file, fn.qualified))
            roots.append((fn, "dispatch", self.index.dispatch_note(owner, name)))
        return roots

    def run(self):
        for fn, grade, note in self._entry_roots():
            self.root=fn;self.root_grade=grade;self.root_note=note
            self.capacities={};self.active=(fn,)
            env={p:Value("parcel",p) if p in fn.parcel_params else Value("request",p)
                 for p in fn.params}
            self.block(fn,fn.body,[State(env=env)],0)
        revised=[]
        for obs in self.observations:
            if obs.rule=="ipc.auth.missing":
                # Permission call somewhere is not coverage. Keep the primary
                # finding and add the explicit coverage subtype for these roots.
                if obs.root_key in self.seen_permissions:
                    revised.append(replace(obs,family="AUTH-04",rule="ipc.auth.guard-coverage",
                        message="Authorization checks exist in the analyzed entry set, but this modeled sensitive path has no matched caller guard. "+obs.message))
            revised.append(obs)
        summary=self._macro_summary()
        if summary is not None:
            self.limitations.add(summary)
        unique={}
        for obs in revised:
            unique.setdefault((obs.file,obs.line,obs.rule,obs.symbol),obs)
        return tuple(unique[k] for k in sorted(unique)),tuple(sorted(self.limitations))
