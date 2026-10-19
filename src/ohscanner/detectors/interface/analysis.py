"""Bounded disjunctive interpretation of structured C/C++ IPC functions.

Private detector analysis, not a replacement shared IR. It reuses the project's
Tree-sitter dependency to recover branches absent from the public AST outline.
No compiler CFG, overload resolution or exploitability proof. Macros are expanded
by `cpp_macros` under an explicit catalogue: a guard written inside a macro body
becomes real interpreted control flow, and everything the expander refused is
reported rather than assumed.
"""
from dataclasses import dataclass, field, replace
from contextlib import contextmanager
import re
from typing import Optional

from tree_sitter import Language, Parser
import tree_sitter_cpp
import tree_sitter_c

from .cpp_macros import Expansion, catalog_for_units, expand_with_catalog
from .entry_index import EntryIndex
from .families import merge_policy
from .models import DISCLOSURE_CALLS, IpcPolicy, consequence_for
from src.parser.syntax_normalize import normalize_member_pointer_syntax

_TEST_ONLY_PATH_SEGMENTS = frozenset({
    "test", "tests", "unittest", "unittests", "fuzz", "fuzztest",
    "fuzztests", "fuzzer", "fuzzers", "mock", "mocks", "rdbmock",
})


def _test_only_source(path):
    segments = path.replace(chr(92), "/").lower().split("/")
    return bool(_TEST_ONLY_PATH_SEGMENTS.intersection(segments))


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


class _Suspended:
    """Inert stand-in for a reporting sink while a value is computed, not walked."""

    def add(self, *items):
        return None

    def __call__(self, *args, **kwargs):
        return None


def _returns_true(value):
    """Whether a returned expression's value is the boolean true.

    A returned comparison counts. `return callingUid == ROOT_UID;` is true on
    exactly the paths where that fact holds, so the return carries the fact
    rather than being an unexplained UNKNOWN for its caller.
    """
    if value.key in ("true", "1"):
        return True
    return (value.kind == "predicate" and len(value.predicate) >= 3
            and value.predicate[2] is True)


def _returned_fact(value):
    """The authorization fact a returned expression names, when it names one.

    Only an authorization predicate contributes. A caller-class or descriptor
    predicate already has its own channel through the plain value path, and
    relabelling one of those as an authorization fact here would credit a guard
    the helper did not make.
    """
    if value.kind != "predicate" or len(value.predicate) < 3:
        return frozenset()
    if value.predicate[0] == "auth" and value.predicate[2] is True:
        return frozenset({value.predicate[1]})
    return frozenset()


def _returned_caller_class(value):
    """The caller class established by a true-valued helper return, if any.

    Unlike a permission fact, a caller-role predicate must remain on the
    caller-class channel when summarized through a local boolean helper.
    """
    if (value.kind == "predicate" and len(value.predicate) >= 3
            and value.predicate[0] == "caller_class"
            and value.predicate[2] is True):
        return frozenset({value.predicate[1]})
    return frozenset()


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
    # Variables holding a pointer into a parcel's own buffer, and the variables
    # whose view was invalidated by a later reuse/rewind on that parcel. Kept on
    # the path state because the invalidation is an operation on the path, not a
    # property of the declaration.
    parcel_views: frozenset = frozenset()
    invalidated_views: tuple = ()
    # `ResetCallingIdentity()` was called and its returned identity was thrown
    # away, so there is nothing on this path that can restore the caller. Kept
    # apart from `reset` itself: saving the identity and acting as the service is
    # a deliberate, restorable protocol; dropping the saved identity is not.
    identity_discarded: bool = False
    # Reviewed service-account roles established on this path. Separate from
    # `auth` because an account is not a permission: what it authorizes is fixed
    # by the reviewed record that named it, not by the fact that a guard ran.
    service_account: frozenset = frozenset()
    identity_issues: tuple = ()
    # Descriptor comparisons seen on this path whose interface identity could not
    # be accepted as this transaction's guard: ((outcome, name, where_compared,
    # what_the_stub_states), ...). A record of what was seen, so a candidate can
    # say "present but mismatched/unresolved" instead of "absent".
    descriptor_issues: tuple = ()
    # Symbols a caller-identity comparison was made against, when this analysis
    # does not bind them to a value. The comparison is real, so the guard cannot
    # be read as absent; its effect is unknown here, so it cannot be credited
    # either. Kept on the path so the candidate can say which it is.
    auth_issues: tuple = ()
    reset: bool = False
    # The thread's binder identity was set to the *original caller's* token
    # (`SetCallingIdentity(GetCallingFullTokenID())` and the like), so a call
    # leaving this process through a proxy carries that caller rather than this
    # service. Cleared by `ResetCallingIdentity`; restoring the service's own
    # saved identity (`SetCallingIdentity(saved)`) does not set it.
    forwarded: bool = False
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
    # Parameter names declared as non-const lvalue references, when the frame came
    # from the entry index's one-hop lookup: an argument bound to one of these can
    # carry the callee's result back to the caller, which is how a stub receives
    # the remote object it then writes into the reply.
    ref_params: tuple = ()
    # 1-based line of the definition, when the frame came from the index.
    line: int = 0
    # Parcel parameters after the request parcel. In the OpenHarmony stub shape
    # `(code, data, reply, option)` the second parcel is the reply buffer; a
    # write to it is what makes a value visible to the remote caller, so it is
    # modelled separately from the request rather than as another request.
    reply_params: tuple = ()

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
    normalized = normalize_member_pointer_syntax(normalized)
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


_PREPROC_HEADS = {"preproc_ifdef": 1, "preproc_if": 1, "preproc_elif": 1, "preproc_else": 0}


def _preproc_arms(node, text):
    """Every arm of one preprocessor conditional, in order: `(condition, statements)`.

    `#ifdef X ... #else ... #endif` is two arms, and `#if/#elif/#else` nests its
    later arms inside the previous node, so this walks the chain rather than only
    reading the outer node. A chain with no `#else` gets no arm synthesised here:
    the caller adds the "no arm taken" path, because that path is real, and
    dropping it would let `#ifdef X return; #endif Work();` read as though
    `Work()` were unreachable.
    """
    head = _PREPROC_HEADS[node.type]
    children = list(node.named_children)
    condition = ""
    if node.type in ("preproc_if", "preproc_elif") and children:
        condition = text(children[0])
    elif node.type == "preproc_ifdef" and children:
        directive = node.children[0].type if node.children else "#ifdef"
        condition = directive + " " + text(children[0])
    elif node.type == "preproc_else":
        condition = "#else"
    arms, body = [], []
    for child in children[head:]:
        if child.type in ("preproc_elif", "preproc_else"):
            arms.append((condition, body))
            arms.extend(_preproc_arms(child, text))
            return arms
        body.append(child)
    arms.append((condition, body))
    return arms


def _preproc_closed(node):
    """Whether a conditional chain ends in `#else`, so some arm is always taken."""
    return any(item.type == "preproc_else" for item in walk(node))


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
    def __init__(self, units, policy: IpcPolicy, request=None):
        self.units = tuple(units)
        # A harness may hand this walk a hand-built policy; the families' reviewed
        # additions are merged in either way, so a walk through the detector and a
        # walk through a script interpret the same sources under the same policy.
        self.policy = merge_policy(policy)
        # The scan this walk belongs to, when the caller bound one. Only used to
        # name the target a service-account claim was read against; a walk without
        # it still runs, and says the target is unstated rather than inventing one.
        self.request = request
        # Reviewed service-account roles by the constant a guard names, and the
        # operations each role authorizes. An account role is not a permission, so
        # it travels on its own channel and is consumed only by `authorized`.
        repository = request.repository if request is not None else None
        account_models = tuple(
            entry for entry in self.policy.service_account_roles
            if not entry.repository or entry.repository == repository
        ) + tuple(
            entry for entry in self.policy.repository_service_account_roles
            if entry.repository and entry.repository == repository
        )
        self.account_roles = {entry.constant: entry for entry in account_models}
        self.account_accepts = {entry.role: frozenset(entry.accepted_operations)
                                for entry in account_models}
        self.account_notes = set()
        self.functions = []
        self.observations = []
        self.limitations = set()
        self.test_only_roots_skipped = set()
        self.seen_permissions = set()
        self.permission_mismatch_roots = set()
        # Provenance for every cross-TU one-hop guard this run credited, one line
        # each. Kept separately from `limitations` while the walk is in progress so
        # a hop note is never mistaken for a refusal, and merged in `run()`.
        self.hop_notes = set()
        # Cross-service boundaries this walk actually reached, as
        # (file, line, called method, identity carried across). A boundary is
        # recorded only when the handle was built by `iface_cast<...>` in the
        # scanned sources; a handle that arrives as a parameter or through an
        # unmodelled factory is not claimed as one.
        self.proxy_notes = set()
        # `(owner, name) -> implementation or None`. Source-derived and
        # root-independent, so it is built once per detector run rather than
        # re-walked for every unqualified call met in the corpus.
        self.hop_cache = {}
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
        for unit in self.units:
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
                                                   source, tuple(params), tuple(parcels[:1]),
                                                   line=node.start_point[0] + 1,
                                                   reply_params=tuple(parcels[1:])))
        self._build_index(units)

    def unbounded_observer_registrations(self):
        """Find unbounded observer sinks and bind direct source paths when possible.

        Candidate discovery remains conservative when the hierarchy is missing or
        ambiguous. A path note is attached only when one scanned stub implementation
        is unique and the observer argument is forwarded unchanged through the
        implementation to the collection insertion.
        """
        def body_text(fn):
            return fn.text(fn.body)

        def named_calls(fn, name):
            for node in walk(fn.body, "call_expression"):
                callee_node = node.child_by_field_name("function")
                if callee_node is None or terminal(fn.text(callee_node)) != name:
                    continue
                arguments_node = node.child_by_field_name("arguments")
                arguments = tuple(fn.text(arg).strip() for arg in
                                  (arguments_node.named_children if arguments_node else ()))
                yield node, arguments

        roots = [fn for fn in self.functions
                 if fn.name.startswith("On") and "Observer" in fn.name
                 and re.search(r"\bSubscribeObserver\s*\(", body_text(fn))]
        if not roots:
            return ()
        subscribe_impls = [fn for fn in self.functions if fn.name == "SubscribeObserver"
                           and re.search(r"\bAddObserver\s*\(", body_text(fn))]
        if not subscribe_impls:
            return ()
        sink_owners = {fn.owner for fn in subscribe_impls if fn.owner}
        if not sink_owners:
            return ()
        sinks = []
        for fn in self.functions:
            if fn.name != "AddObserver" or fn.owner not in sink_owners:
                continue
            body = body_text(fn)
            insert = re.search(
                r"(?:->|\.)\s*(?:insert|push_back|emplace|emplace_back)\s*\(\s*[^)]*\b(observer|callback)\b",
                body,
            )
            if insert is None:
                continue
            aggregate_count = re.search(
                r"\b(?:auto|uint(?:32_t)?|size_t)\s+(\w+)\s*=\s*GetAllObserversSize\s*\(", body
            )
            aggregate_name = aggregate_count.group(1) if aggregate_count and "MAX_OBSERVER_COUNT" in body else None
            insertion_byte = fn.body.start_byte + len(body[:insert.start()].encode("utf-8"))
            bounded = False
            for branch in walk(fn.body, "if_statement"):
                if branch.end_byte > insertion_byte:
                    continue
                condition = fn.text(branch.child_by_field_name("condition"))
                consequence_node = branch.child_by_field_name("consequence")
                direct_exit = consequence_node is not None and (
                    consequence_node.type in ("return_statement", "throw_statement")
                    or any(child.type in ("return_statement", "throw_statement")
                           for child in consequence_node.named_children)
                )
                if (aggregate_name
                        and re.search(r"\bMAX_OBSERVER_COUNT\b", condition)
                        and re.search(r"\b" + re.escape(aggregate_name) + r"\b", condition)
                        and re.search(r"(?:>=|>)", condition)
                        and direct_exit):
                    bounded = True
                    break
            if bounded:
                continue
            line = fn.body.start_point[0] + 1 + body[:insert.start()].count("\n")
            path_notes = []
            if self.index is not None:
                sink_param_name = insert.group(1)
                sink_positions = [i for i, name in enumerate(fn.params) if name == sink_param_name]
                if len(sink_positions) == 1:
                    sink_observer_pos = sink_positions[0]
                    for root in roots:
                        entry = self.index.one_hop_definition(root.owner, "SubscribeObserver")
                        if entry is None:
                            continue
                        implementations = [candidate for candidate in self.functions_by_owner_name.get(
                            (entry.owner.rsplit("::", 1)[-1], entry.name), ())
                            if candidate.file == entry.file and candidate.qualified == entry.qualified]
                        if len(implementations) != 1:
                            continue
                        implementation = implementations[0]
                        observer_positions = [i for i, name in enumerate(implementation.params)
                                              if name in ("observer", "callback")]
                        if len(observer_positions) != 1:
                            continue
                        observer_pos = observer_positions[0]
                        root_calls = list(named_calls(root, "SubscribeObserver"))
                        if len(root_calls) != 1:
                            continue
                        root_node, root_args = root_calls[0]
                        if observer_pos >= len(root_args):
                            continue
                        root_value = root_args[observer_pos]
                        if not re.fullmatch(r"[A-Za-z_]\w*", root_value):
                            continue
                        add_calls = [(node, args) for node, args in named_calls(implementation, "AddObserver")
                                     if sink_observer_pos < len(args)
                                     and args[sink_observer_pos] == implementation.params[observer_pos]]
                        if not add_calls:
                            continue
                        root_name = (root.qualified if "::" in root.qualified or not root.owner
                                     else root.owner + "::" + root.name)
                        implementation_name = (
                            implementation.qualified if "::" in implementation.qualified
                            or not implementation.owner else implementation.owner + "::" + implementation.name)
                        sink_name = (fn.qualified if "::" in fn.qualified or not fn.owner
                                     else fn.owner + "::" + fn.name)
                        add_lines = ",".join(str(node.start_point[0] + 1) for node, _ in add_calls)
                        path_notes.append(
                            "source-indexed direct-argument path: " + root_name + " at "
                            + root.file + ":" + str(root_node.start_point[0] + 1) + " forwards "
                            + root_value + " to " + implementation_name + " at "
                            + implementation.file + ":" + str(implementation.line or
                                implementation.body.start_point[0] + 1) + "; AddObserver call site(s) "
                            + implementation.file + ":" + add_lines + " forward its "
                            + implementation.params[observer_pos] + " parameter unchanged to "
                            + sink_name + " at " + fn.file + ":" + str(line)
                            + ", where that parameter is inserted. This is source-path evidence only."
                        )
            path_note = path_notes[0] if len(set(path_notes)) == 1 else None
            sinks.append((fn, line, insert.group(1), path_note))
        return tuple(sinks)

    def privileged_permission_grants(self):
        """Find a default-app exemption and bind it to the scanned IPC path.

        Keep conservative candidate discovery when a unique source hierarchy is
        unavailable, but attach a concrete path only when the source index resolves
        the stub virtual call to one implementation and that implementation calls
        the verifier. A missing or partial class graph is not proof that no path
        exists.
        """
        roots = [fn for fn in self.functions
                 if fn.name == "OnGetPasteData"
                 and re.search(r"\bGetPasteData\s*\(", fn.text(fn.body))]
        if not roots:
            return ()

        paths_by_owner = {}
        if self.index is not None:
            for root in roots:
                entry = self.index.one_hop_definition(root.owner, "GetPasteData")
                if entry is None:
                    continue
                implementations = [
                    fn for fn in self.functions_by_owner_name.get(
                        (entry.owner.rsplit("::", 1)[-1], entry.name), ())
                    if fn.file == entry.file and fn.qualified == entry.qualified
                ]
                if len(implementations) != 1:
                    continue
                implementation = implementations[0]
                if not re.search(r"\bVerifyPermission\s*\(",
                                 implementation.text(implementation.body)):
                    continue
                root_line = root.body.start_point[0] + 1
                implementation_line = implementation.body.start_point[0] + 1
                root_name = (root.qualified if "::" in root.qualified or not root.owner
                             else root.owner + "::" + root.name)
                implementation_name = (
                    implementation.qualified if "::" in implementation.qualified
                    or not implementation.owner else implementation.owner + "::" + implementation.name)
                paths_by_owner.setdefault(implementation.owner, []).append(
                    "source-indexed within this scope: " + root_name + " at "
                    + root.file + ":" + str(root_line) + " -> "
                    + implementation_name + " at " + implementation.file + ":"
                    + str(implementation_line) + " -> VerifyPermission"
                )

        results = []
        for verifier in self.functions:
            if verifier.name != "VerifyPermission" or not verifier.owner:
                continue
            body = verifier.text(verifier.body)
            privilege = re.search(
                r"\b(?:auto|bool)\s+(\w+)\s*=\s*IsDefaultIME\s*\(", body
            )
            grant = re.search(
                r"\b(?:auto|bool)\s+isGrant\s*=\s*([^;]+);", body
            )
            if privilege is None or grant is None:
                continue
            if not re.search(r"\b" + re.escape(privilege.group(1)) + r"\b", grant.group(1)):
                continue
            callers = [fn for fn in self.functions
                       if fn.name == "GetPasteData" and fn.owner == verifier.owner
                       and re.search(r"\bVerifyPermission\s*\(", fn.text(fn.body))]
            if not callers:
                continue
            line = verifier.body.start_point[0] + 1 + body[:grant.start()].count("\n")
            path_notes = paths_by_owner.get(verifier.owner, ())
            path_note = path_notes[0] if len(set(path_notes)) == 1 else None
            helper_candidates = [candidate for candidate in self.functions
                                 if candidate.name == "IsDefaultIME"
                                 and candidate.owner == verifier.owner]
            empty_branch_note = None
            if len(helper_candidates) == 1:
                helper = helper_candidates[0]
                helper_body = helper.text(helper.body)
                empty_true = re.search(
                    r"if\s*\(\s*(\w+(?:->\w+|\.\w+)*)\s*\.\s*empty\s*\(\s*\)\s*\)\s*\{\s*return\s+true\s*;",
                    helper_body,
                )
                if empty_true is not None:
                    helper_line = helper.body.start_point[0] + 1 + helper_body[:empty_true.start()].count("\n")
                    empty_branch_note = (
                        helper.qualified + " returns true when " + empty_true.group(1)
                        + " is empty at " + helper.file + ":" + str(helper_line)
                        + "; because the result contributes to isGrant, empty configuration "
                        + "can contribute to the verifier grant. Configuration state is unknown."
                    )
            results.append((verifier, line, privilege.group(1), path_note, empty_branch_note))
        return tuple(results)
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
        # Call resolution looks a name up in the current file. A component can
        # carry tens of thousands of functions, so that lookup is indexed rather
        # than scanned: the scan was the dominant cost on graphic_graphic_2d
        # (3411 files) and made a single component take longer than the other 53.
        self.functions_by_file_name = {}
        for fn in self.functions:
            owner = fn.owner.rsplit("::", 1)[-1] if fn.owner else ""
            self.functions_by_owner_name.setdefault((owner, fn.name), []).append(fn)
            self.functions_by_file_name.setdefault((fn.file, fn.name), []).append(fn)

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
                                # A view live on every path is still a view; an
                                # invalidation seen on any path is kept, because
                                # the joined state must not report a use as safe
                                # on the strength of the paths that did not
                                # invalidate.
                                parcel_views=intersection("parcel_views"),
                                invalidated_views=tuple(dict.fromkeys(
                                    item for s in group for item in s.invalidated_views)),
                                identity_discarded=any(s.identity_discarded for s in group),
                                service_account=intersection("service_account"),
                                identity_issues=tuple(issue for s in group for issue in s.identity_issues),
                                descriptor_issues=tuple(dict.fromkeys(
                                    issue for s in group for issue in s.descriptor_issues)),
                                auth_issues=tuple(dict.fromkeys(
                                    issue for s in group for issue in s.auth_issues)),
                                reset=any(s.reset for s in group),
                                # Either path may leave through the proxy with
                                # the caller's identity, so the joined state
                                # records that a change point was carried.
                                forwarded=any(s.forwarded for s in group), flow=flow,
                                trace=((0, "conservative path join"),)))
        return result

    @contextmanager
    def lookahead(self):
        """Suspend reporting while a value is computed rather than a path walked.

        `relay_guard` reads into a handler body to find its descriptor comparison.
        That read starts from the state preceding the handler's own guards, so the
        state it computes in is not one the program can be in: a sensitive call met
        on the way there would be reported with those guards missing, while the
        real walk reports the same call with them present. The look-ahead only
        needs the values it computes, so emission and coverage bookkeeping are
        suspended for its duration -- a permission read seen only on a look-ahead
        does not show that an analysed path performed one.
        """
        sink = _Suspended()
        saved = self.emit, self.limitations, self.seen_permissions, self.proxy_notes
        self.emit, self.limitations, self.seen_permissions = sink, sink, sink
        # A boundary met while reading a handler only to find its guard is not a
        # call the analysed paths made, so it is not counted either.
        self.proxy_notes = set()
        try:
            yield
        finally:
            (self.emit, self.limitations, self.seen_permissions,
             self.proxy_notes) = saved

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
        """The one definition a written call names, preferring this file.

        `f.file == fn.file` alone silently dropped a body that lives in another
        translation unit -- a stub calling `Class::Method()` where the class is
        implemented elsewhere. The widening is bounded to what the call site
        already states:

        * only an explicitly qualified callee can resolve out of its file. An
          unqualified name is still this file (or a hop the entry index models);
          nothing is resolved by last-name-only search;
        * the qualifier must equal the definition's owner, or its last component
          for a body written inside the class (`NS::Foo::Bar` call, `Foo` owner);
        * the match must be unique. An overload set, or a definition visible both
          inside and outside the class, stays unresolved rather than picking one.

        A receiver other than `this` is never resolved: `other->Guard()` names an
        object, and nothing in the call says what that object is.
        """
        receiver = name.rsplit("->", 1)[0] if "->" in name else None
        if "." in name or (receiver is not None and receiver != "this"):
            return None
        prefix = name.rsplit("::", 1)[0] if "::" in name else fn.owner
        matches = [f for f in self.functions_by_file_name.get((fn.file, terminal(name)), ())
                   if f.owner == prefix]
        if matches:
            return matches[0] if len(matches) == 1 else None
        if "::" not in name:
            return None
        short = prefix.rsplit("::", 1)[-1]
        qualified = [f for f in self.functions_by_owner_name.get((short, terminal(name)), ())
                     if f.owner in (prefix, short)]
        return qualified[0] if len(qualified) == 1 else None

    def delegated(self, fn, callee):
        """Resolve a source-backed singleton or typed-member receiver.

        OpenHarmony stubs hand the request to the service implementation, which
        lives in another file: `DelayedSingleton<XxxService>::GetInstance()->Method()`
        or an object macro standing for exactly that expression. The receiver type
        must be source-backed (an object macro, or an explicit `Type::GetInstance()`)
        and the target must resolve to exactly one definition; anything else stays
        unresolved rather than becoming a general cross-file name resolver.
        """
        if self.index is None:
            return None
        target = self.index.resolve_receiver(callee, fn.owner)
        if not target or "::" not in target:
            return None
        owner, name = target.rsplit("::", 1)
        matches = self.functions_by_owner_name.get((owner.rsplit("::", 1)[-1], name), [])
        return matches[0] if len(matches) == 1 else None

    def one_hop_dispatch(self, fn, node, callee, name, args, state):
        """Read one class hop past an unqualified virtual dispatch, when it guards.

        OpenHarmony implements an IPC stub by inheritance: the concrete service
        derives from its stub (`class ScreenSessionManager : public SystemAbility,
        public ScreenSessionManagerStub`) and supplies the handler body in another
        translation unit. The call written in the stub is an unqualified member
        call, so `resolve` (same file only) and `delegated` (an explicit
        `GetInstance()` receiver) both decline it, and the body that actually runs
        was never read. A `::`, `.` or `->` qualified callee is not this case and is
        left alone.

        Returns ``(None, None)`` when no single implementer was found -- an overload
        set, a class the shard does not contain, an unresolvable name -- which keeps
        the call a candidate rather than guessing at one. The lookup is memoised
        because it is source-derived and independent of which root is being walked.
        """
        if self.index is None or not name:
            return None, None, None
        if "::" in callee or "." in callee or "->" in callee:
            return None, None, None
        key = (fn.owner, name)
        if key not in self.hop_cache:
            self.hop_cache[key] = self.index.one_hop_definition(fn.owner, name)
        entry = self.hop_cache[key]
        if entry is None:
            return None, None, None
        # Read the implementer through the same frame type the rest of the walk
        # uses, so one body-walking implementation covers both. A body written
        # inside the class carries only its own name, so the owner is put back:
        # a provenance line naming a bare `Get` cannot be checked against source.
        qualified = entry.qualified if "::" in entry.qualified or not entry.owner \
            else entry.owner + "::" + entry.name
        implementation = Function(entry.file, entry.name, qualified, entry.owner,
                                  entry.node, entry.body, entry.source,
                                  tuple(name for _type, name in entry.params), (),
                                  tuple(entry.ref_params), entry.line)
        # What this call site settles about the implementer's parameters, by
        # position. The implementer's names are not the caller's, so the binding is
        # positional, the same way the body walk binds a locally resolved callee.
        arguments = node.child_by_field_name("arguments")
        supplied = list(arguments.named_children) if arguments is not None else []
        bindings = {}
        for position, param_name in enumerate(implementation.params):
            if position >= len(supplied):
                break
            if not param_name:
                continue
            decided = self._decisive(fn, supplied[position])
            if decided is not None:
                bindings[param_name] = decided
        # Reading the implementer's body must not report into this walk: it starts
        # from that body's own guards, not from this path's.
        with self.lookahead():
            gate = self.dispatch_guard(implementation, bindings)
            contract = self.caller_class_contract_through(implementation)
        required_role = contract[0] if contract else None
        role_guarded = bool(gate and (required_role is None or required_role in gate[2]))
        # Bind only contract-reviewed reference outputs. A role gate only protects
        # those results when it proves the exact role required by the API contract.
        output_positions = (dict(self.policy.disclosure_output_calls).get(name, ())
                            if required_role is not None else ())
        self.bind_result(state, implementation, args,
                         Value("call_result", implementation.qualified,
                               "guarded" if role_guarded else "unguarded"),
                         disclosure_positions=output_positions,
                         disclosure_guarded=role_guarded)
        if gate is not None:
            gate_function, gate_node, gate_roles = gate
            self.hop_notes.add(
                "Cross-TU one-hop guard credited: " + fn.qualified + " at "
                + self._where(fn.file, fn, node) + " dispatches to "
                + implementation.qualified + " at " + implementation.file + ":"
                + str(implementation.line) + ", whose source-derived delegation chain "
                + "reaches caller-role gate at "
                + self._where(gate_function.file, gate_function, gate_node)
                + " in " + gate_function.qualified + ", whose caller-role gate admits "
                + ", ".join(gate_roles) + ".")
        return implementation, gate, required_role

    def _where(self, file, fn, node):
        """`file:line` for a node, read back through the macro line map."""
        if node is None:
            return file + ":" + str(fn.line)
        line_map = self.line_maps.get(file) or {}
        line = node.start_point[0] + 1
        return file + ":" + str(line_map.get(line, line))

    def boundary(self, fn, node, method, state):
        """Record that this path leaves the process through a proxy handle.

        The identity a downstream service sees is not the identity this handler
        was entered with. Unless the path explicitly set the calling identity to
        the original caller's token, the downstream call runs as this service.
        Keeping the change point means a later reader cannot assume the entry's
        authorization carried across the boundary: it either did (the path says
        so) or it did not.

        Nothing is credited from this record and no rule keys on it yet; what it
        refuses to do is assume identity was preserved.
        """
        self.proxy_notes.add((self._where(fn.file, fn, node), method,
                              "caller" if state.forwarded else "service"))

    def bind_result(self, state, implementation, args, produced,
                    disclosure_positions=(), disclosure_guarded=False):
        """Bind reviewed result outputs and reference results from a dispatch."

        A stub receives the remote object from the implementation it dispatches to
        and then writes it into the reply. Which caller variable holds it is a
        call-site fact -- the implementer's parameter names are not the caller's
        variable names -- so the binding is by argument position and only over the
        reference parameters, which is the shape that carries a result back.
        Pointer out-parameters are not bound: a pointer argument does not say
        whether it is written to.
        """
        params = implementation.params
        for position in range(min(len(params), len(args))):
            # A repository-scoped disclosure contract may supply exact output
            # positions when a partial header/index did not recover the declaration.
            if (position not in disclosure_positions
                    and params[position] not in implementation.ref_params):
                continue
            if args[position].key:
                if position in disclosure_positions:
                    kind = "sensitive_result_guarded" if disclosure_guarded else "sensitive_result"
                    state.env[args[position].key] = Value(kind, implementation.qualified,
                                                          implementation.name)
                else:
                    state.env[args[position].key] = produced

    @staticmethod
    def _leaves(branch):
        """Whether a branch ends by leaving the transaction on the paths it has."""
        block = branch if branch.type == "compound_statement" else None
        statements = list(block.named_children) if block is not None else [branch]
        return bool(statements) and statements[-1].type in _RELAY_LEAVES

    def _modelled_before(self, implementation, statements):
        """Known effects or potential reference-output writes before a gate.

        This is a conservative syntactic check, not alias or side-effect proof.
        A write in the rejected arm is also before the alleged safe return.
        """
        modelled = (self.policy.sensitive_calls | self.policy.object_sensitive_calls
                    | self.policy.capability_calls | self.policy.copy_calls
                    | self.policy.boolean_permissions | self.policy.result_permissions
                    | frozenset({"ResetCallingIdentity", "SetCallingIdentity"}))
        outputs = set(implementation.ref_params)
        contract = self.repository_caller_class_contract(implementation.qualified)
        if contract:
            modelled = modelled | frozenset(contract[1])
        for statement in statements:
            for item in walk(statement):
                if item.type in ("assignment_expression", "update_expression"):
                    left = item.child_by_field_name("left") or item.child_by_field_name("argument")
                    identifiers = {implementation.text(n) for n in walk(left, "identifier")} if left else set()
                    if outputs & identifiers:
                        return True
                if item.type != "call_expression":
                    continue
                function = item.child_by_field_name("function")
                if terminal(implementation.text(function)) in modelled:
                    return True
                # Unknown calls that receive or operate on a reference output
                # may write it. Decline credit rather than assuming purity.
                identifiers = {implementation.text(n) for n in walk(item, "identifier")}
                if outputs & identifiers:
                    return True
        return False

    def dispatch_guard(self, implementation, bindings=None, seen=None):
        """What a cross-TU one-hop dispatch lands on, when the callee gates on role.

        Returns ``(gate_node, roles)`` when the implementer's own body rejects
        callers that hold no privileged role before it does anything this analysis
        models, else ``None`` -- and then the call site keeps its candidate.

        The body is read on a frame holding its parameters and nothing else: a
        function starts with its parameters, so a fact that happened to hold at the
        call site cannot stand in for a guard the callee never made. `bindings` is
        the exception, and it is the caller's own: an argument that proves something
        about a parameter -- `&errorCode`, a null literal -- is a fact about *this*
        call, not about the callee. Three conditions decide whether the gate is real:

        * the branch the condition *takes* leaves the transaction and carries no
          caller role on any path that reaches it, and
        * the continuing branch is reachable, and *every* path out of the gate
          carries one,

        which is what "callers that are neither system nor shell are rejected here"
        means in terms of the facts this analysis tracks. Both directions are needed.
        A gate that can be short-circuited past by the callers it was meant to stop
        -- ``!IsSystemCalling() || !IsShellCall()``, or ``!IsSystemCalling() &&
        <undecided>`` -- leaves a continuing path holding no role, and one that turns
        away the callers it was meant to admit leaves a taken path holding one. Both
        are declined, so an unread or partial guard leaves the call a candidate
        rather than being read as one.
        """
        seen = set() if seen is None else set(seen)
        key = (implementation.file, implementation.qualified, implementation.line)
        if implementation.body is None or key in seen or len(seen) >= 3:
            return None
        seen.add(key)
        frame = State(env={name: Value("request", name)
                           for name in implementation.params if name})
        # What the call site proves about the parameters. `&& errorCode` is true
        # whenever the caller passed an address, so a conjunct the caller settles is
        # decided rather than left open -- without this, the branch where the caller
        # passed a null is a continuing path with no role and the gate is declined.
        frame.env.update(bindings or {})
        statements = list(implementation.body.named_children)
        for position, item in enumerate(statements):
            if item.type != "if_statement":
                continue
            taken = item.child_by_field_name("consequence")
            if taken is None or not self._leaves(taken):
                continue
            if self._modelled_before(implementation, statements[:position] + [taken]):
                return None
            condition = item.child_by_field_name("condition")
            if self._modelled_before(implementation, [condition]):
                return None
            yes = self.refine(implementation, condition, frame, True, 0)
            no = self.refine(implementation, condition, frame, False, 0)
            # Rejected branch: no path taken here carries a privileged caller role --
            # otherwise the gate turns away the callers it was meant to admit.
            if not yes or any(s.auth or s.caller_class for s in yes):
                continue
            # Continuing branch: *every* path out of the gate carries one. A single
            # path that reaches the body holding no role is a caller the gate let
            # through, which is what a conjunct the callee cannot settle for an
            # unauthorized caller looks like (`!IsSystemCalling() && <undecided>`).
            if not no or not all(s.auth or s.caller_class for s in no):
                continue
            roles = sorted(set().union(*(s.auth | s.caller_class for s in no)))
            if roles:
                return implementation, item, roles

        # Follow only a unique terminal return through a source-typed member
        # receiver. This is deliberately narrower than general interprocedural
        # flow: no modeled operation may occur before the delegation.
        returns = [(i, item) for i, item in enumerate(statements)
                   if item.type == "return_statement"]
        if len(returns) == 1:
            position, returned = returns[0]
            expression = returned.named_children[0] if returned.named_children else None
            if (position == len(statements) - 1 and expression is not None
                    and expression.type == "call_expression"
                    and not self._modelled_before(implementation, statements[:position])):
                callee = implementation.text(expression.child_by_field_name("function"))
                helper = self.delegated(implementation, callee)
                if helper is not None:
                    arguments = expression.child_by_field_name("arguments")
                    supplied = list(arguments.named_children) if arguments is not None else []
                    nested_bindings = {}
                    for index, name in enumerate(helper.params):
                        if index < len(supplied) and name:
                            decided = self._decisive(implementation, supplied[index])
                            if decided is not None:
                                nested_bindings[name] = decided
                    nested_gate = self.dispatch_guard(helper, nested_bindings, seen)
                    if nested_gate is not None:
                        return nested_gate
        return None

    @staticmethod
    def _decisive(fn, node):
        """The constant an argument proves about the parameter it binds, if any.

        `&errorCode` hands the callee a non-null address, so a conjunct naming that
        parameter is decided at this call site; a null literal decides it the other
        way. Any other argument says nothing about the parameter, which leaves the
        conjunct open and the gate uncredited rather than assumed.
        """
        if node is None:
            return None
        text = fn.text(node).strip()
        if text in ("nullptr", "NULL", "0", "null"):
            return Value("constant", "0")
        # `&x` is a `pointer_expression` in the grammar this pipeline parses with,
        # not a `unary_expression`; reading it as the latter is what left the
        # `&& errorCode` conjunct undecided on a call that passes an address.
        if node.type == "pointer_expression" \
                and fn.text(node.child_by_field_name("operator")) == "&":
            inner = node.child_by_field_name("argument")
            if inner is not None and fn.text(inner).strip() not in ("nullptr", "NULL", "0", "null"):
                return Value("constant", "1")
        return None

    def repository_caller_class_contract(self, qualified):
        repository = self.request.repository if self.request is not None else None
        for owner, method, role, effects in self.policy.repository_caller_class_contracts:
            if owner == repository and method == qualified:
                return role, tuple(effects)
        return None

    def caller_class_contract_through(self, implementation, depth=0, visited=()):
        """Resolve an exact repository contract through a short direct-return chain.

        Only a unique terminal member call with a source-resolved receiver is
        followed. This deliberately does not guess based on a method's short name.
        """
        contract = self.repository_caller_class_contract(implementation.qualified)
        if contract:
            return contract
        key = (implementation.file, implementation.qualified, implementation.line)
        if depth >= 2 or key in visited or implementation.body is None:
            return None
        statements = list(implementation.body.named_children)
        returns = [(i, item) for i, item in enumerate(statements)
                   if item.type == "return_statement"]
        if len(returns) != 1:
            return None
        position, returned = returns[0]
        expression = returned.named_children[0] if returned.named_children else None
        if (position != len(statements) - 1 or expression is None
                or expression.type != "call_expression"
                or self._modelled_before(implementation, statements[:position])):
            return None
        callee = implementation.text(expression.child_by_field_name("function"))
        helper = self.delegated(implementation, callee)
        if helper is None:
            return None
        return self.caller_class_contract_through(helper, depth + 1,
                                                   tuple(visited) + (key,))

    def expected_permission(self, name, qualified=""):
        repository = self.request.repository if self.request is not None else None
        for owner, method, expected in self.policy.repository_expected_permissions:
            if owner == repository and method == qualified:
                return expected
        contracts = dict(self.policy.expected_permissions)
        return contracts.get(qualified) or contracts.get(name)

    def authorized(self, state, name, qualified=""):
        expected = self.expected_permission(name, qualified)
        if expected:
            return expected in state.auth
        # A service-account role is accepted only for the operations the reviewed
        # record names. Recognizing the account that guards an interface is not a
        # statement that the account may do anything else, so this set is computed
        # per operation rather than read as a general authorization.
        account = {role for role in state.service_account
                   if name in self.account_accepts.get(role, ())}
        if name in ("GetRemoteHapTokenInfo","DeleteRemoteHapTokenInfo","UpdateRemoteHapTokenInfo"):
            return bool(state.auth or state.caller_class.intersection({"TOKEN_NATIVE"}) or account)
        return bool(state.auth or account)

    def account_role(self, fn, node, left, right, op):
        """The reviewed account role a caller-UID comparison names, when it names one.

        Three conditions have to hold at once, and each of them is a control:

        * the compared value is the *calling* UID -- `IPCSkeleton::GetCallingUid()`
          on a path whose identity was not reset. A caller TokenID is a different
          domain and a request-derived value is not the caller, so neither is read
          here;
        * the other side names a constant the reviewed account model carries, so a
          bare literal has no reviewed binding to cite;
        * that constant resolves, in the scanned sources, to the value the model
          records. A same-named constant bound to another value is a different
          guard, and nothing is derived from it.

        Every refusal is recorded, because a candidate produced by a guard whose
        value did not line up must not read as a candidate produced by no guard.
        """
        for caller_side, other in ((left, right), (right, left)):
            if caller_side.kind != "caller" or caller_side.subject != "uid":
                continue
            if other.kind != "constant":
                continue
            entry = self.account_roles.get(terminal(other.key))
            if entry is None:
                continue
            definition = (self.index.define_constant(entry.constant, fn.file)
                          if self.index is not None else None)
            if definition is None:
                self.account_notes.add(
                    "Caller-UID guard in " + fn.qualified + " at "
                    + self._where(fn.file, fn, node) + " compares the calling UID with "
                    + entry.constant + ", which the scanned sources do not resolve to a single "
                    "literal definition; the reviewed account role " + entry.role + " was not "
                    "derived, so the call this guard protects stays a candidate. Account model: "
                    + entry.uid + " (" + entry.origin + ").")
                return None
            if definition.value != entry.uid:
                self.account_notes.add(
                    "Caller-UID guard in " + fn.qualified + " at "
                    + self._where(fn.file, fn, node) + " compares the calling UID with "
                    + entry.constant + ", which the scanned sources bind to " + definition.value
                    + " at " + definition.file + ":" + str(definition.line) + " ("
                    + definition.symbol + ", \"" + definition.text + "\"). The reviewed account "
                    "role " + entry.role + " is defined for " + entry.uid + ", so it was not "
                    "derived here and the call this guard protects stays a candidate.")
                return None
            note = ("Service-account role credited: caller-UID guard in " + fn.qualified + " at "
                    + self._where(fn.file, fn, node) + " compares the calling UID with "
                    + entry.constant + ", which the scanned sources bind to " + definition.value
                    + " at " + definition.file + ":" + str(definition.line) + " ("
                    + definition.symbol + ", \"" + definition.text + "\").")
            note += (" The role " + entry.role + " is accepted for "
                    + ", ".join(entry.accepted_operations) + " and for nothing else; target "
                    + self._target() + "; policy origin: " + entry.origin + ".")
            self.account_notes.add(note)
            return entry.role
        # A reviewed account constant compared with something that is not the
        # calling UID: recorded, because "the guard the model describes is written
        # here and answers about something else" is exactly what has to be
        # reviewed. Silence would read as though no such guard existed.
        for side, other in ((left, right), (right, left)):
            entry = (self.account_roles.get(terminal(side.key))
                     if side.kind == "constant" else None)
            if entry is None:
                continue
            if other.kind == "caller" and other.subject in ("token", "full_token"):
                because = "a caller TokenID, which is a different identity domain from a UID"
            elif other.kind == "request":
                because = "a request-derived value, which is not the caller"
            elif other.kind == "self":
                because = "the service's own identity, not the caller's"
            else:
                because = "a value this analysis does not establish as the caller's identity"
            self.account_notes.add(
                "Reviewed account constant " + entry.constant + " is compared in "
                + fn.qualified + " at " + self._where(fn.file, fn, node) + " against "
                + because + "; no caller-identity fact was derived, so the call this "
                "comparison guards stays a candidate.")
            return None
        return None

    def _target(self):
        if self.request is None:
            return "unstated scan target"
        return self.request.repository + "@" + self.request.commit

    def note_shadowed_role_predicate(self, helper):
        """Record that a reviewed caller-role name was read from the file's own body.

        A reviewed caller-role name is credited only where the scanned sources do
        not define the name: a locally written function of that name is a different
        function, and it is interpreted from its body instead. That is the point of
        the rule -- a file may write a function called `IsSACalling` that answers
        something else entirely, and inheriting the reviewed meaning of the name
        would credit a guard the body never made. When the body then answers with a
        UID no reviewed fact covers -- `GetCallingUid() == ACCESSTOKEN_UID`, on a
        constant this policy carries no role for -- the call sites keep their
        candidates. Which body took the name's place is written down, so that a
        candidate is read against the body that has to be reviewed rather than as a
        guard that was never written. Whether the body did establish a reviewed fact
        is not claimed here: `helper_preproc_guard_fixed` defines two of these names
        itself and both bodies do carry one.
        """
        name = helper.name.split("::")[-1]
        if not any(role_name == name
                   for role_name, _kind, _label in self.policy.caller_role_guards):
            return
        # `Function.line` is filled in by the entry index's one-hop lookup and stays 0
        # for a frame read out of the sources directly, so the definition node is the
        # line of record here: a citation of `:0` tells a reviewer nothing.
        line = helper.line or (helper.node.start_point[0] + 1 if helper.node is not None
                               else 0)
        self.limitations.add(
            "Reviewed caller-role predicate " + name + " is also defined in the scanned "
            "sources at " + helper.file + ":" + str(line) + " (" + helper.qualified
            + "); a call to it was read from that body, and the reviewed name itself was "
            "not credited for it. Whether that body derives a fact is a separate question: "
            "a comparison it makes against a reviewed service account is recorded on its "
            "own account-model line when the source resolves it.")

    def action(self, fn, node, state, name, args, depth=0, guard=None,
               required_role=None):
        """Report the candidate a modelled call is, unless `guard` explains it.

        `guard` is what `dispatch_guard` read one class hop away, when this call is
        an unqualified virtual dispatch into an implementer in another translation
        unit. "No matched caller authorization on this path" is then the wrong
        statement: the operation runs in a body that does reject unauthorized
        callers, and the authorization call is simply not in this file. The
        remaining consequences of the call are still computed -- only the
        absent-authorization and capability-export candidates are withheld.
        """
        if self.root is None:
            return
        root_key = (self.root.file, self.root.qualified)
        sensitive = (name in self.policy.sensitive_calls
                     or name in self.policy.object_sensitive_calls
                     or required_role is not None)
        expected_contract = (self.expected_permission(fn.name, fn.qualified)
                             or self.expected_permission(self.root.name, self.root.qualified))
        if name in self.policy.boolean_permissions | self.policy.result_permissions and expected_contract:
            observed_permissions = {arg.key for arg in args
                                    if arg.kind == "constant" and arg.key}
            if observed_permissions and expected_contract not in observed_permissions:
                root_key = (self.root.file, self.root.qualified)
                self.permission_mismatch_roots.add(root_key)
                operation = fn.name if self.expected_permission(fn.name, fn.qualified) else self.root.name
                self.emit("AUTH-02", "ipc.auth.missing", fn, node, state,
                          "Service operation " + operation + " checks permission "
                          + ", ".join(sorted(observed_permissions)) + " but its reviewed "
                          "contract requires " + expected_contract + ".",
                          call=operation)
        if sensitive:
            for issue_fn,issue_node,issue_rule,issue_message in state.identity_issues:
                self.emit("AUTH-03",issue_rule,issue_fn,issue_node,state,issue_message,call=name)
        if required_role is not None and (guard is None or required_role not in guard[2]):
            self.emit("AUTH-03", "ipc.auth.caller-class", fn, node, state,
                      "Repository-reviewed operation " + name + " requires caller role "
                      + required_role + ", but no matching dominating role gate was established.",
                      call=name)
        expected_permission = self.expected_permission(name, fn.qualified)
        permission_mismatch = (expected_permission and state.auth
                               and expected_permission not in state.auth)
        if sensitive and permission_mismatch and guard is None:
            if (self.root.file, self.root.qualified) not in self.permission_mismatch_roots:
                observed = ", ".join(sorted(state.auth))
                self.emit("AUTH-02", "ipc.auth.missing", fn, node, state,
                          "Sensitive modeled call " + name + " has a permission mismatch: "
                          "reviewed contract requires " + expected_permission + ", but this "
                          "path checks " + observed + "."
                          + self.auth_note(state), call=name)
        elif (sensitive and required_role is None
              and not self.authorized(state, name, fn.qualified) and guard is None):
            if self.root_grade == "dispatch" and "dispatcher-guard-observed" in self.root_note:
                # A guard runs before dispatch, so this is a guard-coverage question
                # (does it dominate this transaction?), not an absent-authorization
                # one. Same path, same evidence, classified where the uncertainty is.
                self.emit("AUTH-04", "ipc.auth.guard-coverage", fn, node, state,
                          "Sensitive modeled call " + name + " has no matched caller authorization on "
                          "this path, but the dispatcher performs an authorization call before dispatch; "
                          "its dominance over this transaction is not established."
                          + self.auth_note(state), call=name)
            else:
                self.emit("AUTH-02", "ipc.auth.missing", fn, node, state,
                          "Sensitive modeled call " + name + " has a structured path without a recognized caller authorization."
                          + self.auth_note(state),
                          call=name)
        if sensitive and state.reset and state.identity_discarded and state.auth:
            # A guard established before the identity change authorizes the
            # original caller; after `ResetCallingIdentity` the operation runs as
            # the service. The pair is the finding: each half is fine alone, and
            # together they mean the guard did not dominate the principal the
            # effect is attributed to.
            self.emit("AUTH-05", "ipc.auth.flow", fn, node, state,
                      "Caller identity was reset and the returned identity discarded before "
                      + name + "; the path retains a guard computed for the original caller, "
                        "while the operation runs as the service and nothing on this path can "
                        "restore the caller.", call=name)
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
            # An object the reply carries is only an unguarded export if the code
            # that produced it was unguarded. When the value written came back from
            # a one-hop dispatch whose implementer rejects unauthorized callers,
            # the capability was never handed to a caller this boundary fails to
            # check; treating the write as the export would put the finding one
            # frame too late.
            exported = args[0] if args else UNKNOWN
            from_guarded_dispatch = exported.kind == "call_result" and exported.subject == "guarded"
            if args and args[0].key not in ("nullptr", "NULL", "0") and not from_guarded_dispatch:
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

    def descriptor_symbol_expectation(self, fn, symbol):
        """Resolve a source-defined descriptor string against the stated stub interface.

        Some stubs compare a parcel token with Str8ToStr16(DESCRIPTOR) rather
        than calling GetDescriptor(). The symbol spelling alone is not enough:
        only accept a unique class-owned string definition and compare its literal
        with the interface literal declared in the source. A mismatch remains a
        candidate; an absent or ambiguous binding stays unresolved.
        """
        interfaces = (self.index.implemented_interfaces(fn.owner)
                      if self.index is not None and fn.owner else ())
        if len(interfaces) != 1:
            return Value("descriptor_expected", symbol, subject="unresolved",
                         terms=(symbol, "the class's implemented interface is not unique in the analysed sources"))

        owner = terminal(fn.owner)
        actual_pattern = re.compile(
            r"\b(?:const\s+)?(?:std::)?string\s+" + re.escape(owner)
            + r"\s*::\s*" + re.escape(symbol)
            + r"\s*(?:\(\s*(?:u8|u|U|L)?\"((?:[^\"\\]|\\.)*)\"\s*\)|"
              r"=\s*(?:u8|u|U|L)?\"((?:[^\"\\]|\\.)*)\")\s*;"
        )
        actuals = []
        for unit in self.units:
            for match in actual_pattern.finditer(unit.text):
                literal = match.group(1) if match.group(1) is not None else match.group(2)
                # Escapes need C++ literal decoding. Refuse them rather than
                # comparing their source spelling as though it were the value.
                if "\\" in literal:
                    continue
                line = unit.text.count("\n", 0, match.start()) + 1
                actuals.append((literal, unit.path, line))
        if len(actuals) != 1:
            return Value("descriptor_expected", symbol, subject="unresolved",
                         terms=(symbol, "the class-owned " + symbol + " string definition is absent or ambiguous"))

        interface = interfaces[0]
        interface_pattern = re.compile(
            r"\b(?:class|struct)\s+" + re.escape(interface.name)
            + r"\b[^{};]*\{([\s\S]*?)\}\s*;"
        )
        declared = []
        macro = re.compile(
            r"\bDECLARE_INTERFACE_DESCRIPTOR\s*\(\s*(?:u8|u|U|L)?\"([^\"\\]*)\"\s*\)"
        )
        for unit in self.units:
            for class_match in interface_pattern.finditer(unit.text):
                body_start = class_match.start(1)
                for value_match in macro.finditer(class_match.group(1)):
                    line = unit.text.count("\n", 0, body_start + value_match.start()) + 1
                    declared.append((value_match.group(1), unit.path, line))
        if len(declared) != 1:
            return Value("descriptor_expected", interface.name, subject="unresolved",
                         terms=(interface.name, interface.name + " descriptor declaration is absent or ambiguous"))

        actual, actual_file, actual_line = actuals[0]
        expected, expected_file, expected_line = declared[0]
        subject = "interface" if actual == expected else "mismatch"
        terms = (
            symbol + " is " + repr(actual) + " at " + actual_file + ":" + str(actual_line),
            interface.name + " declares " + repr(expected) + " at " + expected_file + ":" + str(expected_line),
        )
        return Value("descriptor_expected", interface.name, subject=subject, terms=terms)

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

    def auth_note(self, state):
        """The caller-identity comparison seen on this path that was not credited.

        A missing-authorization message must not be read as "no guard was
        written". When the walk saw the caller's identity compared against a
        symbol, the guard is real; the candidate stays, and the message says
        which of the two facts is missing:

        * the symbol has no value in the scanned sources (`auth_unknown`), or
        * it has one and no reviewed account assignment credits that value
          (`auth_uncredited`).

        Reporting the second as the first would be a checkable false statement
        about the source, and the reviewer would go looking for a definition that
        is already there.
        """
        if not state.auth_issues:
            return ""
        unresolved, uncredited = [], []
        for issue in state.auth_issues:
            if isinstance(issue, tuple):
                symbol, value, file, line = issue
                where = (file + ":" + str(line)) if file else "an unstated location"
                uncredited.append(symbol + " (which these sources bind to " + value
                                 + " at " + where + ")")
            else:
                unresolved.append(issue)
        parts = []
        if unresolved:
            parts.append("the caller identity is compared against "
                         + ", ".join(sorted(unresolved))
                         + " on this path, but this analysis does not resolve that symbol "
                           "to a value")
        if uncredited:
            parts.append("the caller identity is compared against "
                         + ", ".join(sorted(uncredited))
                         + ", but no reviewed account assignment in this policy credits "
                           "that value")
        return (" Guard seen, not accepted: " + "; ".join(parts)
                + ", so the comparison cannot be credited as authorization.")

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
            for view, why in state.invalidated_views:
                if view == text:
                    self.emit("DATA-03", "ipc.parcel.lifecycle", fn, node, state,
                              "Parcel-backed view " + text + " is read after " + why
                              + " released or rewound the parcel it points into; on this "
                                "path the view has no live owner.")
                    break
            return state.env.get(text, Value("constant", text))
        if node.type in ("number_literal", "true", "false", "null", "nullptr", "string_literal", "concatenated_string"):
            return Value("constant", text)
        if node.type == "call_expression":
            callee = fn.text(node.child_by_field_name("function"));name = terminal(callee)
            an = node.child_by_field_name("arguments")
            args = [self.value(fn, a, state, depth) for a in an.named_children] if an else []
            receiver = re.split(r"->|\.", callee)[0] if re.search(r"->|\.", callee) else ""
            if callee.strip().startswith("iface_cast") and "<" in callee:
                # `iface_cast<IFoo>(remote)` is the canonical way a client in
                # these sources obtains a typed proxy. The handle names another
                # process, so a later call through it leaves this one even when
                # the callee's body is not in the scanned tree.
                return Value("proxy", text)
            if receiver:
                held = state.env.get(receiver)
                if held is not None and held.kind == "proxy":
                    self.boundary(fn, node, name, state)
            if name in self.policy.caller_token_calls | self.policy.caller_uid_calls:
                subject = ("uid" if name in self.policy.caller_uid_calls else
                           "full_token" if name == "GetCallingFullTokenID" else "token")
                return Value("self" if state.reset else "caller", text, subject)
            if name in self.policy.self_calls:
                return Value("self", text, "uid" if name in ("getuid","geteuid") else "token")
            if name == "ResetCallingIdentity":
                state.reset = True
                state.forwarded = False
                return Value("saved_identity", text)
            if name == "SetCallingIdentity":
                # Restoration cannot establish the original caller unless the
                # corresponding identity token's provenance is available.
                state.reset = not (args and args[0].kind == "saved_identity")
                # Only a token read as the calling token is the original caller.
                # The service's own saved identity is a different principal.
                state.forwarded = bool(args and args[0].kind == "caller"
                                       and args[0].subject in ("token", "full_token"))
                return UNKNOWN
            if name == "ReadInterfaceToken":
                rv = state.env.get(receiver, UNKNOWN)
                return Value("descriptor_read", rv.key) if rv.kind == "parcel" else UNKNOWN
            if name == "GetDescriptor":
                return self.descriptor_expectation(fn, callee, state)
            if (name == "Str8ToStr16" and len(args) == 1
                    and args[0] == Value("constant", "DESCRIPTOR")
                    and "DESCRIPTOR" not in state.env):
                return self.descriptor_symbol_expectation(fn, "DESCRIPTOR")
            if name == "compare" and receiver:
                # `ReadInterfaceToken()` is commonly copied into a local
                # std::u16string and checked with compare() instead of ==/!=.
                # Preserve the descriptor provenance through that exact
                # one-argument string comparison; the result is not itself a
                # guard until the caller compares it with zero below.
                compared = state.env.get(receiver, UNKNOWN)
                if (compared.kind == "descriptor_read" and len(args) == 1
                        and args[0].kind == "descriptor_expected"):
                    return Value("descriptor_compare", compared.key,
                                 terms=(args[0],))
            if name == "AsObject" and receiver and not args:
                # `sptr<T>::AsObject()` hands back the IRemoteObject that smart
                # pointer already holds -- the same object, not a new one. A reply
                # that writes `x->AsObject()` therefore exports whatever `x` was,
                # and reading the accessor as an unknown is what hid that relation
                # from the capability-export check.
                #
                # Only a `call_result` is passed through. Any other value is left to
                # the ordinary path: a receiver holding a null literal would
                # otherwise be handed back as the written argument, and "nullptr" is
                # the sentinel that check uses for "nothing is being exported", so
                # the export would be argued away by a value that in fact proves the
                # opposite.
                held = state.env.get(receiver)
                if held is not None and held.kind == "call_result":
                    return held
            if name in ("GetTokenTypeFlag", "GetTokenType") and args and args[0].kind=="caller" and args[0].subject=="token":
                return Value("caller_type",args[0].key)
            if (callee == "TokenIdKit::IsSystemAppByFullTokenID" and len(args) == 1
                    and args[0].kind == "caller" and args[0].subject == "full_token"):
                return Value("predicate", predicate=("caller_class", "system_app", True))
            if name=="GetNativeTokenInfo" and len(args)>1 and args[0].kind=="caller" and args[0].subject=="token":
                state.env[args[1].key]=Value("caller_info",args[1].key)
            if name=="compare" and args:
                receiver_node=node.child_by_field_name("function")
                receiver_arg=receiver_node.child_by_field_name("argument") if receiver_node else None
                rv=self.value(fn,receiver_arg,state,depth)
                if rv.kind=="caller_process" and args[0].key=='"hdcd"':
                    return Value("permission_result",text,"caller","<caller-native-process:hdcd>")
            if name=="GetDataSize" and state.env.get(receiver,UNKNOWN).kind=="parcel":
                return Value("parcel_size",re.sub(r"\s+","",text))
            if name=="RewindRead" and args:
                self.check_subtractions(fn,node,state,args[0])
            if name in self.policy.owner_calls:
                return Value("owner", args[0].key if args else receiver)
            if name in self.policy.parcel_view_calls:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    # A view, not a copy: the parcel keeps ownership of the bytes.
                    return Value("parcel_view", text, receiver)
            if name in self.policy.parcel_dest_reads and len(args) >= 2:
                self.parcel_destination_bound(fn, node, state, name, args)
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    return Value("request", text, "signed")
            if name in self.policy.parcel_invalidating_calls:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    self.invalidate_views(state, receiver, name)
            if name in self.policy.parcel_reads:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    return Value("request", text, "unsigned" if name.startswith("ReadU") else "signed")
            if callee.lstrip().startswith("(this->*") and self.root.name in self.policy.entry_names and not state.descriptor:
                self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                          "Unresolved member-pointer IPC dispatch lacks interface-descriptor validation; callee remains unknown.")
            helper = self.resolve(fn, callee)
            if helper is None:
                helper = self.delegated(fn, callee)
            if helper is not None:
                self.note_shadowed_role_predicate(helper)
            implementation = guard = None
            if helper is None:
                implementation, guard, required_role = self.one_hop_dispatch(
                    fn, node, callee, name, args, state)
                if implementation is None:
                    # Reviewed caller-role predicates, by exact name, and only for a
                    # call this file does not itself define: a local function of the
                    # same name is interpreted above, never assumed to be the
                    # framework's. Each answers whether the caller holds a privileged
                    # role and none takes a permission, so the fact it yields is a
                    # caller class, not a permission -- `IsPrivilegedCalling` and
                    # `IsAccessTokenCalling` are the two that answer with the
                    # service-role authorization fact their helper summaries derive.
                    local = self.functions_by_file_name.get((fn.file, name), [])
                    role = next(((kind, label) for role_name, kind, label
                                 in self.policy.caller_role_guards if role_name == name), None)
                    if role is not None and local:
                        definitions = ", ".join(f.file + ":" + str(f.line or f.node.start_point[0] + 1)
                                                for f in local)
                        self.limitations.add("Local caller-role definition is unresolved: " + name
                                             + " at " + definitions
                                             + "; reviewed-name credit refused; caller authorization remains unknown.")
                    elif role is not None and not args:
                        return Value("predicate", predicate=(role[0], role[1], True))
            self.action(fn, node, state, name, args, depth, guard=guard,
                        required_role=required_role if implementation is not None else None)
            if name in self.policy.reply_write_calls:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "reply_parcel":
                    self.reply_flow(fn, node, state, name, args)
            if helper and self.root.name in self.policy.entry_names and not state.descriptor:
                with self.lookahead():
                    relay = self.relay_guard(fn, node, args, helper, state, depth)
                if relay is None:
                    # Say where the handler was resolved. A qualified callee can
                    # resolve into another translation unit, and calling that
                    # "locally resolved" would be a claim the reviewer can check.
                    where = helper.qualified if helper.file == fn.file else (
                        helper.qualified + " in " + helper.file)
                    self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                        "IPC entry reaches a handler resolved in the scanned sources without interface-descriptor validation: "+where)
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
                returned = [s for s in ends if s.flow == "return"]
                # A helper is summarized only when all its paths agree. A
                # conditional boolean return gets its guards bound to truth.
                values = {s.returned for s in returned}
                if len(values) == 1 and len(returned) == len(ends):
                    return returned[0].returned
                # Otherwise the helper decides a boolean, and what the caller needs
                # is what returning true implies. Two things imply a fact: a guard
                # bound on the way to that return, and the returned expression
                # itself when it is a comparison -- `return uid == ROOT_UID;` is
                # true exactly where that fact holds. Reading only the first left a
                # local predicate such as `IsRootCalling()` as UNKNOWN, so the
                # caller's `if (!IsRootCalling() && !IsNativeProcessCalling())
                # return;` still looked unguarded on that disjunct.
                good = [s for s in returned if _returns_true(s.returned)]
                bad = [s for s in returned if s.returned.key in ("false", "0")]
                if good and bad and len(good)+len(bad) == len(ends):
                    common = frozenset.intersection(
                        *(s.auth | _returned_fact(s.returned) for s in good)) - state.auth
                    if common:
                        return Value("predicate", predicate=("auth", sorted(common)[0], True))
                    common_class = frozenset.intersection(
                        *(s.caller_class | _returned_caller_class(s.returned) for s in good)) - state.caller_class
                    if common_class:
                        return Value("predicate", predicate=("caller_class", sorted(common_class)[0], True))
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
            if name in DISCLOSURE_CALLS:
                # A disclosure-class call's product is the sensitive value. The
                # value is only a candidate *source*: whether it reaches a caller
                # is decided by what the path does with it, not by the call.
                return Value("sensitive_result_guarded" if guard is not None else "sensitive_result", text, name)
            return Value("unknown", text)
        if node.type == "binary_expression":
            left = self.value(fn,node.child_by_field_name("left"),state,depth)
            right = self.value(fn,node.child_by_field_name("right"),state,depth)
            op = fn.text(node.child_by_field_name("operator"))
            if op in ("==", "!=", "<", "<=", ">", ">="):
                compared = left if left.kind == "descriptor_compare" else (
                    right if right.kind == "descriptor_compare" else None)
                zero = right if left.kind == "descriptor_compare" else left
                if (compared is not None and zero.kind == "constant"
                        and zero.key == "0" and op in ("==", "!=")):
                    expected = compared.terms[0] if compared.terms else UNKNOWN
                    return Value("predicate", predicate=(
                        "descriptor", compared.key, op == "==", expected))
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
                if op in ("==","!="):
                    # A reviewed account, resolved from the source rather than from
                    # the name: only the value the scanned definitions bind the
                    # constant to decides whether this is the guard the model means.
                    account = self.account_role(fn, node, left, right, op)
                    if account:
                        return Value("predicate",predicate=("account",account,op=="=="))
                if op in ("==","!="):
                    # A caller-identity comparison whose other side the scan does
                    # not bind to a value. Checked after the reviewed account, so
                    # a comparison the account model can resolve is not demoted to
                    # "unknown". The comparison exists, so the guard is not absent;
                    # the value is unknown, so the guard cannot be credited.
                    # Recorded rather than silently yielded, because "the helper
                    # has no guard" and "the helper compares against a constant
                    # this scan never saw" are different facts.
                    caller_side = (left.kind == "caller"
                                   and right.kind == "constant" and right.key.isidentifier())
                    symbol = right.key if caller_side else (
                        left.key if right.kind == "caller"
                        and left.kind == "constant" and left.key.isidentifier() else None)
                    if symbol:
                        # Whether the symbol has a value and whether that value is
                        # credited are two different facts, and the message has to
                        # say which one is missing. A resolved constant that no
                        # reviewed account assignment covers is not "unresolved";
                        # calling it that would be a statement about the source
                        # that the scan can check and would find false.
                        definition = (self.index.define_constant(symbol, fn.file)
                                      if self.index is not None else None)
                        if definition is not None:
                            return Value("predicate",predicate=(
                                "auth_uncredited",
                                (symbol, definition.value, definition.file,
                                 definition.line), op=="=="))
                        return Value("predicate",predicate=("auth_unknown",symbol,op=="=="))
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
            left_node=node.child_by_field_name("left")
            if left_node is not None and left_node.type == "subscript_expression":
                # The write side indexes the destination just as the read side
                # does; reading only the right-hand side left an index taken
                # from the parcel unexamined whenever it was used to store.
                self.value(fn,left_node,state,depth)
            left=fn.text(left_node)
            value=self.value(fn,node.child_by_field_name("right"),state,depth)
            self.assign(state,left,value)
            return state.env[left]
        if node.type == "subscript_expression":
            base_node = node.child_by_field_name("argument")
            base = self.value(fn, base_node, state, depth)
            indices = node.child_by_field_name("indices")
            if indices is not None:
                for sub in indices.named_children:
                    index = self.value(fn, sub, state, depth)
                    self.parcel_index_bound(fn, node, state, fn.text(base_node), index)
            return UNKNOWN
        if node.type == "subscript_argument_list":
            for sub in node.named_children:self.value(fn,sub,state,depth)
            return UNKNOWN
        # Visit nested calls without treating comments or strings as executable.
        for child in node.named_children:self.value(fn,child,state,depth)
        return Value("unknown",text)

    def parcel_index_bound(self, fn, node, state, base, index):
        """An index read out of the request parcel, used to select from a buffer.

        The criterion is the same one the copy rule uses: the bound has to name
        the same destination. A bound checked against another array, or against
        the parcel's size rather than the selected buffer, does not establish that
        this selection stays inside it. The capacity has to be stated by a
        declaration in the analysed function; a pointer argument has no capacity
        in the source, so the question is left open rather than guessed.
        """
        if index.kind != "request" or not index.key:
            return
        name = terminal(base)
        capacity = self.capacities.get(name)
        if capacity is None:
            return
        upper = any(key == index.key and bound in (capacity, "sizeof(" + name + ")")
                    for key, bound in state.upper)
        nonnegative = index.subject != "signed" or index.key in state.lower
        if upper and nonnegative:
            return
        missing = []
        if not upper:
            missing.append("an upper bound against " + name + "'s declared capacity " + capacity)
        if not nonnegative:
            missing.append("a non-negative check")
        self.emit("DATA-02", "ipc.parcel.bounds", fn, node, state,
                  "Parcel-derived index " + index.key + " selects from " + name
                  + " with no matched " + " or ".join(missing) + ".")

    def parcel_destination_bound(self, fn, node, state, name, args):
        """`ReadRawData(destination, size)` with `size` taken out of the request.

        The length is argument 1 of that API, not the memcpy position. It is
        reported only when the destination's capacity is stated by a declaration
        here: a caller-supplied pointer carries no capacity the source states, and
        the parcel's own remaining size is not a capacity of the destination.
        """
        destination, length = args[0], args[1]
        if length.kind != "request" or not length.key:
            return
        target = terminal(destination.key)
        capacity = self.capacities.get(target)
        if capacity is None:
            return
        upper = any(key == length.key and bound in (capacity, "sizeof(" + target + ")")
                    for key, bound in state.upper)
        nonnegative = length.subject != "signed" or length.key in state.lower
        if upper and nonnegative:
            return
        missing = []
        if not upper:
            missing.append("an upper bound against " + target + "'s declared capacity " + capacity)
        if not nonnegative:
            missing.append("a non-negative check")
        self.emit("DATA-02", "ipc.parcel.write-bounds", fn, node, state,
                  "Parcel-derived length " + length.key + " is passed to " + name
                  + " writing into " + target + " with no matched " + " or ".join(missing) + ".")

    def invalidate_views(self, state, receiver, call):
        """Mark parcel-backed views of `receiver` as no longer owned.

        `Reuse`, `RewindRead`, `SetReadPosition` and `Seek` release or move the
        parcel's buffer; a pointer `ReadBuffer` handed out points into that buffer.
        Only views whose producing receiver is exactly this parcel are marked: a
        view from another parcel is a different owner.
        """
        marked = []
        for view in sorted(state.parcel_views):
            held = state.env.get(view)
            if held is None or held.kind != "parcel_view" or held.subject != receiver:
                continue
            marked.append((view, call + "()"))
        if marked:
            state.invalidated_views = tuple(dict.fromkeys(
                state.invalidated_views + tuple(marked)))

    def reply_flow(self, fn, node, state, name, args):
        """A modelled sensitive result written into the reply parcel.

        The reply is the caller-visible output of the transaction. A value a
        disclosure-class call produced, written here on a path with no matched
        caller authorization, is a data-flow candidate: the mechanism is the
        missing guard on a path whose product is handed back, not the read alone.
        """
        for value in args:
            if value.kind == "sensitive_result_guarded":
                continue
            if value.kind != "sensitive_result":
                continue
            source = value.subject
            if self.authorized(state, source):
                continue
            self.emit("DATA-04", "ipc.data.sensitive-flow", fn, node, state,
                      "Result of " + source + " is written into the reply parcel by "
                      + name + " on a path without a matched caller authorization."
                      + self.auth_note(state))
            return

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
            if old.kind=="parcel_view" and value.kind!="parcel_view":
                state.parcel_views=state.parcel_views-{name}
        # A fresh value is not the invalidated view it replaced.
        state.invalidated_views=tuple(item for item in state.invalidated_views if item[0]!=name)
        if value.kind=="request":
            value=replace(value,key=name)
            if value.subject=="unsigned":state.lower=state.lower|{name}
        if value.kind=="saved_identity":
            # The returned identity now has a holder, so it can be restored.
            state.identity_discarded=False
        if value.kind=="parcel_view" and name.isidentifier():
            value=replace(value,key=name)
            state.parcel_views=state.parcel_views|{name}
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
            if kind in ("auth_unknown","auth_uncredited"):
                # The comparison was seen and is not a fact on this path. The two
                # kinds are kept apart in the record: `auth_unknown` means the
                # scanned sources do not bind the symbol to a value, and
                # `auth_uncredited` means they do bind it and the policy still has
                # no reviewed account assignment for that value. The candidate
                # message is built from these, so it cannot claim the wrong one.
                accepted=False
                if key not in out.auth_issues:
                    out.auth_issues=out.auth_issues+(key,)
            if truth==when and accepted:
                attr={"auth":"auth","descriptor":"descriptor","owner":"owner","lower":"lower","upper":"upper","size_lower":"size_lower","caller_class":"caller_class","account":"service_account"}[kind]
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
        if kind in ("preproc_if", "preproc_ifdef"):
            # A conditional inside a body is a build-time fork this analysis cannot
            # resolve, so every arm is explored as an alternative instead of one arm
            # being assumed. Facts proved before the conditional survive into each
            # arm -- they hold in every build -- while a guard written inside an arm
            # is credited only on that arm's paths. A chain with no `#else` keeps its
            # no-arm-taken path, so the fall-through that exists when the condition
            # is false is not lost along with the arm it guards.
            arms = _preproc_arms(node, fn.text)
            self.limitations.add(
                "Preprocessor conditional inside a function body: arms are explored as alternatives "
                "because the build variant is unknown. A guard written inside an arm is credited only "
                "on that arm's paths, the no-arm-taken path is kept when the chain has no #else, and "
                "facts proved before the conditional still hold in every arm.")
            result = []
            for s in active:
                for condition, statements in arms:
                    arm = [s.fork(trace=s.trace + ((node.start_point[0] + 1,
                                                    "preproc " + (condition or "#if")),))]
                    for item in statements:
                        arm = self.statement(fn, item, arm, depth)
                    result.extend(arm)
                if not _preproc_closed(node):
                    result.extend([s.fork(trace=s.trace + ((node.start_point[0] + 1,
                                                            "preproc no arm taken"),))])
            return self.bounded(done + result)
        if kind in ("goto_statement","try_statement"):
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
                    macro_guard = self._fail_fast_macro_predicate(fn, expr, s, depth)
                    if macro_guard is not None:
                        # The definition is source-bound and proves that a false
                        # condition returns from this function. Only the normal
                        # continuation receives the predicate's true facts.
                        guarded = self.refine(fn, macro_guard, s, True, depth)
                        for continuation in guarded:
                            continuation.trace = (continuation.trace +
                                ((expr.start_point[0] + 1,
                                  "source-verified fail-fast macro => true"),))[-20:]
                        if guarded:
                            safe = guarded[0]
                            s.auth = safe.auth
                            s.descriptor = safe.descriptor
                            s.owner = safe.owner
                            s.lower = safe.lower
                            s.upper = safe.upper
                            s.size_lower = safe.size_lower
                            s.caller_class = safe.caller_class
                            s.service_account = safe.service_account
                            s.trace = safe.trace
                        else:
                            s.flow = "return"
                        continue
                    if (expr.type=="call_expression" and terminal(fn.text(expr.child_by_field_name("function")))
                            == "ResetCallingIdentity"):
                        # The call stands alone, so its returned identity has no
                        # holder. `ResetCallingIdentity()` used this way cannot be
                        # undone, and a guarded operation after it is attributed to
                        # a principal the guard never checked.
                        s.identity_discarded=True
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

    def _fail_fast_macro_predicate(self, fn, expr, state, depth):
        """Recognize only source-proven `if (!arg) return` macro wrappers.

        Some OpenHarmony fail-fast macros stringify their condition for logging,
        so the bounded expander refuses them. For descriptor guards, model the
        normal continuation only when the scan contains one unconditional macro
        definition with the narrow two-parameter shape checked below. The macro
        name alone never grants a guard.
        """
        if expr.type != "call_expression":
            return None
        name_node = expr.child_by_field_name("function")
        name = terminal(fn.text(name_node)) if name_node is not None else ""
        definitions = self.macro_catalog.get(name, ()) if self.macro_catalog else ()
        if not definitions:
            return None
        signatures = {(item.get("body", ""), tuple(item.get("parameters") or ()),
                       tuple(item.get("conditional_context") or ())) for item in definitions}
        if len(signatures) != 1:
            return None
        body, params, conditions = next(iter(signatures))
        if conditions or len(params) != 2:
            return None
        cond_param, return_param = params
        pattern = (r"^do\s*\{\s*bool\s+([A-Za-z_]\w*)\s*=\s*\(\s*"
                   + re.escape(cond_param) + r"\s*\)\s*;\s*if\s*\(\s*!\s*\1\s*\)\s*\{"
                   + r".*?\breturn\s+" + re.escape(return_param)
                   + r"\s*;.*?\}\s*\}\s*while\s*\(\s*0\s*\)$")
        if not re.match(pattern, body):
            return None
        arguments = expr.child_by_field_name("arguments")
        args = list(arguments.named_children) if arguments is not None else []
        if len(args) != 2:
            return None
        predicate = self.value(fn, args[0], state, depth)
        if predicate.kind != "predicate" or predicate.predicate[:1] != ("descriptor",):
            return None
        return args[0]

    def _entry_roots(self):
        """Build roots from source-confirmed IPC dispatchers and explicit service entries.

        A method name plus one Parcel parameter is insufficient: fuzz wrappers and
        test helpers commonly use the same names without implementing the IPC
        dispatch signature. IPC roots therefore require a class method admitted by
        EntryIndex's code/Parcel/Parcel signature check. Service and transport
        roots remain explicit policy entries. Handler roots still require a unique
        source-derived dispatch binding below.
        """
        roots, seen = [], set()
        dispatcher_keys = ({(item.file, item.name, item.line)
                            for item in self.index.dispatchers if item.owner}
                           if self.index is not None else set())
        for fn in self.functions:
            is_ipc_dispatcher = (fn.name in self.policy.entry_names
                                 and fn.owner and fn.parcel_params and fn.reply_params and len(fn.params) >= 3
                                 and (fn.file, fn.name, fn.line) in dispatcher_keys)
            is_inner_helper = (fn.name.endswith("Inner") and "Stub" in fn.owner and fn.parcel_params)
            is_explicit_entry = (fn.name in self.policy.transport_entries and fn.parcel_params)
            is_service_entry = fn.qualified in self.policy.service_entries
            if not (is_ipc_dispatcher or is_inner_helper or is_explicit_entry or is_service_entry):
                continue
            if _test_only_source(fn.file):
                self.test_only_roots_skipped.add((fn.file, fn.qualified))
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
            if _test_only_source(fn.file):
                self.test_only_roots_skipped.add((fn.file, fn.qualified))
                continue
            if (fn.file, fn.qualified) in seen:
                continue
            seen.add((fn.file, fn.qualified))
            roots.append((fn, "dispatch", self.index.dispatch_note(owner, name)))
        return roots

    def run(self):
        for fn, grade, note in self._entry_roots():
            self.root=fn;self.root_grade=grade;self.root_note=note
            self.capacities={};self.active=(fn,)
            env={p:(Value("parcel",p) if p in fn.parcel_params else
                    Value("reply_parcel",p) if p in fn.reply_params else Value("request",p))
                 for p in fn.params}
            self.block(fn,fn.body,[State(env=env)],0)
        revised=[]
        for obs in self.observations:
            if obs.rule=="ipc.auth.missing":
                # Permission call somewhere is not coverage. Keep the primary
                # finding and add the explicit coverage subtype for these roots.
                if (obs.root_key in self.seen_permissions
                        and "checks permission " not in obs.message):
                    revised.append(replace(obs,family="AUTH-04",rule="ipc.auth.guard-coverage",
                        message="Authorization checks exist in the analyzed entry set, but this modeled sensitive path has no matched caller guard. "+obs.message))
            revised.append(obs)
        summary=self._macro_summary()
        if summary is not None:
            self.limitations.add(summary)
        if self.test_only_roots_skipped:
            self.limitations.add("Excluded " + str(len(self.test_only_roots_skipped))
                                 + " test/fuzz/mock entry root(s) from product candidate analysis; the source paths are retained in scope, but test-target findings are not mixed into product candidates.")
        if self.index is not None:
            # A refused hop is the whole reason a one-hop call site keeps its
            # candidate, and the reason is recorded on the index rather than in
            # this walk. Only the hop refusals are pulled through, so the reader
            # can tell "the implementer does not guard" from "the implementer was
            # never established"; the index's other limitations stay where they
            # were written.
            for refusal in sorted(self.index.limitations):
                if refusal.startswith("One-hop callee is not unique"):
                    self.limitations.add(refusal
                                         + " The call site therefore stays a candidate.")
            # The explicit coverage record for entry discovery: what was bound,
            # at which grade, and what was refused. Emitted even when there are
            # no findings, because "no dispatcher was found" and "dispatchers
            # were found but no handler bound" are different coverage statements
            # that a candidate count cannot distinguish.
            coverage = self.index.dispatch_coverage()
            self.limitations.add(
                "Entry/dispatch coverage: " + str(coverage["dispatchers"]) + " dispatcher(s) ("
                + str(coverage["dispatchers_in_stub"]) + " in stub classes, "
                + str(coverage["dispatchers_guarded_before_dispatch"])
                + " with a recognizable guard before dispatch), " + str(coverage["bindings"])
                + " binding(s) by grade " + repr(coverage["by_grade"]) + ", transactions "
                + repr(coverage["transaction_resolution"]) + ", unresolved dispatch "
                + repr(coverage["unresolved_dispatch"]) + ", "
                + str(coverage["conditional_bindings"])
                + " binding(s) under a preprocessor condition. A binding is not "
                  "reachability; a refused binding is unknown, not safe.")
        if self.account_notes:
            # One provenance line per service-account comparison, then one line
            # saying what the model does and does not cover. The refusals are
            # listed next to the credits: a guard whose value did not line up is
            # the reason its call site is still a candidate, and that reason has to
            # be readable somewhere.
            self.limitations.update(self.account_notes)
            self.limitations.add(
                "Service-account model: " + str(len(self.policy.service_account_roles))
                + " reviewed account role(s) are applied, each credited only where the "
                "calling UID is compared with the constant the record names *and* the "
                "scanned definitions bind that constant to the recorded value, and each "
                "accepted only for the operations the record lists. The role is not a "
                "permission and not a general caller role: it satisfies no capability, "
                "relay or cross-TU dispatch question, and a guard written against a "
                "same-named constant bound to another value (or against a TokenID, or "
                "against a request-derived value) derives nothing.")
        # Always emitted, so "no cross-service call was reached" and "the walk
        # never looked for one" are distinguishable in the report.
        carried = sum(1 for note in self.proxy_notes if note[2] == "caller")
        self.limitations.add(
            "Cross-service boundary coverage: " + str(len(self.proxy_notes))
            + " call(s) on a handle built by iface_cast<> in the scanned sources, "
            + str(carried) + " carrying the original caller's identity "
              "(SetCallingIdentity with a calling-token value active), "
            + str(len(self.proxy_notes) - carried)
            + " executing as the service. Each boundary is recorded with the identity "
              "that crossed it; no candidate is emitted from the boundary itself, and "
              "a downstream service's own guards are not read from this corpus.")
        if self.hop_notes:
            # One provenance line per credited hop, then one line saying what the
            # credit does and does not cover, so the difference between "the callee
            # guards" and "the callee was read" stays visible.
            self.limitations.update(self.hop_notes)
            self.limitations.add(
                "Cross-TU one-hop dispatch: " + str(len(self.hop_notes)) + " implementer "
                "guard(s) were read one class hop from an unqualified virtual dispatch and "
                "their caller-role gate credited, each listed above with its source. A hop "
                "that is not unique, is not in the analysed sources, or whose gate does not "
                "dominate the implementer's body leaves the call a candidate. The implementer "
                "credited is the one the scanned sources give for that virtual call: a subclass "
                "outside the scanned set that overrides nothing inherits whatever body its own "
                "bases carry, and that inherited body is not read here. Pointer out-parameters "
                "are not followed, so an object written back through one is not traced to the "
                "call that produced it.")
        unique={}
        for obs in revised:
            unique.setdefault((obs.file,obs.line,obs.rule,obs.symbol),obs)
        return tuple(unique[k] for k in sorted(unique)),tuple(sorted(self.limitations))
