"""Source-derived IPC entry and dispatch index.

Entry discovery used to be a hardcoded name allowlist (see IpcPolicy.entry_names
and IpcPolicy.service_entries). This module derives the entry set from the source
instead: stub classes and their bases, dispatchers identified by signature rather
than by name, and dispatcher -> handler bindings recovered from the dispatch
idioms that actually occur in OpenHarmony.

Discipline, in the same spirit as the rest of this package:

* Every record is graded. `source_dispatch` (a code-to-handler binding read out
  of a real dispatch table, switch or if-chain) is stronger than
  `source_dispatch_case_call` (a case body calls a handler found by name shape),
  which is stronger than `declaration_shape` (a member that merely looks like a
  handler).
* Uncertainty is recorded, never guessed. An unresolvable transaction code, an
  ambiguous overload, a receiver outside the source-backed alias table and a map
  that is defined but never dispatched are all emitted as explicit records.
* Finding an entry establishes neither reachability nor exploitability.
  `transaction_value` may be unknown and several dispatcher-level guards are not
  modelled at all, so a handler reached through this index still carries its
  evidence obligations.

This is a private detector module. It does not read or change the shared
contracts, the public AST outline, or the coverage sidecar schema.

Scope note: the index parses the *raw* source. The member-pointer dispatch
`(this->*(iter->second))(...)` does not survive Tree-sitter C++ parsing, so
dispatch through a function-pointer table is confirmed by matching the cleanly
parsed `map.find(code)` node and then requiring a byte-level `->*` reference to
that iterator's `second` in the same function body.
"""
from dataclasses import dataclass
import re

from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp

from .models import IpcPolicy

# Evidence grades, strongest first.
SOURCE_DISPATCH = "source_dispatch"                        # map / switch-return / if-return
SOURCE_DISPATCH_CASE_CALL = "source_dispatch_case_call"    # case body calls a handler
VIRTUAL_OVERRIDE = "virtual_override"                      # interface dispatch to a subclass
DELEGATED_DISPATCH = "delegated_dispatch"                  # a table outside any IPC dispatcher
DECLARATION_SHAPE = "declaration_shape"                    # handler-shaped, no visible binding
UNRESOLVED_HANDLER = "unresolved_handler"                  # binding seen, target unresolved

# Grades a binding may carry beyond the plain call shape.
_GRADED_VIRTUAL = "virtual_override_not_definite"

# A dispatcher is a member of a class whose ancestry includes one of these.
# Proxies are the client side of the same interfaces and are excluded.
_CONTAINER_BASES = ("IRemoteStub", "IPCObjectStub", "IRemoteObject", "IPCObject")
_PROXY_MARKERS = ("IRemoteProxy", "IPCObjectProxy")

_CODE_TYPE = re.compile(r"\b(?:u?int(?:8|16|32|64)_t|uint32|int32|unsigned(?:\s+int)?|int|long)\b")
_PARCEL_TYPE = re.compile(r"\b(?:MessageParcel|Parcel)\b")
_OPTION_TYPE = re.compile(r"\bMessageOption\b")

# `(this->*(iter->second))(args)` does not survive parsing; confirm it textually.
_NUMBER = re.compile(r"-?(?:0x[0-9A-Fa-f]+|\d+)")

# Names whose presence before the dispatch site indicates a pre-dispatch guard.
# Deliberately broader than IpcPolicy: the point is to downgrade rather than to
# silently drop findings, and to surface the unmodelled names as obligations.
_EXTRA_GUARD_NAMES = frozenset({
    "IsCallerValid", "IsPermissionGranted", "CheckPermission", "VerifyAccessToken",
    "CheckCallingPermission", "VerifyCallingPermission", "IsSystemAppCalling",
    "CheckCallerIsSystemApp", "IsPrivilegedCalling", "HasCallingPermission",
})

# Object-macro aliases that recover a receiver's type without guessing.
# `(?:::)?` — an optional leading `::`; `::?` would require one colon and silently
# reject every ordinary `#define SVC DelayedSingleton<T>::GetInstance()`.
_ALIAS_PATTERNS = (
    re.compile(r"^(?:::)?\s*([\w:]+)\s*::\s*GetInstance\s*\(\s*\)$"),
    re.compile(r"^(?:::)?\s*DelayedSingleton\s*<\s*([\w:]+)\s*>\s*::\s*GetInstance\s*\(\s*\)$"),
)


def _walk(node, kind=None):
    """Iterative pre-order walk; never recurses into Python's own stack."""
    pending = [node]
    while pending:
        current = pending.pop()
        if kind is None or current.type == kind:
            yield current
        pending.extend(reversed(current.named_children))


def _parents(node):
    while node.parent is not None:
        node = node.parent
        yield node


def _text(source, node):
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _terminal(text):
    return re.split(r"::|->|\.", text)[-1].strip()


def _owner_qualified(qualified):
    """`A::B::Method` -> `A::B`; `Method` -> ``."""
    return qualified.rsplit("::", 1)[0] if "::" in qualified else ""


def _last_component(text):
    return text.rsplit("::", 1)[-1].strip() if text else ""


def _handler_key(qualified):
    """`A::B::Method` -> `('B', 'Method')`; `Method` -> `('', 'Method')`."""
    return (_last_component(_owner_qualified(qualified)), _last_component(qualified))


def _last_identifier(source, node):
    found = ""
    for item in _walk(node):
        if item.type in ("identifier", "field_identifier"):
            found = _text(source, item)
    return found


@dataclass(frozen=True)
class InterfaceRef:
    """An interface a class states it implements, and the source that states it.

    `expression` is the template argument exactly as written; `name` is its
    terminal component. Both come from the base clause, so a caller can cite the
    declaration it relied on instead of inferring the interface from a class name.
    """
    name: str
    expression: str
    file: str
    line: int


@dataclass(frozen=True)
class ClassInfo:
    name: str
    qualified: str
    file: str
    line: int
    direct_bases: tuple[str, ...]
    # (terminal base name, first template argument as written) in clause order.
    # Kept beside `direct_bases` rather than replacing it: the ancestry walk that
    # decides whether this is a stub must not change because identity needs the
    # argument, and the two answers are read at different call sites.
    base_specs: tuple = ()
    stub_ancestor: str = ""      # terminal name of the stub/object base, or ""

    @property
    def is_stub(self):
        return self.stub_ancestor in ("IRemoteStub", "IPCObjectStub")


@dataclass(frozen=True)
class Dispatcher:
    qualified: str
    owner: str
    name: str
    file: str
    line: int
    params: tuple[str, ...]
    kind: str                    # "signature" | "allowlist_name"
    owner_is_stub: bool
    container_ok: bool
    guard_before_dispatch: bool = False


@dataclass(frozen=True)
class Entry:
    """One dispatcher -> handler binding, with its transaction and its grade."""

    dispatcher: str
    handler: str                 # "" when the target could not be resolved
    kind: str                    # map_member_ptr | map_callable | switch_case_return
                                 # | switch_case_call | if_code_return | delegation
    transaction_raw: str
    transaction_value: str
    transaction_resolution: str  # literal | enum | macro | dynamic | unresolved
    transaction_reason: str
    handler_bound: bool
    evidence: str
    file: str
    line: int
    ambiguity: tuple[str, ...] = ()
    guard_before_dispatch: bool = False
    conditional: str = ""        # enclosing preprocessor condition, if any


@dataclass(frozen=True)
class _Binding:
    """Outcome of resolving one case/if-body call to a handler."""

    target: str
    bound: bool
    ambiguity: tuple = ()
    delegated: bool = False
    grade: str = ""


@dataclass
class _Func:
    qualified: str
    owner: str
    name: str
    file: str
    line: int
    node: object
    body: object
    source: bytes
    params: tuple          # (type_text, name_text)
    code_param: str


class EntryIndex:
    """Bounded, source-derived index of IPC entries and their dispatch bindings."""

    def __init__(self, units, policy=None, *, max_files=2000, max_map_entries=4096,
                 max_class_depth=16, max_roots=512):
        self.policy = policy or IpcPolicy()
        self.limitations = set()
        self._max_map_entries = max_map_entries
        self._max_class_depth = max_class_depth
        self._max_roots = max_roots

        self._funcs = []
        self._func_by_key = {}
        self._func_by_owner_name = {}
        self._classes = {}
        self._classes_by_terminal = {}
        self._enum_members = {}
        self._macros = {}
        self._map_literals = {}     # map var -> [(code_text, handler, file, line)]
        self._map_assigns = {}      # map var -> same shape

        selected = list(units)
        if len(selected) > max_files:
            self.limitations.add("Entry index file budget truncated the unit set.")
            selected = selected[:max_files]
        for unit in selected:
            self._index_unit(unit)

        self.aliases = self._build_aliases()
        self._ancestors = {}
        self._resolve_ancestry()
        self._derived = self._build_derived()
        self.dispatchers = tuple(self._find_dispatchers())
        self._dispatcher_names = frozenset(d.name for d in self.dispatchers)
        self.entries = tuple(self._extract_entries())
        self._guard_roots = self._compute_guard_roots()

    # ------------------------------------------------------------------ parsing

    def _index_unit(self, unit):
        language = tree_sitter_c.language() if unit.language == "c" else tree_sitter_cpp.language()
        source = unit.text.encode("utf-8")
        tree = Parser(Language(language)).parse(source)
        if tree.root_node.has_error:
            self.limitations.add("Partial source in entry index: " + unit.path)
        path = unit.path
        for node in _walk(tree.root_node):
            kind = node.type
            if kind in ("class_specifier", "struct_specifier"):
                self._record_class(node, source, path)
            elif kind == "enum_specifier":
                self._record_enum(node, source)
            elif kind == "preproc_def":
                self._record_macro(node, source, functional=False)
            elif kind == "preproc_function_def":
                self._record_macro(node, source, functional=True)
            elif kind == "function_definition":
                self._record_function(node, source, path)
            elif kind == "initializer_list":
                self._record_map_literal(node, source, path)
            elif kind == "assignment_expression":
                self._record_map_assign(node, source, path)

    def _record_class(self, node, source, path):
        name = _text(source, node.child_by_field_name("name"))
        if not name:
            return
        namespace = []
        for ancestor in _parents(node):
            if ancestor.type == "namespace_definition":
                item = ancestor.child_by_field_name("name")
                if item is not None:
                    namespace.append(_text(source, item))
            elif ancestor.type in ("class_specifier", "struct_specifier"):
                outer = _text(source, ancestor.child_by_field_name("name"))
                if outer:
                    namespace.append(outer)
        qualified = "::".join(list(reversed(namespace)) + [name])
        clause = next((c for c in node.named_children if c.type == "base_class_clause"), None)
        bases, specs = [], []
        if clause is not None:
            for child in clause.named_children:
                if child.type in ("type_identifier", "template_type", "qualified_identifier"):
                    base = _base_terminal(source, child)
                    if base:
                        bases.append(base)
                        specs.append((base, _template_argument(source, child)))
        info = ClassInfo(name, qualified, path, node.start_point[0] + 1, tuple(bases),
                         tuple(specs))
        self._classes[qualified] = info
        self._classes_by_terminal.setdefault(name, info)

    def _record_enum(self, node, source):
        name = _text(source, node.child_by_field_name("name"))
        body = node.child_by_field_name("body")
        if not name or body is None:
            return
        members, counter = {}, 0
        for item in body.named_children:
            if item.type != "enumerator":
                continue
            member = _text(source, item.child_by_field_name("name"))
            if not member:
                continue
            raw = item.child_by_field_name("value")
            if raw is None:
                members[member] = counter
                counter += 1
                continue
            literal = _text(source, raw).strip()
            if _NUMBER.fullmatch(literal):
                counter = int(literal, 0)
                members[member] = counter
                counter += 1
            else:
                members[member] = None      # derived from an expression; not resolved
        if members:
            self._enum_members.setdefault(name, {}).update(members)

    def _record_macro(self, node, source, *, functional):
        name = _text(source, node.child_by_field_name("name"))
        if not name:
            return
        value = _text(source, node.child_by_field_name("value")).strip()
        params = _text(source, node.child_by_field_name("parameters")).strip() if functional else ""
        self._macros[name] = {"value": value, "functional": functional, "params": params}

    def _record_function(self, node, source, path):
        declared = node.child_by_field_name("declarator")
        while declared is not None and declared.type != "function_declarator":
            declared = declared.child_by_field_name("declarator")
        if declared is None:
            return
        name_node = declared.child_by_field_name("declarator")
        if name_node is None:
            return
        qualified = _text(source, name_node)
        owner = _owner_qualified(qualified)
        if not owner:
            for ancestor in _parents(node):
                if ancestor.type in ("class_specifier", "struct_specifier"):
                    item = ancestor.child_by_field_name("name")
                    owner = _text(source, item) if item is not None else ""
                    break
        params = []
        plist = declared.child_by_field_name("parameters")
        for param in plist.named_children if plist else ():
            if param.type != "parameter_declaration":
                continue
            ptype = _text(source, param.child_by_field_name("type")).strip()
            pdecl = param.child_by_field_name("declarator")
            params.append((ptype, _last_identifier(source, pdecl) if pdecl is not None else ""))
        record = _Func(qualified, owner, _last_component(qualified), path,
                       node.start_point[0] + 1, node, node.child_by_field_name("body"),
                       source, tuple(params), params[0][1] if params else "")
        self._funcs.append(record)
        self._func_by_key[(qualified, path)] = record
        self._func_by_owner_name.setdefault((_last_component(owner), record.name), []).append(record)

    def _record_map_literal(self, node, source, path):
        """`{ {code, &Cls::Fn}, ... }`, `{ make_pair(code, &Cls::Fn), ... }` or
        `{ .code = ..., .handler = ... }`. Positional entries are nested
        initializer_lists, not initializer_pairs."""
        entries = []
        for item in node.named_children:
            parsed = _map_item(item, source)
            if parsed is not None:
                entries.append((parsed[0], parsed[1], path, item.start_point[0] + 1))
        if not entries:
            return
        name = self._enclosing_declarator(node, source)
        if not name:
            return
        if len(entries) > self._max_map_entries:
            self.limitations.add("Map entry budget truncated entries for " + name)
            entries = entries[:self._max_map_entries]
        self._map_literals.setdefault(name, []).extend(entries)

    def _record_map_assign(self, node, source, path):
        """`recFuncs_[CODE] = std::bind(&Cls::Fn, this, ...)`."""
        left = node.child_by_field_name("left")
        if left is None or left.type != "subscript_expression":
            return
        receiver = left.child_by_field_name("argument")
        indices = left.child_by_field_name("indices")
        if receiver is None or indices is None or not indices.named_children:
            return
        self._map_assigns.setdefault(_text(source, receiver).strip(), []).append(
            (_text(source, indices.named_children[0]).strip(),
             _handler_from_value(node.child_by_field_name("right"), source),
             path, node.start_point[0] + 1))

    def _enclosing_declarator(self, node, source):
        for ancestor in _parents(node):
            if ancestor.type == "init_declarator":
                return _last_identifier(source, ancestor.child_by_field_name("declarator"))
            if ancestor.type == "assignment_expression":
                return _text(source, ancestor.child_by_field_name("left")).strip()
            if ancestor.type in ("declaration", "field_declaration", "expression_statement",
                                 "function_definition", "compound_statement", "translation_unit"):
                return ""
        return ""

    def _build_aliases(self):
        aliases, conflicts = {}, set()
        for name, macro in self._macros.items():
            if macro["functional"]:
                continue
            for pattern in _ALIAS_PATTERNS:
                match = pattern.match(macro["value"])
                if match:
                    target = _last_component(match.group(1))
                    if name in aliases and aliases[name] != target:
                        conflicts.add(name)
                    aliases[name] = target
                    break
        for name in sorted(conflicts):
            aliases.pop(name, None)
            self.limitations.add("Object-macro alias with conflicting targets ignored: " + name)
        return aliases

    def _base_closure(self, qualified):
        """Transitive terminal base names, bounded."""
        info = self._classes.get(qualified)
        if info is None:
            return frozenset()
        names, seen, frontier = set(), set(), list(info.direct_bases)
        for _ in range(self._max_class_depth):
            if not frontier:
                break
            nxt = []
            for base in frontier:
                if base in seen:
                    continue
                seen.add(base)
                names.add(base)
                parent = self._classes_by_terminal.get(base)
                if parent is not None:
                    nxt.extend(parent.direct_bases)
            frontier = nxt
        else:
            self.limitations.add("Class base depth budget reached at " + qualified)
        return frozenset(names)

    def _resolve_ancestry(self):
        for qualified, info in self._classes.items():
            closure = self._base_closure(qualified)
            found = ""
            for candidate in ("IRemoteStub", "IPCObjectStub"):
                if candidate in closure:
                    found = candidate
                    break
            if not found:
                for candidate in ("IRemoteObject", "IPCObject"):
                    if candidate in closure:
                        found = candidate
                        break
            self._ancestors[qualified] = found

    def _build_derived(self):
        derived = {}
        for info in self._classes.values():
            for base in info.direct_bases:
                derived.setdefault(base, []).append(info)
        return derived

    # ------------------------------------------------------------------ identity

    def resolve_class(self, name):
        """The class a written name refers to, or None. Never guesses across names."""
        if not name:
            return None
        return (self._classes.get(name)
                or self._classes_by_terminal.get(_last_component(name)))

    def implemented_interfaces(self, qualified):
        """Interfaces a class states it implements, with the declaration that says so.

        Only the argument of `IRemoteStub<T>` names an interface: the class is
        then a stub *for* T, and T's descriptor is the one its caller writes. The
        walk follows bases' bases, so an intermediate `FooBase` between the stub
        and `IRemoteStub<T>` still yields T.

        An empty result means the analysed sources do not state an interface for
        this class -- a bare `IPCObjectStub`, a declaration outside the shard, or
        a name that is not a class at all. Callers must read that as unknown, not
        as "this class implements nothing".
        """
        found, seen, frontier = [], set(), [(qualified, 0)]
        while frontier:
            current, depth = frontier.pop(0)
            info = self.resolve_class(current)
            if info is None or info.qualified in seen:
                continue
            seen.add(info.qualified)
            if depth > self._max_class_depth:
                self.limitations.add("Interface identity depth budget reached at " + info.qualified)
                continue
            for terminal, argument in info.base_specs:
                if terminal == "IRemoteStub" and argument:
                    found.append(InterfaceRef(_last_component(argument), argument,
                                              info.file, info.line))
                parent = self._classes_by_terminal.get(terminal)
                if parent is not None:
                    frontier.append((parent.qualified, depth + 1))
        return tuple(found)

    # -------------------------------------------------------------- dispatchers

    def _find_dispatchers(self):
        for record in self._funcs:
            if not self._looks_like_dispatcher(record):
                continue
            qualified = self._resolve_owner(record)
            ancestor = self._ancestors.get(qualified, "")
            closure = self._base_closure(qualified)
            proxy = (record.owner.endswith("Proxy")
                     or any(marker in closure for marker in _PROXY_MARKERS))
            container = bool(ancestor) and not proxy
            kind = "signature"
            yield Dispatcher(record.qualified, record.owner, record.name, record.file,
                             record.line, tuple(t for t, _n in record.params), kind,
                             ancestor in ("IRemoteStub", "IPCObjectStub"), container,
                             container and self._has_guard(record))

    def _looks_like_dispatcher(self, record):
        params = record.params
        if len(params) < 3:
            return False
        if not _CODE_TYPE.search(params[0][0]):
            return False
        if not _PARCEL_TYPE.search(params[1][0]) or not _PARCEL_TYPE.search(params[2][0]):
            return False
        if len(params) > 3 and not _OPTION_TYPE.search(params[3][0]):
            return False
        return True

    def _resolve_owner(self, record):
        info = self._classes_by_terminal.get(_last_component(record.owner))
        return info.qualified if info is not None else ""

    def _has_guard(self, record):
        """Whether the dispatcher body calls a recognizable authorization API."""
        if record.body is None:
            return False
        names = (self.policy.boolean_permissions | self.policy.result_permissions
                 | self.policy.caller_class_sensitive_calls | _EXTRA_GUARD_NAMES)
        for node in _walk(record.body, "call_expression"):
            callee = _text(record.source, node.child_by_field_name("function"))
            if _terminal(callee) in names:
                return True
        return False

    # ------------------------------------------------------------------ entries

    def _extract_entries(self):
        emitted = 0
        for dispatcher in self.dispatchers:
            record = self._func_by_key.get((dispatcher.qualified, dispatcher.file))
            if record is None or record.body is None:
                continue
            for entry in self._entries_for(record, dispatcher):
                if emitted >= self._max_roots:
                    self.limitations.add("Entry root budget reached; further bindings not indexed.")
                    return
                emitted += 1
                yield entry

    def _entries_for(self, record, dispatcher):
        yield from self._map_entries(record, dispatcher)
        yield from self._case_entries(record, dispatcher)

    # -- function-pointer tables ------------------------------------------------

    def _map_entries(self, record, dispatcher):
        source, body = record.source, record.body
        for node in _walk(body, "init_declarator"):
            value = node.child_by_field_name("value")
            if value is None or value.type != "call_expression":
                continue
            callee = value.child_by_field_name("function")
            if callee is None or callee.type != "field_expression":
                continue
            if _text(source, callee.child_by_field_name("field")) not in ("find", "at"):
                continue
            args = value.child_by_field_name("arguments")
            if args is None or len(args.named_children) != 1:
                continue
            if _text(source, args.named_children[0]).strip() != record.code_param:
                continue
            map_name = _text(source, callee.child_by_field_name("argument")).strip()
            iterator = _last_identifier(source, node.child_by_field_name("declarator"))
            table = self._map_table(map_name)
            if not table:
                continue
            pointer_form, callable_form = _dispatch_forms(body, source, iterator)
            if not (pointer_form or callable_form):
                yield Entry(dispatcher.qualified, "", "map_member_ptr", "", "unknown",
                            "unresolved", "map_found_but_never_dispatched", False,
                            UNRESOLVED_HANDLER, record.file, node.start_point[0] + 1,
                            (), dispatcher.guard_before_dispatch,
                            _preproc_context(source, node))
                continue
            kind = "map_member_ptr" if pointer_form else "map_callable"
            location = _preproc_context(source, node)
            for code, handler, file, line in table:
                value_text, resolution, reason = self._resolve_transaction(code)
                bound, target, ambiguity = self._bind_handler(handler, record)
                yield Entry(dispatcher.qualified, target, kind, code.strip(), value_text,
                            resolution, reason, bound, SOURCE_DISPATCH, file, line,
                            ambiguity, dispatcher.guard_before_dispatch, location)

    def _map_table(self, map_name):
        return self._map_literals.get(map_name, []) + self._map_assigns.get(map_name, [])

    def _bind_handler(self, handler, record):
        """Resolve a bound handler to exactly one definition. Ambiguity is recorded."""
        if not handler:
            return False, "", ("not_a_bound_callable",)
        matches = self._func_by_owner_name.get(_handler_key(handler), [])
        if len(matches) == 1:
            return True, matches[0].qualified, ()
        if len(matches) > 1:
            return False, handler, ("overload",) + tuple(
                sorted(m.file + ":" + str(m.line) for m in matches))
        if "." in handler or "->" in handler:
            return False, handler, ("unresolved_receiver",)
        return False, handler, ("definition_missing",)

    # -- switch / if dispatch ---------------------------------------------------

    def _case_entries(self, record, dispatcher):
        for node in _walk(record.body):
            if node.type == "switch_statement":
                yield from self._switch_entries(node, record, dispatcher)
            elif node.type == "if_statement":
                entry = self._if_entry(node, record, dispatcher)
                if entry is not None:
                    yield entry

    def _switch_entries(self, node, record, dispatcher):
        condition = node.child_by_field_name("condition")
        if condition is None or record.code_param not in _text(record.source, condition):
            return
        for case in _owned_cases(node):
            code_node = case.child_by_field_name("value")
            if code_node is None:
                continue
            code = _text(record.source, code_node)
            value_text, resolution, reason = self._resolve_transaction(code)
            location = _preproc_context(record.source, case)
            for call, returned in _case_calls(case):
                binding = self._same_owner_target(call, record)
                if binding is None:
                    continue
                if returned:
                    kind, evidence = "switch_case_return", SOURCE_DISPATCH
                elif binding.delegated:
                    kind, evidence = "delegation", DECLARATION_SHAPE
                else:
                    kind, evidence = "switch_case_call", SOURCE_DISPATCH_CASE_CALL
                if binding.grade:
                    evidence = binding.grade
                yield Entry(dispatcher.qualified, binding.target, kind, code.strip(),
                            value_text, resolution, reason,
                            binding.bound and not binding.delegated, evidence,
                            record.file, call.start_point[0] + 1, binding.ambiguity,
                            dispatcher.guard_before_dispatch, location)

    def _if_entry(self, node, record, dispatcher):
        condition = node.child_by_field_name("condition")
        if condition is None:
            return None
        inner = condition.child_by_field_name("value")
        if inner is None and condition.named_children:
            inner = condition.named_children[-1]
        parts = re.split(r"==", _text(record.source, inner))
        if len(parts) != 2:
            return None
        sides = [side.strip() for side in parts]
        if record.code_param not in sides:
            return None
        code = sides[1] if sides[0] == record.code_param else sides[0]
        consequence = node.child_by_field_name("consequence")
        if consequence is None:
            return None
        for call in _walk(consequence, "call_expression"):
            parent = call.parent
            if parent is None or parent.type != "return_statement":
                continue
            binding = self._same_owner_target(call, record)
            if binding is None:
                continue
            value_text, resolution, reason = self._resolve_transaction(code)
            evidence = SOURCE_DISPATCH if binding.bound else DECLARATION_SHAPE
            if binding.grade:
                evidence = binding.grade
            return Entry(dispatcher.qualified, binding.target, "if_code_return", code.strip(),
                         value_text, resolution, reason,
                         binding.bound and not binding.delegated, evidence, record.file,
                         call.start_point[0] + 1, binding.ambiguity,
                         dispatcher.guard_before_dispatch, _preproc_context(record.source, node))
        return None

    def _same_owner_target(self, call, record):
        """Bind a case/if-body call to a handler definition.

        Resolution order: the dispatcher's own class, then a subclass override of
        the same method (an interface stub calls the pure virtual that its concrete
        service implements). A call to a base container (the
        `IPCObjectStub::OnRemoteRequest` fallback, `ProcessProto`) is reported as
        delegated so it is never rooted as a business handler. Anything else is
        left unresolved rather than guessed.
        """
        callee_node = call.child_by_field_name("function")
        if callee_node is None or callee_node.type not in (
                "identifier", "qualified_identifier", "field_expression"):
            return None
        callee = _text(record.source, callee_node)
        if not callee:
            return None
        if callee_node.type == "field_expression":
            receiver = _text(record.source, callee_node.child_by_field_name("argument"))
            if receiver not in ("this", ""):
                return None
        owner = _last_component(record.owner)
        if "::" in callee:
            other = _last_component(_owner_qualified(callee))
            if other and other != owner:
                if other in _CONTAINER_BASES:
                    return _Binding(callee, False, ("delegation_to_container",), delegated=True)
                return None
        name = _last_component(callee)
        matches = self._func_by_owner_name.get((owner, name), [])
        if len(matches) == 1:
            return _Binding(matches[0].qualified, True)
        if len(matches) > 1:
            return _Binding(callee, False,
                            ("overload",) + tuple(sorted(
                                m.file + ":" + str(m.line) for m in matches)))
        overrides = self._virtual_overrides(owner, name)
        if len(overrides) == 1:
            return _Binding(overrides[0].qualified, True, (_GRADED_VIRTUAL,), grade=VIRTUAL_OVERRIDE)
        if len(overrides) > 1:
            return _Binding(callee, False, ("ambiguous_virtual_override",) + tuple(
                sorted(m.file + ":" + str(m.line) for m in overrides)))
        if name in self._dispatcher_names:
            return _Binding(callee, False, ("inherited_dispatcher",), delegated=True)
        return None

    def _virtual_overrides(self, base_owner, name):
        """Subclasses of `base_owner` that define `name`.

        Source-declared, not proven: an interface stub calling a pure virtual is
        implemented by exactly one concrete subclass in the observed source, but
        dynamic dispatch is not established here.
        """
        found, seen, frontier = [], {base_owner}, [base_owner]
        for _ in range(self._max_class_depth):
            if not frontier:
                break
            nxt = []
            for base in frontier:
                for info in self._derived.get(base, ()):
                    if info.name in seen:
                        continue
                    seen.add(info.name)
                    found.extend(self._func_by_owner_name.get((info.name, name), []))
                    nxt.append(info.name)
            frontier = nxt
        else:
            self.limitations.add("Virtual override depth budget reached at " + base_owner)
        return found

    # -- transaction codes ------------------------------------------------------

    def _unwrap_cast(self, raw):
        text = raw.strip()
        match = re.fullmatch(r"static_cast\s*<[^<>]*>\s*\((.*)\)", text, re.S)
        if match:
            return match.group(1).strip(), ""
        match = re.fullmatch(r"([A-Za-z_]\w*)\s*\((.*)\)", text, re.S)
        if match and match.group(1) in self._macros:
            body = self._macros[match.group(1)]["value"].strip()
            # A transparent cast macro looks like `(static_cast<uint32_t>(x))`.
            if body.startswith("(") and body.endswith(")"):
                body = body[1:-1].strip()
            if re.fullmatch(r"static_cast\s*<[^<>]*>\s*\(\s*\w+\s*\)", body):
                return match.group(2).strip(), ""
            return "", "macro_not_transparent"
        return text, ""

    def _resolve_transaction(self, raw):
        text, wrapper = self._unwrap_cast(raw)
        if wrapper:
            return "unknown", "unresolved", wrapper
        if not text:
            return "unknown", "unresolved", "empty_transaction"
        if _NUMBER.fullmatch(text):
            return str(int(text, 0)), "literal", ""
        terminal = _last_component(text)
        qualifier = _last_component(_owner_qualified(text))
        hits = [(enum, members[terminal]) for enum, members in self._enum_members.items()
                if terminal in members and (not qualifier or _last_component(enum) == qualifier)]
        if not hits:
            return "unknown", "dynamic", "not_a_constant"
        values = {value for _enum, value in hits}
        if len(hits) == 1 and hits[0][1] is not None:
            return str(hits[0][1]), "enum", ""
        if len(values) > 1:
            return "unknown", "unresolved", "ambiguous_enum:" + ",".join(
                sorted(_last_component(enum) for enum, _v in hits))
        if hits:
            return "unknown", "unresolved", "enum_value_not_literal:" + _last_component(hits[0][0])
        return "unknown", "unresolved", "enum_member_not_found:" + terminal

    # ------------------------------------------------------------------ queries

    def _compute_guard_roots(self):
        roots = set()
        for entry in self.entries:
            if entry.guard_before_dispatch and entry.handler:
                roots.add(entry.handler)
                owner, name = _handler_key(entry.handler)
                if owner:
                    roots.add(owner + "::" + name)
        return frozenset(roots)

    def dispatcher_guard_roots(self):
        return self._guard_roots

    def root_bindings(self):
        """Handlers admitted as roots from a source-verified dispatch binding.

        Yields `(owner_terminal, handler_name, ambiguity)`, de-duplicated, and only
        for bindings whose handler resolves to exactly one definition.
        """
        seen = set()
        for entry in self.entries:
            if entry.evidence not in (SOURCE_DISPATCH, SOURCE_DISPATCH_CASE_CALL,
                                      VIRTUAL_OVERRIDE):
                continue
            if not entry.handler_bound or not entry.handler:
                continue
            key = _handler_key(entry.handler)
            if not key[1] or key in seen:
                continue
            seen.add(key)
            yield key[0], key[1], entry.ambiguity

    def dispatch_note(self, owner, name):
        """Compact, reviewable evidence note for a dispatch-derived entry root."""
        codes, conditions, kinds, guarded = [], set(), set(), False
        for entry in self.entries:
            if _handler_key(entry.handler) != (owner, name):
                continue
            codes.append(entry.transaction_value if entry.transaction_value != "unknown"
                         else entry.transaction_raw)
            kinds.add(entry.kind)
            guarded = guarded or entry.guard_before_dispatch
            if entry.conditional:
                conditions.add(entry.conditional)
        unique = sorted({code for code in codes if code})
        if not unique:
            return ""
        shown = "/".join(unique[:6]) + ("/..." if len(unique) > 6 else "")
        note = "dispatch=" + ",".join(sorted(kinds)) + " codes=" + shown
        if conditions:
            note += " within " + "; ".join(sorted(conditions))
        if guarded:
            note += " dispatcher-guard-observed"
        return note

    def resolve_receiver(self, expression):
        """Map a source-backed receiver to `Type::Method`; never guesses."""
        expression = expression.strip()
        if "->" not in expression:
            return None
        receiver, method = (part.strip() for part in expression.split("->", 1))
        if not re.fullmatch(r"\w+", method):
            return None
        if receiver in self.aliases:
            return self.aliases[receiver] + "::" + method
        match = re.fullmatch(
            r"(?:DelayedSingleton\s*<\s*)?([\w:]+?)\s*>?\s*::\s*GetInstance\s*\(\s*\)", receiver)
        if match:
            return _last_component(match.group(1)) + "::" + method
        return None

    def counts(self):
        by_evidence, by_kind = {}, {}
        for entry in self.entries:
            by_evidence[entry.evidence] = by_evidence.get(entry.evidence, 0) + 1
            by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1
        return {
            "classes": len(self._classes),
            "stub_classes": sum(1 for name, ancestor in self._ancestors.items()
                                if ancestor in ("IRemoteStub", "IPCObjectStub")),
            "dispatchers": len(self.dispatchers),
            "dispatchers_by_signature": sum(1 for d in self.dispatchers if d.kind == "signature"),
            "dispatchers_with_guard": sum(1 for d in self.dispatchers if d.guard_before_dispatch),
            "entries": len(self.entries),
            "entries_by_evidence": dict(sorted(by_evidence.items())),
            "entries_by_kind": dict(sorted(by_kind.items())),
            "bound_handlers": sum(1 for e in self.entries if e.handler_bound),
            "root_bindings": sum(1 for _ in self.root_bindings()),
            "aliases": len(self.aliases),
            "unresolved_transactions": sum(1 for e in self.entries
                                           if e.transaction_resolution == "unresolved"),
            "limitations": sorted(self.limitations),
        }


def _base_terminal(source, node):
    if node.type == "template_type":
        return _last_component(_text(source, node.child_by_field_name("name")))
    if node.type == "qualified_identifier":
        inner = node.child_by_field_name("name")
        if inner is not None and inner.type == "template_type":
            return _last_component(_text(source, inner.child_by_field_name("name")))
        return _last_component(_text(source, inner if inner is not None else node))
    return _last_component(_text(source, node))


def _template_argument(source, node):
    """The first template argument of a base specifier, as written, or "".

    `IRemoteStub<IFoo>` -> "IFoo"; `NS::IRemoteStub<NS::IFoo>` -> "NS::IFoo";
    a non-template base has no argument. Only the first argument is read: no
    stub shape in scope carries a second one that changes the identity.
    """
    holder = node
    if node.type == "qualified_identifier":
        inner = node.child_by_field_name("name")
        if inner is not None and inner.type == "template_type":
            holder = inner
    arguments = holder.child_by_field_name("arguments")
    if arguments is None or not arguments.named_children:
        return ""
    return _text(source, arguments.named_children[0]).strip()


def _map_item(item, source):
    """One map entry -> (code_text, handler_text). None when not an entry."""
    if item.type == "initializer_list" and len(item.named_children) == 2:
        return (_text(source, item.named_children[0]),
                _handler_from_value(item.named_children[1], source))
    if item.type == "initializer_pair":
        return "", _handler_from_value(item.child_by_field_name("value"), source)
    if item.type == "call_expression":
        callee = item.child_by_field_name("function")
        if callee is None or _last_component(_text(source, callee)) != "make_pair":
            return None
        args = item.child_by_field_name("arguments")
        kids = args.named_children if args else []
        if len(kids) == 2:
            return _text(source, kids[0]), _handler_from_value(kids[1], source)
    return None


def _handler_from_value(node, source):
    if node is None:
        return ""
    if node.type == "pointer_expression":
        return _text(source, node.child_by_field_name("argument")).strip()
    if node.type == "call_expression":                    # std::bind(&Cls::Fn, ...)
        args = node.child_by_field_name("arguments")
        kids = args.named_children if args else []
        if kids:
            return _handler_from_value(kids[0], source)
    return ""


def _dispatch_forms(body, source, iterator):
    """Whether a `MAP.find(code)` site actually dispatches, and how.

    Returns `(pointer_form, callable_form)`. Three shapes occur in real code:

      return (this->*(iter->second))(this, data, reply, option);   # direct
      Fn fn = iter->second; return (this->*fn)(data, reply);        # copied alias
      Fn fn = iter->second; fn(data, reply);                        # callable table

    The `->*` operator does not survive parsing, so the first two are confirmed by
    matching text in the function body; the third by a call to the alias.
    """
    aliases = []
    for node in _walk(body, "init_declarator"):
        value = node.child_by_field_name("value")
        if value is None or value.type != "field_expression":
            continue
        if _text(source, value.child_by_field_name("field")) != "second":
            continue
        argument = value.child_by_field_name("argument")
        if argument is not None and _text(source, argument).strip() == iterator:
            name = _last_identifier(source, node.child_by_field_name("declarator"))
            if name:
                aliases.append(name)
    targets = [re.escape(iterator) + r"\s*->\s*second"] + [re.escape(a) for a in aliases]
    body_text = _text(source, body)
    pointer = any(re.search(r"this\s*->\s*\*\s*\(?\s*" + target + r"\s*\)?", body_text)
                  for target in targets)
    if pointer:
        return True, False
    for alias in aliases:
        for node in _walk(body, "call_expression"):
            callee = node.child_by_field_name("function")
            if callee is not None and callee.type == "identifier" and _text(source, callee) == alias:
                return False, True
    return False, False


def _nearest_switch(node):
    cursor = node.parent
    while cursor is not None:
        if cursor.type == "switch_statement":
            return cursor
        cursor = cursor.parent
    return None


def _owned_cases(switch_node):
    """Cases belonging to this switch, including those inside `#if`/`#ifndef` blocks.

    A case nested in a preprocessor conditional is still an entry of this switch —
    `IPCObjectStub::SendRequest` keeps `GET_PID_UID` behind `CONFIG_IPC_SINGLE`.
    Cases owned by a nested switch are excluded.
    """
    body = switch_node.child_by_field_name("body")
    if body is None:
        return []
    # Node identity: py-tree-sitter builds a fresh wrapper per access, so compare
    # with `==` (which matches on the node id), never `is`.
    return [case for case in _walk(body, "case_statement")
            if _nearest_switch(case) == switch_node]


def _preproc_context(source, node):
    """Text of the enclosing preprocessor conditions, outermost first.

    Recorded, never interpreted: whether a branch is reachable under a given build
    configuration is not established here. `preproc_ifdef` covers both `#ifdef` and
    `#ifndef` (the node type does not distinguish them), so the directive word is
    read back out of the source instead of being assumed.
    """
    parts = []
    for parent in _parents(node):
        kind = parent.type
        if kind == "preproc_if":
            parts.append("if " + _text(source, parent.child_by_field_name("condition")).strip())
        elif kind == "preproc_ifdef":
            item = parent.child_by_field_name("name")
            parts.append(_directive_word(source, parent, item) + " " + _text(source, item).strip())
        elif kind == "preproc_elif":
            parts.append("elif " + _text(source, parent.child_by_field_name("condition")).strip())
        elif kind == "preproc_else":
            parts.append("else")
        elif kind in ("function_definition", "class_specifier", "struct_specifier",
                      "namespace_definition", "translation_unit"):
            break
    return " && ".join(reversed(parts))


def _directive_word(source, node, name_node):
    if name_node is None:
        return "ifdef"
    prefix = source[node.start_byte:name_node.start_byte].decode("utf-8", errors="replace")
    match = re.search(r"#\s*(ifn?def)", prefix)
    return match.group(1) if match else "ifdef"


def _case_calls(case):
    """Calls in a case body, with whether the call is returned directly."""
    for node in _walk(case, "call_expression"):
        parent = node.parent
        yield node, parent is not None and parent.type == "return_statement"
