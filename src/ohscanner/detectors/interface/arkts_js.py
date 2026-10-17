"""Bounded ArkTS / JavaScript interface-surface detector (first batch).

The gap review asks for an auditable language frontend before any rule: the
result must say whether a file parsed completely, partially or not at all, and
must not turn "a .ets file was seen" into a semantic claim. This module does
that literally:

* `.js` is parsed with tree-sitter-javascript; `.ts` and `.ets` with
  tree-sitter-typescript. ArkTS is TypeScript plus decorators and `struct`
  declarations, and the TypeScript grammar does **not** understand `struct` or
  ArkTS decorators: such files parse ``partial`` and the component/decorator
  semantics are explicitly not analysed. Only the call / class / property
  structure the grammar did recover is read.
* When a grammar is not installed the language is ``unsupported`` and the run is
  ``blocked`` rather than silently reporting zero.

The rules are deliberately narrow and stay candidates:

``ohscanner.oh.arkts.component_exposure``
    An exported Ability/Extension class reads ``want.parameters`` in a lifecycle
    method and reaches a path sink without a path predicate. ``module.json5``
    export/permission state is not read, so the finding states that obligation
    instead of assuming the ability is exported.
``ohscanner.oh.arkts.webview_bridge``
    ``registerJavaScriptProxy``/``javaScriptProxy`` registration with no URL or
    origin predicate in the same function.
``ohscanner.js.path_taint``
    ``want.parameters`` reaching a file-path sink in the same function with no
    path predicate in between.
``ohscanner.js.dangerous_eval``
    ``eval``/``new Function`` with a non-literal argument.
``ohscanner.oh.native_bridge``
    A value derived from ``want.parameters`` is passed as a numeric argument to
    an N-API export imported from a ``lib*.so`` module, and the same function has
    no numeric range or domain predicate. The binding map comes from
    ``declare module 'lib*.so'`` signatures in the scan's ``.d.ts`` files; an
    import whose module or export is not declared there is counted as unmapped,
    not guessed.

What this module does not do, and says so in every result: no CFG, no
cross-function taint beyond one same-file hop between function declarations,
no decorator/struct modelling, no manifest parsing, no page-origin
determination, and no claim that a candidate is reachable or exploitable.
The N-API binding map is limited to ``.d.ts`` files in the same scan batch:
a declaration that lives outside the scanned tree is invisible, and such a
call is reported as unmapped rather than matched by symbol name.
"""
from dataclasses import dataclass
import bisect
import re
from typing import Dict, List, Optional, Tuple

from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit)

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as _javascript_grammar
except ImportError:  # pragma: no cover - exercised only where the wheel is absent
    Language = Parser = None
    _javascript_grammar = None

try:
    import tree_sitter_typescript as _typescript_grammar
except ImportError:  # pragma: no cover
    _typescript_grammar = None


LANGUAGE_MODULE_STATUS: Dict[str, str] = {
    "js": "available" if _javascript_grammar is not None else "missing",
    "ts": "available" if _typescript_grammar is not None else "missing",
    "arkts": "available" if _typescript_grammar is not None else "missing",
}

_FUNCTION_TYPES = {
    "function_declaration", "function_expression", "method_definition",
    "arrow_function", "generator_function_declaration", "required_parameter",
}
_LIFECYCLE_METHODS = {"onCreate", "onNewWant", "onRequest", "onConnect",
                      "onStartContinuation", "onAcceptWant"}
_ABILITY_BASES = re.compile(
    r"\b(UIAbility|ExtensionAbility|ServiceExtensionAbility|FormExtensionAbility|"
    r"UIExtensionAbility|DataShareExtensionAbility)\b")
_PATH_SINKS = (
    "fileIo.openSync", "fileIo.open", "fileIo.readTextSync", "fileIo.readSync",
    "fileIo.writeSync", "fileIo.copyFileSync", "fileIo.mkdirSync",
    "fs.openSync", "fs.open", "fs.readFileSync", "fs.writeFileSync",
    "fs.readdirSync", "fs.unlinkSync", "fs.rmdirSync",
)
_PATH_PREDICATE = re.compile(
    r"\b(?:startsWith|endsWith|includes|indexOf|startsWithPath|canonicalPath|"
    r"isValidPath|resolvePath)\s*\(")
_SOURCE = re.compile(r"\bwant\s*\.\s*parameters\b|\bparameters\s*\[")
_ORIGIN_PREDICATE = re.compile(
    r"\b(?:url|origin|src|allowlist|isTrusted|isAllowed)\b")
_COMPARE = re.compile(r"===|!==|startsWith|endsWith|indexOf|includes|match\(")
# A numeric-domain or range test on a value before it crosses into native code.
# The predicate list is deliberately small: these are the ways the sources in
# this corpus say "this number is a count/length/offset I have constrained",
# and a wider pattern would start crediting comparisons that bound something
# else. `parseInt` is not here: it converts and truncates, it does not bound.
_NUMBER_PREDICATE = re.compile(
    r"\bNumber\.(?:isInteger|isSafeInteger|isFinite)\s*\(|"
    r"\bisNaN\s*\(|"
    r"(?:<=?|>=?)\s*-?\d|"
    r"-?\d\s*(?:<=?|>=?)")

_BASE_OBLIGATIONS = (
    EvidenceObligation(
        "entry_reachability",
        "Show that the component/page/ability is reachable by the attacker the "
        "candidate assumes. A .ets/.ts/.js file in the scan is not an installed "
        "or exported entry."),
    EvidenceObligation(
        "argument_control",
        "Show where the source value comes from and that an untrusted party can "
        "choose it. The frontend only sees the local expression."),
    EvidenceObligation(
        "not_implicitly_sanitised",
        "Verify that no API, framework normalization or upstream caller has "
        "already constrained the value before the sink."),
)
_MANIFEST_OBLIGATION = EvidenceObligation(
    "manifest_export_state",
    "Read module.json5 (exported, skills, permission, extension type) and any "
    "caller-side check. This frontend does not parse manifests, so the class "
    "alone neither proves nor disproves exposure.")
_ORIGIN_OBLIGATION = EvidenceObligation(
    "page_origin",
    "Establish which page is loaded and whether it is untrusted. The bridge "
    "registration alone does not show that untrusted content can call it.")
_NATIVE_OBLIGATION = EvidenceObligation(
    "native_parameter_check",
    "Read the N-API implementation behind this lib*.so export and show whether "
    "the native side validates the value's range, length or index. The .d.ts "
    "type is a declaration, not a runtime check.")


@dataclass(frozen=True)
class FrontendFile:
    path: str
    language: str
    status: str            # complete | partial | unsupported
    error_nodes: int
    call_sites: int
    root_text: bytes = b""
    source: bytes = b""


@dataclass(frozen=True)
class Observation:
    rule_id: str
    line: int
    symbol: str
    message: str
    cwe: str
    obligations: Tuple[EvidenceObligation, ...] = _BASE_OBLIGATIONS


@dataclass(frozen=True)
class BindingParameter:
    name: str
    type_text: str


@dataclass(frozen=True)
class BindingFunction:
    module: str
    name: str
    parameters: Tuple[BindingParameter, ...]


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _line_starts(source: bytes) -> List[int]:
    """Byte offsets of line starts, for line numbers computed from offsets.

    Line numbers do not come from ``Node.start_point``: on a real 88-call ArkTS
    file the binding segfaulted reading that property after earlier nodes had
    been touched, while ``start_byte`` stayed valid. Computing from the saved
    bytes keeps extraction independent of that binding path.
    """
    starts = [0]
    position = source.find(b"\n")
    while position != -1:
        starts.append(position + 1)
        position = source.find(b"\n", position + 1)
    return starts


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _count(node, node_type: str) -> int:
    return sum(1 for item in _walk(node) if item.type == node_type)


def _language_for(language: str):
    if Language is None:
        return None
    if language == "js" and _javascript_grammar is not None:
        cached = getattr(_language_for, "_js", None)
        if cached is None:
            cached = Language(_javascript_grammar.language())
            _language_for._js = cached
        return cached
    if language in ("ts", "arkts") and _typescript_grammar is not None:
        cached = getattr(_language_for, "_ts", None)
        if cached is None:
            cached = Language(_typescript_grammar.language_typescript())
            _language_for._ts = cached
        return cached
    return None


def _parser_for(language: str):
    """A fresh Parser per parse.

    Reusing one Parser across parses segfaulted on a real 88-call ArkTS file
    (tree-sitter 0.26 / tree-sitter-typescript 0.23) when the previous Tree had
    already been collected. A new Parser over the cached Language is cheap and
    avoids that binding-level crash; the input is untrusted code either way.
    """
    language_object = _language_for(language)
    return Parser(language_object) if language_object is not None else None


def frontend(unit: SourceUnit) -> FrontendFile:
    """Parse one unit and report what the grammar actually recovered."""
    parser = _parser_for(unit.language)
    if parser is None:
        return FrontendFile(unit.path, unit.language, "unsupported", 0, 0)
    source = unit.text.encode("utf-8")
    tree = parser.parse(source)
    errors = _count(tree.root_node, "ERROR") + _count(tree.root_node, "MISSING")
    status = "complete" if errors == 0 and not tree.root_node.has_error else "partial"
    return FrontendFile(unit.path, unit.language, status, errors,
                        _count(tree.root_node, "call_expression"), b"", source)


def _enclosing_function(node):
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def _scope_text(call, source: bytes) -> str:
    scope = _enclosing_function(call)
    return _text(scope, source) if scope is not None else source.decode("utf-8", "replace")


def _tainted_names(scope_text: str) -> List[str]:
    """Local variables assigned from ``want.parameters`` in the same function."""
    names: List[str] = []
    pattern = re.compile(
        r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*([^;\n]+)")
    for match in pattern.finditer(scope_text):
        if _SOURCE.search(match.group(2)):
            names.append(match.group(1))
    # Destructuring: `const { path } = want.parameters;`
    for match in re.finditer(
            r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*want\s*\.\s*parameters", scope_text):
        names.extend(part.strip().split(":")[0].strip()
                     for part in match.group(1).split(",") if part.strip())
    return [name for name in names if name]


def _mentions(text: str, names: List[str]) -> bool:
    return any(re.search(r"\b" + re.escape(name) + r"\b", text) for name in names)


def _inline_source(text: str) -> bool:
    """``want.parameters`` used directly in an expression, not via a local."""
    return _SOURCE.search(text) is not None


def _path_guarded(scope_text: str, names: List[str], inline: bool = False) -> bool:
    for match in re.finditer(r"if\s*\(([^)]{0,400})\)", scope_text):
        condition = match.group(1)
        if not _PATH_PREDICATE.search(condition):
            continue
        if (names and _mentions(condition, names)) or (inline and _inline_source(condition)):
            return True
    return False


def _origin_guarded(scope_text: str) -> bool:
    for match in re.finditer(r"if\s*\(([^)]{0,400})\)", scope_text):
        condition = match.group(1)
        if _ORIGIN_PREDICATE.search(condition) and _COMPARE.search(condition):
            return True
    return False


def _callee_text(call, source: bytes) -> str:
    function = call.child_by_field_name("function")
    return _text(function, source).strip() if function is not None else ""


def _arguments_text(call, source: bytes) -> str:
    arguments = call.child_by_field_name("arguments")
    return _text(arguments, source) if arguments is not None else ""


def _exported_ability_bases(node, source: bytes) -> List[str]:
    heritage = node.child_by_field_name("class_heritage") if hasattr(node, "child_by_field_name") else None
    if heritage is None:
        for child in node.children:
            if child.type == "class_heritage":
                heritage = child
                break
    if heritage is None:
        return []
    return _ABILITY_BASES.findall(_text(heritage, source))


def _split_top_level(text: str) -> List[str]:
    """Split on commas that are not inside brackets or string literals."""
    parts: List[str] = []
    depth = 0
    quote = ""
    current = ""
    for character in text:
        if quote:
            current += character
            if character == quote:
                quote = ""
            continue
        if character in "'\"`":
            quote = character
            current += character
        elif character in "([{<":
            depth += 1
            current += character
        elif character in ")]}>":
            depth = max(0, depth - 1)
            current += character
        elif character == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += character
    if current.strip():
        parts.append(current)
    return [part.strip() for part in parts if part.strip()]


def _parameter_names(parameters, source: bytes) -> List[str]:
    text = _text(parameters, source).strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    names: List[str] = []
    for part in _split_top_level(text):
        match = re.match(r"\s*(?:\.\.\.)?\s*([A-Za-z_$][\w$]*)", part)
        if match:
            names.append(match.group(1))
    return names


def _function_index(root, source: bytes) -> Dict[str, Tuple[object, List[str]]]:
    """Same-file function declarations, one hop only.

    Methods and arrow functions are not indexed: their names are less reliable
    without a symbol table, and the first bounded version would rather miss
    than guess.
    """
    index: Dict[str, Tuple[object, List[str]]] = {}
    for node in _walk(root):
        if node.type != "function_declaration":
            continue
        name = node.child_by_field_name("name")
        parameters = node.child_by_field_name("parameters")
        if name is None or parameters is None:
            continue
        index[_text(name, source).strip()] = (
            node, _parameter_names(parameters, source))
    return index


def _class_method_names(node, source: bytes) -> List[str]:
    names: List[str] = []
    for item in _walk(node):
        if item.type == "method_definition":
            name = item.child_by_field_name("name")
            if name is not None:
                names.append(_text(name, source))
    return names


def _module_key(module: str) -> str:
    """Canonical N-API module key.

    ``requireNapi('foo')`` and ``import ... from 'libfoo.so'`` name the same
    library through different spellings; the loader's own convention is
    ``libfoo.z.so``. Keying on the stem keeps the binding map usable without
    guessing which file on disk corresponds to which import.
    """
    key = module.strip().strip("'\"").lower()
    for suffix in (".z.so", ".so"):
        if key.endswith(suffix):
            key = key[:-len(suffix)]
            break
    if key.startswith("lib"):
        key = key[3:]
    return key


def _signature_name(node, source: bytes) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(name, source).strip()
    for child in node.children:
        if child.type == "identifier":
            return _text(child, source).strip()
    return ""


def _formal_parameters(parameters, source: bytes) -> Tuple[BindingParameter, ...]:
    result: List[BindingParameter] = []
    for item in parameters.named_children:
        if item.type not in ("required_parameter", "optional_parameter"):
            continue
        pattern = item.child_by_field_name("pattern")
        name = _text(pattern, source).strip() if pattern is not None else ""
        annotation = item.child_by_field_name("type")
        type_text = _text(annotation, source).strip().lstrip(":").strip() \
            if annotation is not None else ""
        result.append(BindingParameter(name, type_text))
    return tuple(result)


def _signature_parameters(node, source: bytes) -> Tuple[BindingParameter, ...]:
    parameters = node.child_by_field_name("parameters")
    if parameters is None:
        for child in node.children:
            if child.type == "formal_parameters":
                parameters = child
                break
    if parameters is None:
        return ()
    return _formal_parameters(parameters, source)


def _function_type_parameters(node, source: bytes) -> Tuple[BindingParameter, ...]:
    """Parameters of a ``const f: (a: number) => T`` declaration.

    The DevEco N-API template writes its type file this way instead of
    ``declare module``, so the ``formal_parameters`` sit under
    ``type_annotation`` -> ``function_type`` rather than on the declarator.
    """
    for child in _walk(node):
        if child.type == "function_type":
            for item in child.children:
                if item.type == "formal_parameters":
                    return _formal_parameters(item, source)
    return ()


_TYPES_DIRECTORY = re.compile(
    r"(?:^|/)cpp/types/(lib[^/]+)/index\.d\.ts$")


def _types_directory_module(path: str) -> str:
    """Module name implied by the DevEco ``cpp/types/lib<name>/index.d.ts`` path.

    This is the layout the N-API template generates; the type file itself does
    not spell the module name. Anything outside that exact layout is left
    unmapped rather than inferred from the directory name.
    """
    match = _TYPES_DIRECTORY.search(path)
    return match.group(1) + ".so" if match else ""


def _path_bound_functions(root, source: bytes) -> List[Tuple[str, Tuple[
        BindingParameter, ...]]]:
    """Top-level exported functions in a module-shaped ``.d.ts``."""
    result: List[Tuple[str, Tuple[BindingParameter, ...]]] = []
    for node in _walk(root):
        if node.type == "function_signature":
            name = _signature_name(node, source)
            if name:
                result.append((name, _signature_parameters(node, source)))
            continue
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None or name_node.type != "identifier":
            continue
        parameters = _function_type_parameters(node, source)
        if not parameters and not any(
                child.type == "function_type" for child in _walk(node)):
            continue
        result.append((_text(name_node, source).strip(), parameters))
    return result


def _native_bindings(units: Tuple[SourceUnit, ...]) -> Tuple[
        Dict[str, Dict[str, BindingFunction]], int, int]:
    """The N-API binding map, from two declaration shapes in the scan's ``.d.ts``.

    ``declare module 'lib*.so' { export function ... }`` is read as written.
    The DevEco template's ``cpp/types/lib<name>/index.d.ts`` (which names the
    module only via its path) is accepted for that exact layout. A module with
    no declaration is not guessed from its name, and a declaration is a type
    statement, not a statement that the native side checks anything.
    """
    bindings: Dict[str, Dict[str, BindingFunction]] = {}
    signatures = 0
    for unit in units:
        if not unit.path.endswith(".d.ts"):
            continue
        parser = _parser_for(unit.language)
        if parser is None:
            continue
        source = unit.text.encode("utf-8")
        root = parser.parse(source).root_node
        declared = 0
        for node in _walk(root):
            if node.type != "module":
                continue
            module_strings = [child for child in node.children
                              if child.type == "string"]
            if not module_strings:
                continue
            module_name = _text(module_strings[0], source).strip().strip("'\"")
            if not module_name.endswith(".so"):
                continue
            declared += 1
            table = bindings.setdefault(_module_key(module_name), {})
            for child in _walk(node):
                if child.type != "function_signature":
                    continue
                name = _signature_name(child, source)
                if not name:
                    continue
                signatures += 1
                if name in table:
                    # Overloads: the first signature is kept; the call's
                    # argument positions against the others are not evaluated.
                    continue
                table[name] = BindingFunction(
                    module_name, name, _signature_parameters(child, source))
        if declared:
            continue
        # The DevEco N-API template's `cpp/types/lib<name>/index.d.ts` names
        # the module only through its path. Only that exact layout is used;
        # no other directory name is inferred to be a library.
        module_name = _types_directory_module(unit.path)
        if not module_name:
            continue
        table = bindings.setdefault(_module_key(module_name), {})
        for name, parameters in _path_bound_functions(root, source):
            if name in table:
                continue
            signatures += 1
            table[name] = BindingFunction(module_name, name, parameters)
    return bindings, len(bindings), signatures


def _native_imports(root, source: bytes) -> Dict[str, Tuple[str, Optional[str]]]:
    """Local names bound to a native module.

    Value is ``(module, member)``: ``member`` is the named import when the
    binding is ``import { fn } from 'libx.so'`` and ``None`` for a default or
    namespace import, where the member is written at the call site.
    ``import`` modules must end in ``.so``; ``requireNapi(...)`` is itself a
    native loader call, so its argument is accepted as written.
    """
    imports: Dict[str, Tuple[str, Optional[str]]] = {}
    for node in _walk(root):
        if node.type == "import_statement":
            module_strings = [child for child in node.children
                              if child.type == "string"]
            if not module_strings:
                continue
            module = _text(module_strings[-1], source).strip().strip("'\"")
            if not module.endswith(".so"):
                continue
            for child in node.children:
                if child.type != "import_clause":
                    continue
                for item in child.children:
                    if item.type == "identifier":
                        imports[_text(item, source).strip()] = (module, None)
                    elif item.type == "namespace_import":
                        names = [sub for sub in item.children
                                 if sub.type == "identifier"]
                        if names:
                            imports[_text(names[-1], source).strip()] = (module, None)
                    elif item.type == "named_imports":
                        for specifier in item.named_children:
                            if specifier.type != "import_specifier":
                                continue
                            names = [sub for sub in specifier.children
                                     if sub.type == "identifier"]
                            if names:
                                imports[_text(names[-1], source).strip()] = (
                                    module, _text(names[0], source).strip())
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            if value_node.type != "call_expression":
                continue
            callee = _callee_text(value_node, source)
            if callee != "requireNapi":
                continue
            arguments = value_node.child_by_field_name("arguments")
            if arguments is None or not arguments.named_children:
                continue
            module = _text(arguments.named_children[0], source).strip().strip("'\"")
            # `requireNapi` is an explicit native-module loader, so its argument
            # is taken as a module name even without the `.so` suffix that the
            # import form carries; the binding map still has to declare it.
            if not module:
                continue
            imports[_text(name_node, source).strip()] = (module, None)
    return imports


def _numeric_guarded(scope_text: str, names: List[str],
                     inline: bool = False) -> bool:
    """A same-function numeric predicate on the tainted value.

    Same bounded shape as ``_path_guarded``: an ``if (...)`` that mentions the
    tainted local (or, for an inline expression, ``want.parameters`` itself) and
    contains a numeric comparison or a numeric-domain test. Presence in the
    function is not dominance over the call; that distinction stays an
    obligation on the candidate, not an assertion here.
    """
    for match in re.finditer(r"if\s*\(([^)]{0,400})\)", scope_text):
        condition = match.group(1)
        if not _NUMBER_PREDICATE.search(condition):
            continue
        if (names and _mentions(condition, names)) or (inline and _inline_source(condition)):
            return True
    return False


def _analyze_file(unit: SourceUnit, frontend_file: FrontendFile,
                  counters: Dict[str, int],
                  bindings: Optional[Dict[str, Dict[str, BindingFunction]]] = None
                  ) -> List[Observation]:
    if frontend_file.status == "unsupported":
        return []
    observation_list: List[Observation] = []
    source = frontend_file.source
    line_starts = _line_starts(source)

    def line_at(offset):
        return bisect.bisect_right(line_starts, offset)

    # Re-parse to walk nodes; the frontend result keeps only counts.
    parser = _parser_for(unit.language)
    tree = parser.parse(source)
    root = tree.root_node

    calls = [node for node in _walk(root) if node.type == "call_expression"]
    counters["call_sites"] += len(calls)

    # `new Function(x)` is a separate node type; treat it like eval.
    for constructor in (node for node in _walk(root) if node.type == "new_expression"):
        name = constructor.child_by_field_name("constructor")
        if name is None or _text(name, source).strip() != "Function":
            continue
        arguments = _arguments_text(constructor, source)
        counters["eval_sites"] += 1
        if arguments.strip("()") and not re.fullmatch(
                r"\(\s*(['\"]).*\1\s*\)", arguments, re.S):
            observation_list.append(Observation(
                "ohscanner.js.dangerous_eval", line_at(constructor.start_byte),
                "new Function",
                "new Function() receives a non-literal body. Dynamic code "
                "generation is a candidate sink; attacker control is an "
                "obligation, not established here.", "CWE-95"))

    for call in calls:
        callee = _callee_text(call, source)
        arguments = _arguments_text(call, source)
        scope_text = _scope_text(call, source)
        names = _tainted_names(scope_text)
        line = line_at(call.start_byte)

        # dangerous_eval: a non-literal argument to eval/new Function.
        if callee.split(".")[-1] == "eval":
            counters["eval_sites"] += 1
            if arguments.strip("()") and not re.fullmatch(
                    r"\(\s*(['\"]).*\1\s*\)", arguments, re.S):
                observation_list.append(Observation(
                    "ohscanner.js.dangerous_eval", line, callee,
                    "eval() receives a non-literal value. Dynamic evaluation is a "
                    "candidate sink; whether the value is attacker-controlled is "
                    "an obligation, not established here.", "CWE-95"))
                continue

        # WebView bridge registration.
        if callee.endswith("registerJavaScriptProxy") or callee.endswith("javaScriptProxy"):
            counters["bridge_sites"] += 1
            if _origin_guarded(scope_text):
                counters["bridge_guarded"] += 1
            else:
                observation_list.append(Observation(
                    "ohscanner.oh.arkts.webview_bridge", line, callee,
                    "A JavaScript bridge is registered with no URL/origin "
                    "predicate in the same function. The object and its method "
                    "list are not enumerated, and the loaded page's trust is not "
                    "established; module/component facts are not read.",
                    "CWE-749", _BASE_OBLIGATIONS + (_ORIGIN_OBLIGATION,)))
            continue

        # Path sinks fed by want.parameters.
        if any(callee.endswith(sink) for sink in _PATH_SINKS):
            counters["path_sinks"] += 1
            inline = _inline_source(arguments)
            tainted = (names and _mentions(arguments, names)) or inline
            if tainted:
                if _path_guarded(scope_text, names, inline):
                    counters["path_guarded"] += 1
                else:
                    observation_list.append(Observation(
                        "ohscanner.js.path_taint", line, callee,
                        "A value derived from want.parameters reaches " + callee
                        + " with no path predicate in the same function. "
                        "Caller reachability and API-level sanitisation are "
                        "obligations.", "CWE-22"))

    # N-API boundary: a want.parameters-derived numeric argument to an export
    # of a lib*.so module. The binding map is built from the scan's .d.ts
    # declarations; an import whose module/export is not declared is counted as
    # unmapped rather than matched by name.
    imports = _native_imports(root, source)
    mappings = bindings or {}
    for call in calls:
        callee = _callee_text(call, source)
        head, _separator, member = callee.partition(".")
        bound = imports.get(head)
        if bound is None:
            continue
        module, imported_member = bound
        export_name = member or imported_member or ""
        if not export_name:
            continue
        counters["native_calls"] += 1
        function = mappings.get(_module_key(module), {}).get(export_name)
        if function is None:
            counters["native_unmapped"] += 1
            continue
        arguments_node = call.child_by_field_name("arguments")
        argument_nodes = (list(arguments_node.named_children)
                          if arguments_node is not None else [])
        scope_text = _scope_text(call, source)
        tainted_names = _tainted_names(scope_text)
        positions = []
        for position, parameter in enumerate(function.parameters):
            if "number" not in parameter.type_text:
                continue
            if position >= len(argument_nodes):
                break
            argument_text = _text(argument_nodes[position], source)
            inline = _inline_source(argument_text)
            if inline or _mentions(argument_text, tainted_names):
                positions.append((position, parameter.name, inline))
        if not positions:
            continue
        inline_any = any(item[2] for item in positions)
        if _numeric_guarded(scope_text, tainted_names, inline_any):
            counters["native_guarded"] += 1
            continue
        parameters_text = ", ".join(
            item[1] or ("argument " + str(item[0] + 1)) for item in positions)
        observation_list.append(Observation(
            "ohscanner.oh.native_bridge", line_at(call.start_byte),
            module + ":" + export_name,
            "A want.parameters-derived value reaches numeric parameter(s) "
            + parameters_text + " of " + module + ":" + export_name
            + " with no numeric range or domain predicate in the same "
            "function. "
            "The .d.ts type is a declaration, not a check; whether the N-API "
            "side validates the value is an obligation.", "CWE-20",
            _BASE_OBLIGATIONS + (_NATIVE_OBLIGATION,)))

    # One-hop same-file propagation: a helper parameter receives a
    # want.parameters-derived value at a call site, and the helper passes that
    # parameter to a path sink. Deeper chains and methods are out of scope.
    index = _function_index(root, source)
    tainted_parameters: Dict[str, set] = {name: set() for name in index}
    for call in calls:
        callee = _callee_text(call, source)
        if callee not in index:
            continue
        _target, parameter_names = index[callee]
        arguments_node = call.child_by_field_name("arguments")
        if arguments_node is None:
            continue
        caller_names = _tainted_names(_scope_text(call, source))
        for position, argument in enumerate(arguments_node.named_children):
            if position >= len(parameter_names):
                break
            argument_text = _text(argument, source)
            if _inline_source(argument_text) or _mentions(argument_text, caller_names):
                tainted_parameters[callee].add(parameter_names[position])
    for callee, (function_node, parameter_names) in index.items():
        tainted = tainted_parameters[callee]
        if not tainted:
            continue
        for call in _walk(function_node):
            if call.type != "call_expression":
                continue
            sink = _callee_text(call, source)
            if not any(sink.endswith(item) for item in _PATH_SINKS):
                continue
            arguments_text = _arguments_text(call, source)
            used = [name for name in parameter_names if name in tainted
                    and re.search(r"\b" + re.escape(name) + r"\b", arguments_text)]
            if not used:
                continue
            if _path_guarded(_scope_text(call, source), used):
                continue
            observation_list.append(Observation(
                "ohscanner.js.path_taint", line_at(call.start_byte),
                sink + " <- " + callee,
                "A same-file caller passes a want.parameters-derived value into "
                + callee + "(); parameter " + ", ".join(used) + " reaches "
                + sink + " with no path predicate in the callee. One hop only; "
                "the call site's reachability is an obligation.", "CWE-22"))

    # Exported Ability/Extension classes reading want.parameters in a lifecycle
    # method and reaching a path sink.
    for node in _walk(root):
        if node.type != "class_declaration":
            continue
        bases = _exported_ability_bases(node, source)
        if not bases:
            continue
        counters["ability_classes"] += 1
        class_text = _text(node, source)
        if not _SOURCE.search(class_text):
            continue
        methods = _class_method_names(node, source)
        lifecycle = [name for name in methods if name in _LIFECYCLE_METHODS]
        if not lifecycle:
            continue
        names: List[str] = []
        source_present = True
        for match in re.finditer(
                r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*want\s*\.\s*parameters",
                class_text):
            names.append(match.group(1))
        inline = any(
            re.search(re.escape(sink) + r"\s*\([^;]{0,400}?" + _SOURCE.pattern,
                      class_text)
            for sink in _PATH_SINKS)
        if not names and not inline:
            continue
        sinks = [sink for sink in _PATH_SINKS if sink + "(" in class_text]
        if not sinks:
            continue
        if _path_guarded(class_text, names, inline):
            counters["ability_guarded"] += 1
            continue
        observation_list.append(Observation(
            "ohscanner.oh.arkts.component_exposure", line_at(node.start_byte),
            ", ".join(lifecycle),
            "An exported " + "/".join(sorted(set(bases))) + " reads "
            "want.parameters and reaches a path API (" + ", ".join(sorted(sinks))
            + ") without a path predicate. module.json5 export/permission state "
            "is not read; this is a candidate, not an exposure proof.",
            "CWE-862", _BASE_OBLIGATIONS + (_MANIFEST_OBLIGATION,)))

    return observation_list


class ArkTsJsInterfaceDetector:
    detector_id = "ohscanner.oh.arkts_js"
    version = "0.3.0"
    supported_languages = ("js", "ts", "arkts")
    required_facts = ()
    ast_scope = "per_file"

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        applicable = tuple(u for u in units if u.language in self.supported_languages)
        if not applicable:
            return DetectorRun(
                self.detector_id, self.version, "blocked",
                limitations=("No .js/.ts/.ets unit in scope; the detector ran no "
                             "frontend and claims nothing about other languages.",))
        missing = sorted({u.language for u in applicable
                          if LANGUAGE_MODULE_STATUS.get(u.language) != "available"})
        if missing:
            return DetectorRun(
                self.detector_id, self.version, "blocked",
                limitations=("Tree-sitter grammar not installed for: " + ", ".join(missing)
                             + ". Those languages are unsupported here; zero findings "
                               "would be a coverage statement, not a result.",))

        counters: Dict[str, int] = {
            "call_sites": 0, "eval_sites": 0, "bridge_sites": 0,
            "bridge_guarded": 0, "path_sinks": 0, "path_guarded": 0,
            "ability_classes": 0, "ability_guarded": 0,
            "native_calls": 0, "native_unmapped": 0, "native_guarded": 0,
        }
        bindings, native_modules, native_signatures = _native_bindings(applicable)
        findings: List[DetectorFinding] = []
        outcomes: List[Tuple[str, str]] = []
        statuses: List[str] = []
        for unit in sorted(applicable, key=lambda item: item.path):
            frontend_file = frontend(unit)
            statuses.append(frontend_file.status)
            outcomes.append((unit.path, frontend_file.status))
            for observation in _analyze_file(unit, frontend_file, counters,
                                             bindings):
                findings.append(DetectorFinding(
                    file=unit.path, line=observation.line,
                    symbol=observation.symbol, rule_id=observation.rule_id,
                    message=observation.message, evidence_type="syntax",
                    candidate_cwe=observation.cwe,
                    evidence_obligations=observation.obligations))

        findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
        complete = sum(1 for status in statuses if status == "complete")
        partial = sum(1 for status in statuses if status == "partial")
        limitations = (
            "ArkTS/JS frontend: " + str(len(statuses)) + " file(s) parsed; "
            + str(complete) + " complete, " + str(partial) + " partial, "
            + str(len(statuses) - complete - partial) + " unsupported; "
            + str(counters["call_sites"]) + " call site(s) recovered.",
            "ArkTS `struct` and ArkTS decorators are outside the TypeScript "
            "grammar; a partial parse is reported for every such file and no "
            "component/decorator semantics are claimed from it. Only recovered "
            "call/class/property structure is read.",
            "No CFG; taint crosses one same-file function hop at most "
            "(function declarations only, not methods or arrow functions). "
            "No manifest (module.json5) parsing, installed-package or "
            "page-origin facts. Guard detection is a "
            "same-function `if (...)` predicate containing the tainted name; it "
            "is a heuristic boundary on the candidate, not dominance proof.",
            "Ability surface: " + str(counters["ability_classes"])
            + " exported Ability/Extension class(es) seen; export/permission "
              "state is an obligation, never inferred from the class.",
            "WebView bridge coverage: " + str(counters["bridge_sites"])
            + " registration(s), " + str(counters["bridge_guarded"])
            + " with an origin predicate in the same function.",
            "Taint coverage: " + str(counters["path_sinks"]) + " path sink(s), "
            + str(counters["path_guarded"]) + " behind a same-function path "
              "predicate; " + str(counters["eval_sites"]) + " eval site(s).",
            "N-API binding map: " + str(native_modules) + " .so module(s) and "
            + str(native_signatures) + " function signature(s) declared in the "
              "scan's .d.ts files; " + str(counters["native_calls"])
            + " call site(s) into lib*.so imports, "
            + str(counters["native_unmapped"]) + " unmapped (module or export "
              "not declared in this scan), " + str(counters["native_guarded"])
            + " behind a same-function numeric predicate. A declaration is a "
              "type statement, not a runtime check.",
            "All output is candidate/unassessed; no candidate is a vulnerability "
            "finding and no reachability is established by this frontend.",
        )
        return DetectorRun(
            self.detector_id, self.version, "completed",
            tuple(unit.path for unit in sorted(applicable, key=lambda item: item.path)),
            tuple(findings), limitations, tuple(outcomes))
