"""Bounded, source-bound cross-file facts for Ark Runtime semantic passes.

The bundle is deliberately finite: canonical paths, source SHA-256 values and
include edges are recorded explicitly. Missing includes, ambiguous targets,
unsupported host loops and unresolved helper bodies remain limitations. These
facts support local candidate analysis; they do not prove preprocessing,
ownership, runtime types, path feasibility or product impact.
"""
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import PurePosixPath
import re

from .cross_helper import build_helper_contracts
from .model import AnalysisBudget
from .runtime_ir import build_graph
from .syntax import parse_functions, walk


_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+(?P<kind>[<"])(?P<path>[^>"]+)[>"]', re.MULTILINE)
_DEFINE_RE = re.compile(r'^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)(?P<params>\([^)]*\))?', re.MULTILINE)


@dataclass(frozen=True)
class SourceIdentity:
    path: str
    sha256: str
    git_blob_oid: str
    parse_status: str


@dataclass(frozen=True, order=True)
class IncludeFact:
    source: str
    target: str
    written: str
    kind: str
    resolved_path: str = ''
    status: str = 'unknown'


@dataclass(frozen=True)
class MacroFact:
    name: str
    path: str
    sha256: str
    arity: int
    source_line: int
    status: str = 'bound'


@dataclass(frozen=True)
class AliasFact:
    function: str
    source_path: str
    source_sha256: str
    alias: str
    original: str
    kind: str
    status: str


@dataclass(frozen=True)
class CastFact:
    function: str
    source_path: str
    source_sha256: str
    written: str
    inner: str
    cast_kind: str
    status: str


@dataclass(frozen=True)
class HelperSummaryFact:
    function: str
    source_path: str
    source_sha256: str
    parameter_index: int
    normalized_type: str
    helper_hash: str
    effects: tuple
    status: str


@dataclass(frozen=True)
class LoopBackedgeFact:
    function: str
    source_path: str
    source_sha256: str
    begin_instruction: int
    end_instruction: int
    label_identity: str
    source_start_byte: int
    source_end_byte: int
    status: str = 'bounded'


@dataclass(frozen=True)
class CrossFileFactBundle:
    schema_version: int
    sources: tuple
    include_edges: tuple
    macro_facts: tuple
    alias_facts: tuple
    cast_facts: tuple
    helper_facts: tuple
    loop_backedges: tuple
    limitations: tuple

    def to_dict(self):
        return asdict(self)

    def source_units_for(self, root):
        root = _canonical_path(root)
        allowed = set(self._closure.get(root, ()))
        return tuple(unit for unit in self._units if unit.path in allowed)

    def limitations_for(self, root):
        root = _canonical_path(root)
        prefix = root + ':'
        return tuple(item for item in self.limitations if item.startswith(prefix))


_CROSS_FILE_FACT_BUNDLE_PRIVATE = ('_units', '_closure')


def _canonical_path(path):
    if not isinstance(path, str) or not path or '\\' in path:
        raise ValueError('non_canonical_source_path')
    value = PurePosixPath(path)
    if value.is_absolute() or any(part in ('', '.', '..') for part in value.parts):
        raise ValueError('non_canonical_source_path')
    return value.as_posix()


def _git_blob_oid(raw):
    from hashlib import sha1
    return sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()


def _include_target(root, written, kind):
    if kind == '"':
        parent = PurePosixPath(root).parent
        value = PurePosixPath(written)
        if value.is_absolute():
            return None
        combined = parent / value
        parts = []
        for part in combined.parts:
            if part == '..':
                if not parts:
                    return None
                parts.pop()
            elif part not in ('', '.'):
                parts.append(part)
        return _canonical_path('/'.join(parts))
    if '\\' in written or written.startswith('/') or '..' in PurePosixPath(written).parts:
        return None
    return _canonical_path(written)


def _extract_macros(unit):
    facts = []
    lines = unit.text.splitlines()
    for index, line in enumerate(lines, 1):
        match = _DEFINE_RE.match(line)
        if match is None:
            continue
        params = match.group('params') or ''
        arity = len([item for item in params.strip('()').split(',') if item.strip()]) if params else 0
        facts.append(MacroFact(match.group('name'), unit.path, unit.sha256, arity, index))
    return tuple(facts)


def _alias_facts(fn, path, source_hash):
    facts = []
    for node in walk(fn.body):
        if node.type == 'init_declarator':
            declarator = node.child_by_field_name('declarator')
            value = node.child_by_field_name('value')
            if declarator is None or value is None:
                continue
            root = value
            cast_kind = 'direct'
            while root.type in ('parenthesized_expression', 'pointer_expression') and root.named_children:
                root = root.named_children[-1]
            if root.type == 'cast_expression':
                inner = root.child_by_field_name('value')
                if inner is None and root.named_children:
                    inner = root.named_children[-1]
                if inner is not None:
                    root = inner
                cast_kind = 'cast'
            if root.type != 'identifier':
                continue
            left = declarator
            while left.type in ('pointer_declarator', 'parenthesized_declarator') and left.named_children:
                left = left.named_children[-1]
            if left.type not in ('identifier', 'field_identifier'):
                continue
            left_binding = fn.resolve(fn.text(left), left)
            right_binding = fn.resolve(fn.text(root), root)
            status = 'identity_preserving' if left_binding and right_binding else 'unknown'
            facts.append(AliasFact(fn.qualified_name, path, source_hash, fn.text(left),
                                   fn.text(root), cast_kind, status))
    return tuple(facts)


def _cast_facts(fn, path, source_hash):
    facts = []
    for node in walk(fn.body):
        written = ''
        inner_node = None
        kind = ''
        if node.type == 'cast_expression':
            value = node.child_by_field_name('value')
            if value is None and node.named_children:
                value = node.named_children[-1]
            written = fn.text(node)
            inner_node = value
            kind = 'cpp_cast'
        elif node.type == 'call_expression' and fn.call_name(node) in (
                'const_cast', 'dynamic_cast', 'reinterpret_cast', 'static_cast'):
            args = fn.arguments(node)
            if len(args) != 1:
                continue
            written = fn.text(node)
            inner_node = args[0]
            kind = fn.call_name(node)
        else:
            continue
        if inner_node is None:
            status = 'unknown'
            inner = ''
        else:
            inner = fn.text(inner_node)
            root = inner_node
            while root.type in ('parenthesized_expression', 'pointer_expression') and root.named_children:
                root = root.named_children[-1]
            status = ('identity_preserving' if kind in ('cpp_cast', 'const_cast', 'static_cast')
                      and root.type == 'identifier' and fn.resolve(fn.text(root), root) is not None
                      else 'unknown')
        facts.append(CastFact(fn.qualified_name, path, source_hash, written, inner, kind, status))
    return tuple(facts)


def build_cross_file_facts(units, *, budget=None, max_include_depth=8,
                           max_files=128, max_total_bytes=2 * 1024 * 1024):
    budget = budget or AnalysisBudget()
    normalized = []
    seen = set()
    total_bytes = 0
    limitations = []
    for unit in sorted(tuple(units), key=lambda item: item.path):
        path = _canonical_path(unit.path)
        if path in seen:
            raise ValueError('duplicate_source_path:' + path)
        seen.add(path)
        raw = unit.text.encode('utf-8')
        total_bytes += len(raw)
        if total_bytes > max_total_bytes or len(normalized) >= max_files:
            limitations.append(path + ':cross_file_fact_budget_exhausted')
            continue
        digest = sha256(raw).hexdigest()
        if digest != unit.sha256:
            raise ValueError('source_hash_mismatch:' + path)
        normalized.append(unit)
    by_path = {unit.path: unit for unit in normalized}
    edges = []
    closure = {}
    for root in sorted(by_path):
        pending = [(root, 0)]
        visited = set()
        while pending:
            current, depth = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            if depth >= max_include_depth:
                limitations.append(root + ':include_depth_budget_exhausted:' + current)
                continue
            source = by_path[current]
            for match in _INCLUDE_RE.finditer(source.text):
                written = match.group('path')
                target = _include_target(current, written, match.group('kind'))
                if target is None:
                    edges.append(IncludeFact(root, current, written, match.group('kind')))
                    limitations.append(root + ':include_target_non_canonical:' + current + ':' + written)
                    continue
                resolved = target if target in by_path else ''
                status = 'resolved' if resolved else 'source_unavailable'
                edges.append(IncludeFact(root, current, written, match.group('kind'), resolved, status))
                if resolved:
                    pending.append((resolved, depth + 1))
                else:
                    limitations.append(root + ':include_source_unavailable:' + current + ':' + target)
        closure[root] = tuple(sorted(visited))

    parsed = {}
    helper_inputs = []
    for unit in normalized:
        if unit.language != 'cpp':
            continue
        try:
            tree, functions = parse_functions(unit.text.encode('utf-8'))
        except (ValueError, RuntimeError, UnicodeError):
            limitations.append(unit.path + ':cross_file_parse_unavailable')
            continue
        if tree.root_node.has_error:
            limitations.append(unit.path + ':cross_file_parse_partial')
        parsed[unit.path] = functions
        helper_inputs.extend(functions)

    alias, casts, loops = [], [], []
    for path, functions in sorted(parsed.items()):
        unit = by_path[path]
        for fn in functions:
            alias.extend(_alias_facts(fn, path, unit.sha256))
            casts.extend(_cast_facts(fn, path, unit.sha256))
            try:
                graph = build_graph(fn, budget)
            except (ValueError, RuntimeError):
                limitations.append(path + ':loop_graph_budget_exhausted:' + fn.qualified_name)
                continue
            for edge in graph.loop_backedges:
                loops.append(LoopBackedgeFact(
                    fn.qualified_name, path, unit.sha256, edge.begin, edge.end,
                    edge.label_identity, edge.source_start_byte, edge.source_end_byte))
            limitations.extend(path + ':' + item for item in graph.limitations)

    contracts = build_helper_contracts(helper_inputs)
    contract_by_name = {}
    for contract in contracts:
        contract_by_name.setdefault(contract.qualified_name, []).append(contract)
    helpers = []
    for qualified_name, rows in sorted(contract_by_name.items()):
        if len(rows) != 1:
            continue
        item = rows[0]
        source = next((unit for path, functions in parsed.items()
                       if any(fn.qualified_name == qualified_name for fn in functions)
                       for unit in (by_path[path],)), None)
        if source is None:
            continue
        status = 'identity' if item.returns_parameter and not item.effects else (
            'effectful' if item.effects else 'not_identity')
        helpers.append(HelperSummaryFact(
            qualified_name, source.path, source.sha256, item.parameter_index,
            item.normalized_type, item.source_hash, item.effects, status))

    result = CrossFileFactBundle(
        1,
        tuple(SourceIdentity(unit.path, unit.sha256, _git_blob_oid(unit.text.encode('utf-8')),
                             unit.parse_status) for unit in normalized),
        tuple(sorted(set(edges))),
        tuple(fact for unit in normalized for fact in _extract_macros(unit)),
        tuple(alias), tuple(casts), tuple(helpers), tuple(loops),
        tuple(sorted(set(limitations))))
    object.__setattr__(result, '_units', tuple(normalized))
    object.__setattr__(result, '_closure', closure)
    return result
