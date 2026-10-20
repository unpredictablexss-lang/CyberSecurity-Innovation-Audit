"""D v1: bounded function-local material flow to explicitly public log operands.

Uses the existing Tree-sitter infrastructure; detailed statement parsing is private
because shared outlines expose no expression/binding facts. No global IR changes.
"""
import ast
import re
from collections import OrderedDict
from dataclasses import dataclass, field, replace
import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser
from src.parser.cpp_assignment_comma import recover_cpp_assignment_commas
from src.parser.syntax_normalize import normalize_empty_cpp_linkage_wrappers
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation
from .models import DEFAULT_SOURCE, SINKS, STATUS_RETURN_CALLS, SUPPORTED_SOURCE_MODELS, SensitiveSourceModel
from .property_keys import PROPERTY_READ_CALLS, PropertyKeyBindings
from .log_macro_roles import LogMacroRoles, enclosing_function
from .comma_values import BuiltinCommaProof

@dataclass(frozen=True)
class Flow:
    steps: tuple


@dataclass
class LocalState:
    values: dict
    types: dict
    shadows: set
    pointers: dict = field(default_factory=dict)

    def clone(self):
        return LocalState(dict(self.values), dict(self.types), set(self.shadows),dict(self.pointers))


@dataclass(frozen=True)
class PointerTarget:
    slot: object = None
    bound: bool = False


@dataclass(frozen=True)
class ExitState:
    kind: str
    line: int
    state: LocalState
    returned: tuple = ()


@dataclass(frozen=True)
class BlockResult:
    fallthrough_state: object
    exit_states: tuple = ()
    limitations: tuple = ()


def walk(n):
    yield n
    for c in n.named_children:
        yield from walk(c)


def looks_sensitive_name(value):
    # Match material names, not metadata or token-like substrings. OpenHarmony
    # uses spellings such as PassWordAnonymize and PreSharedKey; normalize the
    # former before looking for semantic phrases.
    words = [word.lower() for word in re.findall(
        r'[A-Z]+(?=[A-Z][a-z]|[^A-Za-z]|$)|[A-Z]?[a-z]+|[0-9]+', value)]
    if not words:
        return False
    normalized = []
    index = 0
    while index < len(words):
        if words[index:index + 2] == ['pass', 'word']:
            normalized.append('password')
            index += 2
        else:
            normalized.append(words[index])
            index += 1
    words = normalized

    # These suffixes identify scalar/label metadata, not the material itself.
    # This avoids treating WPS password IDs, byte lengths and asset tags as
    # passwords while preserving names such as passwordBytes/privateKeyData.
    if any(word in {
        'id', 'identifier', 'name', 'type', 'count', 'len', 'length', 'size',
        'status', 'code', 'tag', 'allowed',
    } for word in words):
        return False

    if any(word in {'password', 'passwd', 'secret', 'credential'} for word in words):
        return True
    if any(words[i:i + 2] in (
            ['private', 'key'], ['session', 'key'], ['client', 'key'],
            ['access', 'key'], ['signing', 'key'], ['encryption', 'key'],
            ['key', 'material'], ['key', 'bytes'], ['auth', 'header'],
            ['authorization', 'header']) for i in range(len(words) - 1)):
        return True
    if any(words[i:i + 3] == ['pre', 'shared', 'key']
           for i in range(len(words) - 2)):
        return True
    # API_KEY is a plausible secret field, while names such as
    # HTTP_API_KEY_FETCH describe an API entry point, not key material.
    if words == ['api', 'key'] or words == ['psk']:
        return True
    # A bare "token" is commonly an ID or protocol token in this codebase.
    # Retain explicit bearer/auth/access/refresh/session token names only.
    return any(words[i:i + 2] in (
        ['bearer', 'token'], ['auth', 'token'], ['access', 'token'],
        ['refresh', 'token'], ['session', 'token'], ['security', 'token'])
        for i in range(len(words) - 1))



def formats(value, default_privacy='private'):
    """(privacy, consumed operand indexes, conversion); unsupported => ValueError."""
    out, pos, arg = [], 0, 0
    pattern = re.compile(r'%(?:\{(public|private)\})?[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|ll|h|l|j|z|t|L)?([diuoxXfFeEgGaAcsp])')
    while pos < len(value):
        if value[pos] != '%':
            pos += 1
            continue
        if value[pos:pos+2] == '%%':
            pos += 2
            continue
        match = pattern.match(value, pos)
        if not match:
            raise ValueError('unsupported format conversion/positional operand')
        indexes = []
        for star in match.group(2, 3):
            if star == '*':
                indexes.append(arg); arg += 1
        indexes.append(arg); arg += 1
        out.append((match.group(1) or default_privacy, tuple(indexes), match.group(4)))
        pos = match.end()
    return out, arg


class CrossFileResolver:
    """Lazy, bounded C/C++ function-body lookup for sensitive call arguments.

    Resolution is syntax/name/arity based only. Overload, receiver, macro,
    include, and build identity are not inferred; ambiguity and budget exhaustion
    preserve an unresolved candidate.
    """
    MAX_CANDIDATE_UNITS = 24
    MAX_PARSED_UNITS = 128
    MAX_TOTAL_BYTES = 64 * 1024 * 1024
    MAX_UNIT_BYTES = 2 * 1024 * 1024
    CACHE_SIZE = 8

    def __init__(self, units, model, heuristic_sources=False, flow_factory=None):
        self.units = tuple(units)
        self.model = model
        self.heuristic_sources = heuristic_sources
        self.flow_factory = flow_factory
        self.cache = OrderedDict()
        self.call_stack = []
        self.parsed_units = 0
        self.parsed_bytes = 0
        self.limitations = set()
        self.partial_paths = set()

    @staticmethod
    def eligible(unit):
        return (unit.language in ('c', 'cpp')
                and not any(p.lower() in ('tests', 'test', 'unittest', 'mock', 'mocks', 'fuzztest')
                            for p in unit.path.split('/')))

    def flow(self, unit):
        cached = self.cache.pop(unit.path, None)
        if cached is not None:
            self.cache[unit.path] = cached
            return cached
        size = len(unit.text.encode('utf-8'))
        if (size > self.MAX_UNIT_BYTES
                or self.parsed_units >= self.MAX_PARSED_UNITS
                or self.parsed_bytes + size > self.MAX_TOTAL_BYTES):
            self.limitations.add(
                'cross-file function index reached its parse budget; unresolved calls remain candidates')
            return None
        self.parsed_units += 1
        self.parsed_bytes += size
        result = (self.flow_factory(unit, self) if self.flow_factory else
                  LocalFlow(unit, self.model, self.heuristic_sources, self))
        self.cache[unit.path] = result
        while len(self.cache) > self.CACHE_SIZE:
            self.cache.popitem(last=False)
        return result

    @staticmethod
    def writable_parameter(parameter, flow):
        # Tree-sitter may attach const to a sibling of the declarator. Inspect
        # the full parameter declaration so const pointees are never treated
        # as output parameters.
        declaration = flow.text(parameter)
        declarator = flow.text(parameter.child_by_field_name('declarator'))
        operators = list(re.finditer(r'[*&]', declarator))
        return len(operators) == 1 and not re.search(r'\bconst\b', declaration)

    @staticmethod
    def function_name(node, flow):
        d = node.child_by_field_name('declarator')
        fd = next((x for x in walk(d) if x.type == 'function_declarator'), None) if d else None
        name = flow.text(fd.child_by_field_name('declarator')) if fd else ''
        params = fd.child_by_field_name('parameters') if fd else None
        values = [p for p in params.named_children if p.type != 'variadic_parameter'] if params else []
        return name, fd, values

    def resolve(self, name, arity, caller_name, current_path):
        terminal = name.rsplit('::', 1)[-1]
        pattern = re.compile(r'(?<![A-Za-z_0-9])' + re.escape(terminal) + r'\s*\(')
        candidates = [u for u in self.units
                      if u.path != current_path and self.eligible(u)
                      and pattern.search(u.text)]
        if len(candidates) > self.MAX_CANDIDATE_UNITS:
            self.limitations.add(
                'cross-file helper lookup is ambiguous or exceeds candidate-unit budget: ' + name)
            return (), 'budget'

        matches = []
        incomplete = False
        for unit in candidates:
            if unit.parse_status in ('failed', 'not_run'):
                incomplete = True
                continue
            flow = self.flow(unit)
            if flow is None:
                incomplete = True
                continue
            flow_partial = unit.parse_status != 'complete' or flow.tree.root_node.has_error
            for definition in flow.function_nodes.values():
                for node in definition:
                    qname, fd, params = self.function_name(node, flow)
                    if not qname:
                        continue
                    if '::' in name:
                        if qname != name:
                            continue
                    elif qname.rsplit('::', 1)[-1] != terminal:
                        continue
                    if len(params) != arity:
                        continue
                    body = node.child_by_field_name('body')
                    if (fd is None or body is None
                            or node.has_error or body.has_error):
                        incomplete = True
                        continue
                    matches.append((flow, node, params, qname))
                    # A clean function subtree inside a partial translation
                    # unit is useful only as a may-summary. Callers must retain
                    # an unresolved candidate and the unit remains partial.
                    if flow_partial:
                        incomplete = True

        owner = caller_name.rsplit('::', 1)[0] if '::' in caller_name else ''
        if owner and '::' not in name:
            owner_matches = [row for row in matches
                             if row[3].rsplit('::', 1)[0] == owner]
            if owner_matches:
                matches = owner_matches
        if len(matches) == 1 and not incomplete:
            return tuple(matches), 'unique'
        if len(matches) == 1 and incomplete:
            self.limitations.add(
                'cross-file helper body is syntactically clean inside a partial translation unit; '
                'only a may-summary is used and call binding remains unknown: ' + name)
            return tuple(matches), 'partial'
        if incomplete:
            self.limitations.add(
                'cross-file helper lookup encountered partial definitions; overload/type identity remains unknown: '
                + name)
            return (), 'partial'
        if len(matches) > 1:
            self.limitations.add(
                'cross-file helper lookup found multiple same-name/arity definitions; call remains unresolved: '
                + name)
            return (), 'ambiguous'
        return (), 'missing'


class SensitiveExposureDetector:
    detector_id = 'ohscanner.data.sensitive_exposure'
    version = '0.21.17'
    supported_languages = ('c', 'cpp')
    required_facts = ('ast',)

    def __init__(self, model=None):
        # Explicit models keep research fixtures isolated. The default instance
        # dispatches only among source profiles whose exact repository and commit
        # have been reviewed; an unknown revision remains blocked.
        self.model = model if model is not None else DEFAULT_SOURCE
        self.models = (model,) if model is not None else SUPPORTED_SOURCE_MODELS

    def make_flow(self, unit, model=None, heuristic_sources=False, resolver=None):
        return LocalFlow(unit, model if model is not None else self.model,
                         heuristic_sources, resolver)

    def detect(self, context, units):
        model = next((candidate for candidate in self.models
                      if (context.request.repository, context.request.commit) ==
                      (candidate.repository, candidate.commit)), None)
        heuristic_sources = model is None
        if heuristic_sources:
            model = SensitiveSourceModel(
                'unreviewed/heuristic', '0' * 40, fields=(), non_sensitive_fields=(),
                output_calls=(), parameters=(),
                provenance='Unreviewed sensitive-name heuristic only; type, content and secret semantics are unknown. Candidate triage required.')
        findings, outcomes, limits = [], [], set()
        resolver = CrossFileResolver(
            units, model, heuristic_sources,
            flow_factory=lambda unit, active_resolver: self.make_flow(
                unit, model, heuristic_sources, active_resolver))
        # Runner can omit parser-ineligible units from `units`. This local
        # precision proof still requires the entire selected input to be known.
        outlines=context.shared_facts.get('ast',{})
        resolver.switch_join_scope_complete=all(
            u.parse_status=='complete' and outlines.get(u.path,{}).get('parse_status')=='complete'
            and not re.search(r'^\s*#',u.text,re.M) for u in context.units)
        if heuristic_sources:
            limits.add('No reviewed sensitive-source model for this repository/commit; heuristic candidates are incomplete and the scan is blocked.')
        for u in units:
            if u.language not in self.supported_languages:
                continue
            if any(p.lower() in ('tests', 'test', 'unittest', 'mock', 'mocks', 'fuzztest') for p in u.path.split('/')):
                outcomes.append((u.path, 'not_analyzed')); limits.add('Test/mock scope excluded, not evaluated as production exposure.')
                continue
            outline = context.shared_facts.get('ast', {}).get(u.path, {})
            if u.parse_status == 'failed' or outline.get('parse_status') == 'failed':
                outcomes.append((u.path, 'failed')); continue
            if u.parse_status == 'not_run' or not outline:
                outcomes.append((u.path, 'not_analyzed')); continue
            analysis = resolver.flow(u)
            if analysis is None:
                outcomes.append((u.path, 'partial'))
                limits.add(u.path + ': cross-file helper parse budget exhausted')
                continue
            rows = analysis.run()
            findings.extend(rows)
            partial = heuristic_sources or analysis.gaps or u.parse_status != 'complete' or outline.get('parse_status') != 'complete'
            outcomes.append((u.path, 'partial' if partial else 'complete'))
            limits.update(u.path+': '+s for s in analysis.gaps)
        outcomes=[(path,'partial' if path in resolver.partial_paths and state=='complete' else state)
                  for path,state in outcomes]
        limits.update(resolver.limitations)
        limits.update((
            'Candidate only: runtime log readers, production enablement and impact require independent review.',
            'Function-local syntax dependencies, not CFG/alias/full-program proof; no secret values recorded.',
            'Unsupported control-flow subtrees are scanned for may-flow call effects; branch feasibility remains unresolved.',
            'Model scope is exact repository/commit; receiver/typedef identity and include binding remain obligations.',
            'Detailed private Tree-sitter statements pending owner-approved shared expression facts; no new global frontend.',
            'Private/default-private sensitive operands retained as conditional candidates; runtime privacy configuration and reader exposure remain obligations.',
        ))
        merged={}
        for finding in findings:
            key=(finding.file,finding.line,finding.rule_id,finding.symbol or '',
                 finding.source_sha256)
            previous=merged.get(key)
            if previous is None:
                merged[key]=finding
            else:
                merged[key]=replace(
                    previous,
                    message=previous.message if finding.message in previous.message
                           else previous.message+' | '+finding.message,
                    evidence_obligations=tuple(dict.fromkeys(
                        previous.evidence_obligations+finding.evidence_obligations)))
        return DetectorRun(self.detector_id, self.version,
            'completed' if not heuristic_sources and outcomes and all(s == 'complete' for _, s in outcomes) else 'blocked',
            analyzed_files=tuple(p for p,s in outcomes if s in ('complete','partial')),
            findings=tuple(sorted(merged.values(), key=lambda f:(f.file,f.line,f.rule_id,f.symbol or ''))),
            file_outcomes=tuple(outcomes), limitations=tuple(sorted(limits)))


class LocalFlow:
    def __init__(self, unit, model, heuristic_sources=False, resolver=None):
        self.u, self.model = unit, model
        self.resolver = resolver
        self.heuristic_sources = heuristic_sources
        self.b = unit.text.encode()
        self.gaps, self.findings = set(), []
        self.external_gaps = set()
        self.source_sites, self.sink_sites = [], []
        lang = tree_sitter_c if unit.language == 'c' else tree_sitter_cpp
        parsed_bytes = normalize_empty_cpp_linkage_wrappers(self.b) if unit.language == 'cpp' else self.b
        self.tree = Parser(Language(lang.language())).parse(parsed_bytes)
        if unit.language == "cpp":
            self.tree = recover_cpp_assignment_commas(parsed_bytes, self.tree)
        if getattr(self.tree, "recovery_spans", ()):
            self.gaps.add("bounded assignment-comma syntax recovery preserves original offsets; operand types/overloads remain unproved")
        self.sinks = {s.name:s for s in SINKS if not s.files or unit.path in s.files}
        self.sinks.update({s.name:s for s in model.additional_sinks if not s.files or unit.path in s.files})
        self.output_calls = {
            item[0]: (item[1], item[2] if len(item) > 2 else 2)
            for item in model.output_calls
        }
        self.copy_calls = {
            item[0]: (item[1], item[2], item[3])
            for item in model.copy_calls
        }
        self.non_escaping_calls = frozenset(model.non_escaping_calls)
        self.fields = dict(model.fields)
        self.non_sensitive_fields = dict(model.non_sensitive_fields)
        self.shadows = set()
        self.pointers = {}
        self.function_definitions = set()
        self.function_bodies = {}
        self.function_nodes = {}
        self.call_stack = resolver.call_stack if resolver is not None else []
        self.call_results = {}
        self.comma_values = BuiltinCommaProof(self)
        self.property_keys = PropertyKeyBindings(self)
        self.property_key_roles = set()
        self.log_macro_roles = LogMacroRoles(self, formats)
        self.type_conflicts = set()
        for n in walk(self.tree.root_node):
            if n.type == 'function_definition':
                d=n.child_by_field_name('declarator')
                if d:
                    fd=next((x for x in walk(d) if x.type=='function_declarator'),None)
                    if fd:
                        fname=self.text(fd.child_by_field_name('declarator'))
                        self.function_definitions.add(fname)
                        self.function_bodies.setdefault(fname, []).append(n.child_by_field_name('body'))
                        self.function_nodes.setdefault(fname, []).append(n)
            if n.type in ('struct_specifier','class_specifier','type_definition'):
                if any(t in self.text(n) for t in self.fields):
                    self.type_conflicts.update(t for t in self.fields if re.search(r'\b'+re.escape(t)+r'\b',self.text(n)))
                    self.gaps.add('local type definition needs identity review')
            if n.type.startswith('preproc_'):
                self.gaps.add('preprocessor/build context not expanded')

    def text(self,n):
        return self.b[n.start_byte:n.end_byte].decode() if n else ''

    def name(self,n):
        if n is None:return ''
        if n.type in ('identifier','field_identifier'):return self.text(n)
        child=n.child_by_field_name('declarator')
        if child:return self.name(child)
        if n.type in ('parenthesized_declarator','reference_declarator') and len(n.named_children)==1:
            return self.name(n.named_children[0])
        return ''

    def source(self,desc,n):
        self.source_sites.append({'description':desc,'line':n.start_point[0]+1})
        return Flow((f'{self.u.path}:{n.start_point[0]+1} source {desc}',))

    def expr(self,n,env,types):
        if n is None:return ()
        if n.type=='pointer_expression' and self.text(n.child_by_field_name('operator'))=='*':
            target=self.pointer_target(n.child_by_field_name('argument'))
            if target.slot is not None and target.slot in env:
                return env[target.slot]
        if n.type=='identifier':
            ident=self.text(n)
            known=env.get(ident,())
            target=self.pointers.get(ident)
            if target and target.slot:
                known=tuple(dict.fromkeys(known+tuple(env.get(target.slot,()))))
            if known:return known
            if self.heuristic_sources and looks_sensitive_name(ident):
                self.gaps.add('unreviewed sensitive-name heuristic source; semantics unknown')
                return (self.source('heuristic suspected sensitive identifier '+ident,n),)
            return ()
        if n.type in ('string_literal','char_literal','number_literal','sizeof_expression','null','true','false'):return ()
        if n.type=='alignof_expression' and self.u.language=='cpp':
            # C++ alignof describes a type's alignment, not the operand's bytes.
            # In particular, a sensitive name inside decltype is not read here.
            return ()
        if n.type=='comma_expression':
            if self.comma_values.is_builtin(n):
                return self.addstep(self.expr(n.child_by_field_name('right'),env,types),
                    f'{n.start_point[0]+1} builtin comma final operand')
            self.gaps.add('comma operand type/binding unresolved; dependencies retained as may-flow')
        if n.type=='field_expression':
            obj=n.child_by_field_name('argument'); field=self.text(n.child_by_field_name('field'))
            root=self.text(obj)
            if self.heuristic_sources and looks_sensitive_name(field):
                self.gaps.add('unreviewed sensitive-field-name heuristic source; semantics unknown')
                return (self.source('heuristic suspected sensitive field '+field,n),)
            if root in types and types[root] in self.type_conflicts:
                type_name=types[root]
                self.gaps.add('shadowed sensitive record type identity unresolved; candidate retained')
                if self.fields.get(type_name)==field:
                    return (self.source(type_name+'.'+field+' with unresolved same-name type identity',n),)
                if field in self.non_sensitive_fields.get(type_name,()):
                    return ()
                if root in env:
                    return env[root]
                return ()
            member=self.lvalue(n,types)
            if member and member in env:
                return env[member]
            if root in types and self.fields.get(types[root]) == field:
                self.gaps.add('record binding and initialization require compiler facts')
                return (self.source(types[root]+'.'+field,n),)
            if root in types:
                return () # known nonmaterial field (len/iv/index), not whole object taint
            if root in env:
                self.gaps.add('unknown field/alias propagation; aggregate object taint is propagated as a may-flow')
                return env[root]
            return ()
        if n.type=='conditional_expression':
            self.gaps.add('conditional value is may-flow; no path feasibility proof')
            condition=n.child_by_field_name('condition')
            known=self.truth(condition)
            branches=('consequence',) if known is True else ('alternative',) if known is False else ('consequence','alternative')
            return tuple(v for field in branches for v in self.expr(n.child_by_field_name(field),env,types))
        if n.type=='lambda_expression':
            self.gaps.add('lambda body/capture value not analyzed');return ()
        if n.type=='assignment_expression':
            right=self.expr(n.child_by_field_name('right'),env,types)
            if self.text(n.child_by_field_name('operator'))=='=':return right
            # Compound assignment reads the old destination as well as the RHS.
            # Its value can feed another assignment or a log argument directly.
            left=self.expr(n.child_by_field_name('left'),env,types)
            return tuple(dict.fromkeys(left+right))
        if n.type=='binary_expression':
            op=self.text(n.child_by_field_name('operator'))
            if op in ('==','!=','<','>','<=','>=','&&','||'):return ()
        if n.type=='unary_expression' and self.text(n).lstrip().startswith('!'):return ()
        if n.type=='call_expression':
            if n.id in self.call_results:
                return self.call_results[n.id]
            if self.cpp_pointer_cast(n):
                return tuple(flow for arg in n.child_by_field_name('arguments').named_children
                             for flow in self.expr(arg,env,types))
            function=n.child_by_field_name('function')
            fn=self.text(function)
            args=n.child_by_field_name('arguments')
            # Only a directly declared std::string local value is modeled.
            # Pointer/reference aliases, arbitrary same-name methods and inferred
            # receiver types need separate binding evidence.
            if (function is not None and function.type=='field_expression'
                    and self.text(function.child_by_field_name('operator'))=='.'
                    and self.text(function.child_by_field_name('field'))=='c_str'
                    and args is not None and not args.named_children):
                receiver=function.child_by_field_name('argument')
                if (receiver is not None and receiver.type=='identifier'
                        and types.get(self.text(receiver))=='std::string'):
                    flows=self.expr(receiver,env,types)
                    if flows:
                        self.gaps.add('std::string c_str receiver dependency is syntax-bound; compiler type identity remains unresolved')
                    return self.addstep(flows,
                        f'{n.start_point[0]+1} std::string receiver {self.text(receiver)}.c_str()')
            if (fn in STATUS_RETURN_CALLS and fn not in self.shadows
                    and fn not in self.function_definitions):
                self.gaps.add('modeled status-return API; argument escape remains a candidate: '+fn)
                return ()
            if self.heuristic_sources and looks_sensitive_name(fn):
                self.gaps.add('unreviewed sensitive-API-name heuristic source; return semantics unknown')
                return (self.source('heuristic suspected sensitive-return API '+fn,n),)
            if fn in ('strlen','strnlen','strnlen_s','wcslen') and fn not in self.function_definitions and fn not in self.shadows:
                return () # A scalar length is not the sensitive material itself.
            if fn not in self.shadows and fn not in self.function_definitions and (fn in self.output_calls or fn in self.copy_calls or fn in ('memcpy_s','strcpy_s','snprintf','snprintf_s')):
                return () # modeled return is a status/count, not the output buffer
            vals=tuple(v for a in (args.named_children if args else []) for v in self.expr(a,env,types))
            # Unknown transform is not a sanitizer. Retain a tentative dependency and gap.
            if vals:self.gaps.add('unresolved transform/call '+fn)
            return vals
        return tuple(v for c in n.named_children for v in self.expr(c,env,types))

    def addstep(self,flows,text):
        return tuple(Flow(f.steps+(text,)) for f in flows)

    @staticmethod
    def store_value(env, destination, flows):
        values=tuple(dict.fromkeys(flows))
        env[destination]=values
        if '.' in destination:
            root=destination.split('.',1)[0]
            env[root]=tuple(dict.fromkeys(tuple(env.get(root,()))+values))

    def literal(self,n):
        if n.type=='concatenated_string':
            return ''.join(self.literal(x) for x in n.named_children)
        if n.type!='string_literal':raise ValueError('nonliteral format')
        value=ast.literal_eval(self.text(n))
        if not isinstance(value,str):raise ValueError('nonstring format')
        return value

    def emit_unresolved_escape(self,fn,args,env,types,node,fnname,reason):
        flows=tuple(dict.fromkeys(flow for arg in args
                                  for flow in self.expr(arg,env,types)))
        if not flows:return
        self.emit_unresolved_flows(fn,node,fnname,flows,reason)

    def emit_unresolved_flows(self,fn,node,fnname,flows,reason,binding_kind='callee_binding',event='call'):
        if not flows:return
        line=node.start_point[0]+1
        traces=sorted(set(' -> '.join(flow.steps+(f'{line} unresolved {event} {fn}',))
                          for flow in flows))
        binding_question=(
            'Resolve the exact overload, receiver, and implementation for '+fn+'.'
            if binding_kind=='callee_binding' else
            'Resolve the format string, operand mapping, and output destination for '+fn+'.'
            if binding_kind=='format_resolution' else
            'Resolve pointer/member aliases and the exact destination object written by '+fn+'.')
        self.findings.append(DetectorFinding(
            file=self.u.path,line=line,symbol=fnname,
            rule_id='data.sensitive.unresolved-escape',candidate_cwe=None,
            evidence_type='syntax',source_sha256=self.u.sha256,
            message='Candidate sensitive-data escape with unresolved binding: '
                    +reason+'; path='+' | '.join(traces),
            evidence_obligations=(
                EvidenceObligation(binding_kind,binding_question),
                EvidenceObligation('sink_behavior',
                    'Determine whether the unresolved destination exposes or forwards material.' if event=='material write' else
                    'Determine whether the callee logs, serializes, stores, or safely transforms the sensitive value.'),
                EvidenceObligation('runtime_log_visibility','No log exposure or reader reachability is established by this call alone.'),
                EvidenceObligation('security_impact','Establish recoverable sensitive material and concrete impact independently.'),
            )))

    def expand_tainted_call(self,fn,args,env,types,call_line,call_node=None,fnname=''):
        """Summarize a bounded same-file or uniquely resolved cross-file helper."""
        arg_flows=[self.expr(arg,env,types) for arg in args]

        matches=[]
        local_definitions=self.function_nodes.get(fn,())
        for definition in local_definitions:
            _,fd,parameters=CrossFileResolver.function_name(definition,self)
            if fd is not None and len(parameters)==len(args):
                matches.append((self,definition,parameters,fn))
        cross_file=False
        partial_binding=False
        if not local_definitions and self.resolver is not None:
            matches,status=self.resolver.resolve(fn,len(args),fnname,self.u.path)
            if status in ('ambiguous','budget') or (status == 'partial' and len(matches) != 1):
                self.gaps.add('cross-file helper call could not be bound uniquely: '+fn)
                if call_node is not None:
                    self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                                'cross-file definition is ambiguous, partial, or over budget')
                return True
            if status == 'unique':
                cross_file=True
            elif status == 'partial':
                cross_file=True
                partial_binding=True
                self.gaps.add('cross-file helper body summary is partial evidence; caller candidate is retained: '+fn)
                if call_node is not None:
                    self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                                'callee body is inside a partial translation unit')
            else:
                return False
        elif not local_definitions:
            return False

        if not matches:
            self.gaps.add('helper call has unresolved overload/arity: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'helper overload/arity binding failed')
            return True
        if len(matches)>1:
            self.gaps.add('same-file helper call has ambiguous definitions: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'same-file helper definition is ambiguous')
            return True

        units=self.resolver.units if self.resolver is not None else (self.u,)
        if (re.fullmatch(r'\w+',fn) and any(re.search(
                r'^\s*#\s*(?:define|undef)\s+'+re.escape(fn)+r'\b',u.text,re.M) for u in units)):
            self.gaps.add('visible helper body cannot bind a macro-overridden call: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                    'helper spelling is macro-overridden; visible body is not the call target proof')
            # Keep inspecting the visible body for positive evidence, but its
            # apparently clean summary cannot erase this unresolved call.

        callee_flow,definition,parameters,callee_name=matches[0]
        if cross_file and self.resolver is not None:
            self.resolver.partial_paths.update((self.u.path,callee_flow.u.path))
        call_key=(callee_flow.u.path,callee_name)
        findings_before=len(callee_flow.findings)
        if call_key in self.call_stack or len(self.call_stack)>=3:
            self.gaps.add('interprocedural call expansion stopped by recursion/depth bound: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'recursion/depth limit stopped body analysis')
            return True

        fd=definition.child_by_field_name('declarator')
        body=definition.child_by_field_name('body')
        if fd is None or body is None or body.has_error:
            self.gaps.add('helper definition lacks a complete supported body: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'helper body is incomplete')
            return True

        local_values={};local_types={};local_shadows=set();bound=[];local_pointers={}
        for index,param in enumerate(parameters):
            ident=callee_flow.name(param.child_by_field_name('declarator'))
            bound.append(ident)
            if not ident:
                continue
            local_shadows.add(ident)
            local_values[ident]=callee_flow.addstep(
                arg_flows[index],
                f'{call_line} call {callee_name} argument {index}')
            typ=callee_flow.text(param.child_by_field_name('type'))
            if typ in callee_flow.fields:
                local_types[ident]=typ
            if callee_flow.raw_pointer(param.child_by_field_name('declarator')):
                actual_target=self.pointer_target(args[index])
                local_pointers[ident]=PointerTarget('*'+ident,
                    actual_target.bound and callee_flow.u.parse_status=='complete'
                    and not callee_flow.tree.root_node.has_error
                    and CrossFileResolver.writable_parameter(param,callee_flow))

        callee_flow.call_stack.append(call_key)
        try:
            summary_note = (
                'bounded cross-file helper summary; overload, receiver, macro, include and build identity remain unknown'
                if cross_file else
                'bounded same-file helper expansion; compiler type identity remains unknown')
            callee_flow.gaps.add(summary_note)
            if cross_file:
                callee_flow.external_gaps.add(summary_note)
            result=callee_flow.block(
                body,LocalState(local_values,local_types,local_shadows,local_pointers),callee_name)
        finally:
            callee_flow.call_stack.pop()

        new_callee_findings=callee_flow.findings[findings_before:]
        if callee_flow is not self:
            self.findings.extend(new_callee_findings)
            self.gaps.update(callee_flow.gaps)
            self.external_gaps.update(callee_flow.external_gaps)

        returned=tuple(flow for exit in result.exit_states
                       if exit.kind=='return_statement' for flow in exit.returned)
        states=([result.fallthrough_state] if result.fallthrough_state is not None else [])
        states.extend(exit.state for exit in result.exit_states)
        outputs={}
        initial_values = {
            ident: tuple(local_values.get(ident, ()))
            for ident in bound if ident
        }
        for index,(param,ident) in enumerate(zip(parameters,bound)):
            if not ident or not CrossFileResolver.writable_parameter(param,callee_flow):
                continue
            actual_target=self.pointer_target(args[index])
            actual=actual_target.slot or self.lvalue(args[index],types)
            if not actual:
                continue
            raw=callee_flow.raw_pointer(param.child_by_field_name('declarator'))
            slots=('*'+ident,) if raw else (ident,)
            writes = tuple(dict.fromkeys(
                flow for state in states
                for slot in slots
                for flow in state.values.get(slot, ())))
            original = set(initial_values.get(ident, ()))
            writes = tuple(flow for flow in writes if flow not in original)
            if writes:
                outputs.setdefault(actual,[]).extend(
                    self.addstep(writes,
                                 f'{call_line} {callee_name} may write through argument {index}'))
            # Preserve a single visible member slot through a writable object
            # parameter as well as a scalar pointee. No arbitrary alias walk.
            for prefix in (('*'+ident+'.',) if raw else (ident+'.',)):
                slots={slot for state in states for slot in state.values if slot.startswith(prefix)}
                for slot in slots:
                    member_writes=tuple(dict.fromkeys(flow for state in states
                        for flow in state.values.get(slot,())))
                    if member_writes:
                        destination=actual+'.'+slot[len(prefix):]
                        outputs.setdefault(destination,[]).extend(self.addstep(member_writes,
                            f'{call_line} {callee_name} may write member through argument {index}'))
        for actual,flows in outputs.items():
            self.store_value(env,actual,tuple(env.get(actual,()))+tuple(flows))
        call_flows=self.addstep(tuple(dict.fromkeys(returned)),
                                f'{call_line} return from {callee_name}')
        if call_node is not None:
            self.call_results[call_node.id]=call_flows

        # A body summary that neither reaches a modeled sink nor returns/writes
        # tainted material is not a clean proof: preserve the escape candidate.
        if (cross_file and not partial_binding and not new_callee_findings
                and not returned and not outputs and call_node is not None):
            self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                        'bounded helper body did not establish a sink or a safe value summary')
        return True

    def unresolved_member_destination(self,node,types=None):
        if node is None or node.type!='field_expression':
            return False
        base=node.child_by_field_name('argument')
        operator=self.text(node.child_by_field_name('operator'))
        field=self.text(node.child_by_field_name('field'))
        if base is None or base.type!='identifier' or not field:
            return True
        if operator=='->':
            return True
        if operator=='.':
            root=self.text(base)
            type_name=(types or {}).get(root)
            return (not type_name or type_name not in self.fields
                    or type_name in self.type_conflicts)
        return True

    def lvalue(self,node,types=None):
        if node is None:return ''
        if node.type=='identifier':return self.text(node)
        if node.type=='parenthesized_expression' and len(node.named_children)==1:
            return self.lvalue(node.named_children[0],types)
        if node.type=='field_expression':
            base=node.child_by_field_name('argument')
            field=self.text(node.child_by_field_name('field'))
            operator=self.text(node.child_by_field_name('operator'))
            if (operator in ('.','->') and base is not None
                    and base.type=='identifier' and field):
                root=self.text(base)
                if operator=='->':
                    target=self.pointers.get(root)
                    if target and target.slot:
                        return target.slot+'.'+field
                if (operator=='.' and types and types.get(root) in self.fields
                        and self.fields.get(types[root])!=field
                        and types[root] not in self.type_conflicts):
                    return ''
                return root+'.'+field
            return ''
        if node.type in ('pointer_expression','unary_expression'):
            op=self.text(node.child_by_field_name('operator'))
            if op=='&':
                return self.lvalue(node.child_by_field_name('argument'),types)
        return ''

    @staticmethod
    def raw_pointer(declarator):
        if declarator is None:return False
        nodes=list(walk(declarator))
        return (sum(n.type=='pointer_declarator' for n in nodes)==1
                and not any(n.type in ('function_declarator','reference_declarator','array_declarator') for n in nodes))

    def cpp_pointer_cast(self,node):
        if self.u.language!='cpp':return False
        function=node.child_by_field_name('function')
        args=node.child_by_field_name('arguments')
        if (function is None or function.type!='template_function' or args is None
                or len(args.named_children)!=1 or len(function.named_children)!=2):
            return False
        keyword,template=function.named_children
        if self.text(keyword) not in ('static_cast','reinterpret_cast','const_cast','dynamic_cast'):
            return False
        if (template.type!='template_argument_list' or len(template.named_children)!=1
                or template.named_children[0].type!='type_descriptor'
                or not any(x.type=='abstract_pointer_declarator' for x in walk(template))):
            return False
        units=self.resolver.units if self.resolver is not None else (self.u,)
        tokens=re.escape(self.text(keyword))+'|nullptr'
        return not any(re.search(r'^\s*#\s*(?:define|undef)\s+(?:'+tokens+r')\b',u.text,re.M) for u in units)

    def pointer_target(self,node,pointers=None,shadows=None):
        """Only direct address syntax and already tracked raw-pointer copies."""
        pointers=self.pointers if pointers is None else pointers
        shadows=self.shadows if shadows is None else shadows
        if node is None:return PointerTarget()
        if node.type=='parenthesized_expression' and len(node.named_children)==1:
            return self.pointer_target(node.named_children[0],pointers,shadows)
        if node.type=='identifier':return pointers.get(self.text(node),PointerTarget())
        if node.type!='pointer_expression' or self.text(node.child_by_field_name('operator'))!='&':
            return PointerTarget()
        operand=node.child_by_field_name('argument')
        if operand is None:return PointerTarget()
        if operand.type=='identifier':
            slot=self.text(operand);root=slot
        elif (operand.type=='field_expression'
                and self.text(operand.child_by_field_name('operator'))=='.'
                and operand.child_by_field_name('argument') is not None
                and operand.child_by_field_name('argument').type=='identifier'):
            root=self.text(operand.child_by_field_name('argument'))
            slot=root+'.'+self.text(operand.child_by_field_name('field'))
        else:return PointerTarget()
        if root not in shadows:return PointerTarget()
        units=self.resolver.units if self.resolver is not None else (self.u,)
        names=slot.split('.')
        macro=r'^\s*#\s*(?:define|undef)\s+(?:'+'|'.join(re.escape(x) for x in names)+r')\b'
        bound=(self.u.parse_status=='complete' and not self.tree.root_node.has_error
               and not any(re.search(macro,u.text,re.M) or re.search(r'\boperator\s*&(?!&)',u.text) for u in units))
        return PointerTarget(slot,bound)

    def write_destination(self,node,state):
        before=self.pointers;self.pointers=state.pointers
        try:
            if node.type=='pointer_expression' and self.text(node.child_by_field_name('operator'))=='*':
                target=self.pointer_target(node.child_by_field_name('argument'),state.pointers,state.shadows)
                return target.slot,target.bound
            destination=self.lvalue(node,state.types)
            if node.type=='field_expression' and self.text(node.child_by_field_name('operator'))=='->':
                base=node.child_by_field_name('argument')
                target=state.pointers.get(self.text(base),PointerTarget())
                return destination,bool(target.slot and target.bound)
            return destination,bool(destination)
        finally:self.pointers=before

    def output_destination(self,node,types):
        # Call models write through their destination, not to the local pointer
        # variable itself. Keep this slot distinct from an input pointer value.
        target=self.pointer_target(node)
        return target.slot or self.lvalue(node,types)

    def emit_log_candidate(self,fn,fnname,node,flows,message,extra_obligation,operand_status='unresolved operand-privacy status'):
        line=node.start_point[0]+1
        traces=sorted(set(' -> '.join(flow.steps+(f'{line} {fn} {operand_status}',))
                          for flow in flows))
        self.findings.append(DetectorFinding(
            file=self.u.path,line=line,symbol=fnname,rule_id='data.log.sensitive-value',
            candidate_cwe='CWE-532',evidence_type='syntax',source_sha256=self.u.sha256,
            message='Candidate local sensitive-material dependency: '+message+' path='+' | '.join(traces),
            evidence_obligations=(
                EvidenceObligation('local_flow',' | '.join(traces)),
                EvidenceObligation('source_semantics',self.model.provenance),
                EvidenceObligation('type_identity','Resolve the compiler-bound identity of the modeled sensitive record and field; same-name declarations remain candidate-only.'),
                extra_obligation,
                EvidenceObligation('runtime_log_visibility','Verify production level, privacy switches, build branch and unauthorized readers.'),
                EvidenceObligation('security_impact','Prove recoverable secret material and concrete impact; no automatic confirmation.'),
            )))

    def call(self,n,env,types,fnname):
        fn=self.text(n.child_by_field_name('function')); a=n.child_by_field_name('arguments')
        args=list(a.named_children) if a else []
        # A reserved C++ pointer-cast expression is not a sensitive-return API.
        # Operand call effects were inspected by effects(); its value may-flow
        # is retained by expr(). Visible keyword overrides keep normal unknowns.
        if self.cpp_pointer_cast(n):return
        if fn in self.shadows:
            self.gaps.add('call target is shadowed by a local value: '+fn)
            # A callable parameter/local alias is not the reviewed API with the
            # same spelling. Its unresolved target can still consume material.
            self.emit_unresolved_escape(fn,args,env,types,n,fnname,
                                        'local callable target shadows the named API; implementation is unknown')
            return
        callee=fn
        locally_defined=fn in self.function_definitions
        if not locally_defined and '::' in fnname and '::' not in fn:
            caller_owner=fnname.rsplit('::',1)[0]
            same_owner=[name for name in self.function_nodes
                        if name.endswith('::'+fn) and name.rsplit('::',1)[0]==caller_owner]
            if len(same_owner)==1:
                callee=same_owner[0]
                locally_defined=True
            elif same_owner:
                self.gaps.add('same-owner unqualified method call is ambiguous: '+fn)
        if fn in ('strlen','strnlen','strnlen_s','wcslen') and not locally_defined:
            return
        if (fn in self.non_escaping_calls and not locally_defined
                and fn not in self.shadows):
            if any(self.expr(arg,env,types) for arg in args):
                self.gaps.add('exact source model classifies '+fn+' as cleanup, not an exposure sink')
            return
        if locally_defined and (fn in self.output_calls or fn in self.copy_calls):
            self.gaps.add('modeled source/transform name has a same-file definition; API identity unresolved: '+fn)
            return
        if locally_defined and fn in ('memcpy_s','strcpy_s'):
            self.gaps.add('same-file copy-like definition has unresolved write semantics: '+fn)
            if len(args) >= 2:
                dst=self.output_destination(args[0],types)
                if dst:
                    source=args[2] if len(args)>2 else args[-1]
                    self.store_value(env,dst,self.addstep(self.expr(source,env,types),f'{n.start_point[0]+1} unresolved {fn} may write {dst}'))
                else:
                    self.emit_unresolved_escape(fn,args,env,types,n,fnname,
                                                'same-file copy-like callee may write sensitive input to an unresolved destination')
            return
        if locally_defined and fn in ('snprintf','snprintf_s'):
            self.gaps.add('same-file formatting name has unresolved write semantics: '+fn)
            if len(args) >= 2:
                dst=self.output_destination(args[0],types)
                if dst:
                    flows=tuple(flow for arg in args[1:] for flow in self.expr(arg,env,types))
                    self.store_value(env,dst,self.addstep(flows,f'{n.start_point[0]+1} unresolved {fn} may write {dst}'))
                else:
                    self.emit_unresolved_escape(fn,args,env,types,n,fnname,
                                                'same-file formatting callee may write sensitive input to an unresolved destination')
            return
        if locally_defined and fn in self.sinks:
            bodies=self.function_bodies.get(callee, [])
            if len(bodies)==1 and bodies[0] is not None and not any(
                    child.type not in ('comment','empty_statement') for child in bodies[0].named_children):
                self.gaps.add('same-file modeled sink resolves to a visible empty body: '+fn)
                return
            self.gaps.add('same-file modeled sink name has a visible local definition; body is analyzed before sink modeling: '+fn)
        if locally_defined and self.expand_tainted_call(
                callee,args,env,types,n.start_point[0]+1,n,fnname):
            return
        # A cross-TU definition can shadow a modeled log macro/API or receive
        # sensitive material. Resolve and inspect it before crediting the name.
        if not locally_defined and self.resolver is not None:
            tainted_args=any(self.expr(arg,env,types) for arg in args)
            if tainted_args and self.expand_tainted_call(
                    fn,args,env,types,n.start_point[0]+1,n,fnname):
                return
        if fn in PROPERTY_READ_CALLS and not locally_defined and len(args)==4:
            binding=self.property_keys.bind(n,args[2])
            if binding:
                self.property_key_roles.add((enclosing_function(n),binding))
                self.gaps.add('reviewed NAPI property-name argument 2 is not fetched '+binding.material_kind+' material: '
                              +fn+'; bound constant '+binding.identity)
                # Only the exact, bound schema-key operand is excluded. Outputs,
                # object values and any other material remain may-escape inputs.
                flows=tuple(flow for i,arg in enumerate(args) if i!=2
                            for flow in self.expr(arg,env,types))
                if flows:
                    self.emit_unresolved_flows(fn,n,fnname,flows,
                        'other NAPI operands remain unresolved; only the bound property-name operand is excluded')
                if fn=='napi_get_named_property':
                    source=self.source('napi_get_named_property '+binding.material_kind+'-property output argument 3',n)
                    destination=self.lvalue(args[3],types)
                    if (destination and args[3].type=='pointer_expression'
                            and self.text(args[3].child_by_field_name('operator'))=='&'):
                        self.store_value(env,destination,(source,))
                    else:
                        self.emit_unresolved_flows(fn,n,fnname,(source,),
                            binding.material_kind+'-property output destination is unresolved','destination_binding')
                self.call_results[n.id]=()  # napi_status, not fetched material
                return
        if fn=='LOGE' and not locally_defined and args:
            macro_binding=self.log_macro_roles.resolve()
            scope=enclosing_function(n)
            if macro_binding and scope is not None:
                try:
                    slots,count=formats(self.literal(args[0]))
                    if count!=len(args)-1:raise ValueError('log macro format arity')
                except (ValueError,SyntaxError):
                    slots=()
                excluded=set()
                for _,indexes,conversion in slots:
                    if conversion!='s':continue
                    index=indexes[-1]+1
                    binding=self.property_keys.bind(n,args[index],allow_target_macro=True)
                    if binding and (scope,binding) in self.property_key_roles:
                        excluded.add(index)
                if excluded:
                    self.gaps.add('bound schema-key log operand excluded through complete LOGE macro roles: '+macro_binding)
                    flows=tuple(flow for index,arg in enumerate(args) if index not in excluded
                                for flow in self.expr(arg,env,types))
                    self.emit_unresolved_flows(fn,n,fnname,flows,
                        'other logging operands remain candidates; only prior-bound schema-name string operands are excluded')
                    return
        if fn in self.output_calls:
            index, arity = self.output_calls[fn]
            if len(args) != arity:
                self.gaps.add('source API argument count unresolved');return
            if index<len(args):
                dst=self.output_destination(args[index],types)
                if dst:
                    source=self.source(fn+' output argument '+str(index),n)
                    self.store_value(env,dst,(source,))
                    if self.unresolved_member_destination(args[index],types):
                        self.emit_unresolved_flows(fn,n,fnname,(source,),
                            'modeled sensitive source writes to a destination whose identity is unresolved',
                            'destination_binding')
                else:
                    self.gaps.add('complex source output destination')
                    source=self.source(fn+' output argument '+str(index),n)
                    self.emit_unresolved_flows(fn,n,fnname,(source,),
                                               'modeled sensitive source writes to a destination whose identity is unresolved',
                                               'destination_binding')
            return
        if fn in ('memcpy_s','strcpy_s'):
            if len(args)!=(4 if fn=='memcpy_s' else 3):
                self.gaps.add('copy API argument count unresolved');return
            dst=self.output_destination(args[0],types)
            if dst:
                flows=self.addstep(self.expr(args[2],env,types),f'{n.start_point[0]+1} {fn} -> {dst}')
                self.store_value(env,dst,flows)
                if self.unresolved_member_destination(args[0],types) and flows:
                    self.gaps.add('pointer/member destination retained as a may-flow; object identity and aliasing remain unknown')
                    self.emit_unresolved_flows(fn,n,fnname,flows,
                        'sensitive bytes are copied to a destination whose identity is unresolved (member object binding is unknown)',
                        'destination_binding')
            else:
                self.gaps.add('member/pointer output copy unsupported')
                flows=tuple(dict.fromkeys(flow for value in args
                                          for flow in self.expr(value,env,types)))
                self.emit_unresolved_flows(fn,n,fnname,flows,
                                           'sensitive input is copied to a destination whose identity is unresolved',
                                           'destination_binding')
            return
        if fn in ('snprintf','snprintf_s'):
            fi=2 if fn=='snprintf' else 3
            if len(args)<=fi:return
            try:
                slots,count=formats(self.literal(args[fi]))
                operands=args[fi+1:]
                if count!=len(operands):raise ValueError('format arity')
                vals=tuple(v for _,ids,_ in slots for i in ids for v in self.expr(operands[i],env,types))
                dst=self.output_destination(args[0],types)
                if dst:
                    flows=self.addstep(vals,f'{n.start_point[0]+1} {fn} -> {dst}')
                    self.store_value(env,dst,flows)
                    if self.unresolved_member_destination(args[0],types) and flows:
                        self.gaps.add('pointer/member destination retained as a may-flow; object identity and aliasing remain unknown')
                        self.emit_unresolved_flows(fn,n,fnname,flows,
                            'sensitive formatted bytes use a destination whose identity is unresolved (member object binding is unknown)',
                            'destination_binding')
                elif vals:
                    self.gaps.add('member/pointer formatting destination identity unresolved')
                    flows=tuple(dict.fromkeys(flow for value in args
                                              for flow in self.expr(value,env,types)))
                    self.emit_unresolved_flows(fn,n,fnname,flows,
                                               'sensitive formatting output has an unresolved destination',
                                               'destination_binding')
            except (ValueError,SyntaxError):
                self.gaps.add('unsupported formatting propagation')
                flows=tuple(dict.fromkeys(flow for value in args[fi+1:]
                                          for flow in self.expr(value,env,types)))
                self.emit_unresolved_flows(fn,n,fnname,flows,
                                           'sensitive formatting input has unresolved format-to-destination flow',
                                           'format_resolution')
            return
        if fn in self.copy_calls:
            source_index, destination_index, arity = self.copy_calls[fn]
            if len(args) != arity:
                self.gaps.add('modeled copy API argument count unresolved: '+fn)
                return
            destination = self.output_destination(args[destination_index], types)
            flows = self.expr(args[source_index], env, types)
            if destination:
                written=self.addstep(
                    flows, f'{n.start_point[0]+1} {fn} -> {destination}')
                self.store_value(env,destination,written)
                if self.unresolved_member_destination(args[destination_index],types) and written:
                    self.gaps.add('pointer/member destination retained as a may-flow; object identity and aliasing remain unknown')
                    self.emit_unresolved_flows(fn,n,fnname,written,
                        'sensitive bytes pass through a modeled encoder to a destination whose identity is unresolved (member object binding is unknown)',
                        'destination_binding')
            elif flows:
                self.gaps.add('modeled copy destination identity unresolved: '+fn)
                self.emit_unresolved_flows(
                    fn, n, fnname, flows,
                    'sensitive bytes pass through a modeled encoder but its output destination is unresolved',
                    'destination_binding')
            return
        if fn not in self.sinks:
            flows=tuple(flow for arg in args for flow in self.expr(arg,env,types))
            if flows:
                self.gaps.add('unmodeled call may mutate/escape sensitive value: '+fn)
                self.emit_unresolved_escape(fn,args,env,types,n,fnname,
                                            'the call is outside the same-file reviewed model')
            return
        sink=self.sinks[fn]
        self.sink_sites.append({'symbol':fn,'line':n.start_point[0]+1,'format_index':sink.format_index})
        if len(args)<=sink.format_index:
            self.gaps.add('missing log format');return
        try:
            format_text = self.literal(args[sink.format_index])
            if (not sink.supports_privacy_markers
                    and re.search(r'%(?:\{public\}|\{private\})', format_text)):
                raise ValueError('privacy annotations are not supported by this preformatted sink')
            slots,count=formats(format_text, 'private' if sink.default_private else 'public')
            operands=args[sink.format_index+1:]
            if count!=len(operands):raise ValueError('format/argument mismatch')
        except (ValueError,SyntaxError):
            self.gaps.add('nonliteral/unsupported log format: '+fn)
            flows=tuple(flow for arg in args[sink.format_index:]
                        for flow in self.expr(arg,env,types))
            if flows:
                self.emit_log_candidate(fn,fnname,n,flows,
                    'Sensitive data reaches a modeled logging call, but dynamic/unsupported formatting prevents privacy-slot resolution.',
                    EvidenceObligation('format_resolution','Resolve the runtime format and whether sensitive operands are public or private.'))
            return
        for privacy,ids,conversion in slots:
            if privacy!='public':
                for i in ids:
                    if conversion=='p' and i==ids[-1]:
                        if self.expr(operands[i],env,types):
                            self.gaps.add('pointer-address output outside material rule')
                        continue
                    flows=self.expr(operands[i],env,types)
                    if not flows:continue
                    self.gaps.add('private operand requires runtime privacy-configuration review; conditional candidate retained')
                    self.emit_log_candidate(
                        fn,fnname,n,flows,
                        'Sensitive data reaches a modeled logging call through a private/default-private operand; exposure is conditional and not established.',
                        EvidenceObligation(
                            'sink_privacy',
                            'Verify the exact sink implementation, production privacy configuration, log collection policy, and reader permissions; the static private marker does not prove non-exposure.'),
                        operand_status=f'{privacy} operand {i}')
                continue
            for i in ids:
                # Pointer-address output is not automatically a secret material leak.
                if conversion=='p' and i==ids[-1]:
                    if self.expr(operands[i],env,types):self.gaps.add('pointer-address output outside material rule')
                    continue
                flows=self.expr(operands[i],env,types)
                if not flows:continue
                line=n.start_point[0]+1
                steps=sorted(set(' -> '.join(f.steps+(f'{line} {fn} public operand {i}',)) for f in flows))
                self.findings.append(DetectorFinding(
                    file=self.u.path,line=line,symbol=fnname,
                    rule_id='data.log.sensitive-value',candidate_cwe='CWE-532',
                    evidence_type='syntax',source_sha256=self.u.sha256,
                    message='Candidate local sensitive-material dependency: '+' | '.join(steps),
                    evidence_obligations=(
                        EvidenceObligation('local_flow', ' | '.join(steps)),
                        EvidenceObligation('source_semantics',self.model.provenance),
                        EvidenceObligation('type_identity','Resolve the compiler-bound identity of the modeled sensitive record and field; same-name declarations remain candidate-only.'),
                        EvidenceObligation('runtime_log_visibility','Verify production level, privacy switches, build branch and unauthorized readers.'),
                        EvidenceObligation('execution_and_identity','Verify initialization, API binding, return status, branch feasibility and pointer aliases.'),
                        EvidenceObligation('security_impact','Prove recoverable secret material and concrete impact; no automatic confirmation.'),
                    )))

    @staticmethod
    def truth(node):
        if node is None:return None
        if node.type in ('parenthesized_expression','condition_clause') and len(node.named_children)==1:
            return LocalFlow.truth(node.named_children[0])
        if node.type=='true':return True
        if node.type in ('false','null'):return False
        return None

    @staticmethod
    def merge(states):
        live=[s for s in states if s is not None]
        if not live:return None
        out=live[0].clone()
        for key in set().union(*(set(s.values) for s in live)):
            out.values[key]=tuple(dict.fromkeys(v for s in live for v in s.values.get(key,())))
        for key in set().union(*(set(s.types) for s in live)):
            kinds={s.types.get(key) for s in live}
            if len(kinds)==1 and None not in kinds:out.types[key]=next(iter(kinds))
            else:out.types.pop(key,None)
        out.shadows=set().union(*(s.shadows for s in live))
        for key in set().union(*(set(s.pointers) for s in live)):
            targets={s.pointers.get(key,PointerTarget()) for s in live}
            out.pointers[key]=next(iter(targets)) if len(targets)==1 else PointerTarget()
        return out

    def replace_state(self,state,new):
        state.values,state.types,state.shadows=new.values,new.types,new.shadows
        state.pointers=new.pointers

    def apply_call(self,node,state,fnname):
        before=self.shadows,self.pointers
        self.shadows,self.pointers=state.shadows,state.pointers
        try:self.call(node,state.values,state.types,fnname)
        finally:self.shadows,self.pointers=before
        # Passing the pointer variable's address can rebind it. Do not retain a
        # previous pointee claim across an unsupported pointer-to-pointer write.
        args=node.child_by_field_name('arguments')
        for arg in args.named_children if args else ():
            if arg.type=='pointer_expression' and self.text(arg.child_by_field_name('operator'))=='&':
                name=self.text(arg.child_by_field_name('argument'))
                if name in state.pointers:state.pointers[name]=PointerTarget()

    def value(self,node,state):
        before=self.shadows,self.pointers
        self.shadows,self.pointers=state.shadows,state.pointers
        try:return self.expr(node,state.values,state.types)
        finally:self.shadows,self.pointers=before

    def effects(self,node,state,fnname):
        """Bounded evaluation effects; short circuit/?: merge possible live states."""
        if node is None:return
        if node.type=='lambda_expression':
            self.gaps.add('lambda execution not analyzed');return
        if node.type=='assignment_expression':
            right=node.child_by_field_name('right');left=node.child_by_field_name('left')
            self.effects(right,state,fnname)
            destination,target_bound=self.write_destination(left,state)
            flows=self.value(right,state)
            op=self.text(node.child_by_field_name('operator'))
            if op!='=':
                flows=tuple(dict.fromkeys(self.value(left,state)+flows))
            if destination:
                step=f'{node.start_point[0]+1} assign {destination}'
                if op!='=':
                    self.gaps.add('compound assignment semantics incomplete; destination dependency retained as may-flow')
                    step=f'{node.start_point[0]+1} compound assign {destination} ({op})'
                self.store_value(state.values,destination,
                    self.addstep(flows,step))
                if left.type=='identifier' and destination in state.pointers:
                    state.pointers[destination]=(self.pointer_target(right,state.pointers,state.shadows)
                                                 if op=='=' else PointerTarget())
            if not target_bound:
                self.gaps.add('pointer/member assignment requires alias proof')
                self.emit_unresolved_flows(self.text(left),node,fnname,flows,
                    'material assignment has unresolved pointer/member destination',
                    'destination_binding',event='material write')
            return
        if node.type=='binary_expression' and self.text(node.child_by_field_name('operator')) in ('&&','||'):
            left=node.child_by_field_name('left');right=node.child_by_field_name('right')
            self.effects(left,state,fnname)
            op=self.text(node.child_by_field_name('operator'));known=self.truth(left)
            executes=(known is True and op=='&&') or (known is False and op=='||')
            skips=(known is False and op=='&&') or (known is True and op=='||')
            if executes:self.effects(right,state,fnname)
            elif not skips:
                self.gaps.add('short-circuit effects are may-flow; no path feasibility proof')
                possible=state.clone();self.effects(right,possible,fnname)
                self.replace_state(state,self.merge([state,possible]))
            return
        if node.type=='conditional_expression':
            condition=node.child_by_field_name('condition');self.effects(condition,state,fnname)
            known=self.truth(condition)
            fields=('consequence',) if known is True else ('alternative',) if known is False else ('consequence','alternative')
            if known is None:self.gaps.add('conditional effects are may-flow; no path feasibility proof')
            options=[]
            for field in fields:
                other=state.clone();self.effects(node.child_by_field_name(field),other,fnname);options.append(other)
            self.replace_state(state,self.merge(options));return
        if node.type=='call_expression':
            args=node.child_by_field_name('arguments')
            if args:
                for arg in args.named_children:self.effects(arg,state,fnname)
            self.apply_call(node,state,fnname);return
        if node.type in ('string_literal','char_literal','number_literal','identifier','sizeof_expression'):return
        if node.type=='alignof_expression' and self.u.language=='cpp':return
        for child in node.named_children:self.effects(child,state,fnname)

    def declaration(self,node,state,fnname):
        type_text=self.text(node.child_by_field_name('type'))
        declared=set()
        for d in node.children_by_field_name('declarator'):
            name=self.name(d)
            if not name:continue
            for pointer,target in list(state.pointers.items()):
                if target.slot and target.slot.split('.')[0]==name:
                    state.pointers[pointer]=PointerTarget()
            state.pointers.pop(name,None)
            declared.add(name);state.types.pop(name,None);state.values[name]=();state.shadows.add(name)
            if type_text in self.fields:state.types[name]=type_text
            declarator=d.child_by_field_name('declarator') if d.type=='init_declarator' else d
            if (type_text=='std::string' and declarator is not None
                    and declarator.type=='identifier'):
                state.types[name]=type_text
            # A condition declaration puts its initializer on the declaration,
            # unlike the init_declarator used by ordinary declarations.
            value=(d.child_by_field_name('value') if d.type=='init_declarator'
                   else node.child_by_field_name('value'))
            if value:
                self.effects(value,state,fnname)
                state.values[name]=self.addstep(self.value(value,state),f'{node.start_point[0]+1} assign {name}')
            target=self.pointer_target(value,state.pointers,state.shadows)
            if (self.raw_pointer(declarator)
                    or (type_text=='auto' and declarator is not None
                        and declarator.type=='identifier' and target.slot is not None)):
                state.pointers[name]=target
                if re.search(r'\bconst\b',self.text(node)):
                    state.pointers[name]=PointerTarget(target.slot,False)
        return declared

    def header_effects(self,node,state,fnname):
        """Bind only the explicit header declaration shapes, in source order."""
        if node is None:return set()
        if node.type=='declaration':return self.declaration(node,state,fnname)
        if node.type in ('condition_clause','init_statement'):
            declared=set()
            for child in node.named_children:
                declared.update(self.header_effects(child,state,fnname))
            return declared
        self.effects(node,state,fnname)
        return set()

    def exact_switch_cases(self,node):
        """Shared bounded dispatch proof; no general label evaluation or CFG."""
        units=self.resolver.units if self.resolver is not None else (self.u,)
        if ((self.resolver is not None and not getattr(self.resolver,'switch_join_scope_complete',False))
                or self.tree.root_node.has_error or any(u.parse_status!='complete'
                or re.search(r'^\s*#',u.text,re.M) for u in units)):
            return None
        condition=node.child_by_field_name('condition')
        value=condition.child_by_field_name('value') if condition else None
        body=node.child_by_field_name('body')
        if (value is None or value.type!='identifier' or body is None
                or body.type!='compound_statement'):
            return None
        cases=[c for c in body.named_children if c.type!='comment']
        if len(cases)<2 or any(c.type!='case_statement' for c in cases):return None
        labels=set();defaults=0;arms=[]
        for case in cases:
            label=case.child_by_field_name('value')
            if label is None:
                defaults+=1
            else:
                text=self.text(label)
                if (label.type!='number_literal' or not re.fullmatch(r'0|[1-9][0-9]*',text)
                        or int(text)>2147483647 or text in labels):
                    return None
                labels.add(text)
            statements=[c for c in case.named_children
                        if c.type!='comment' and (label is None or c.id!=label.id)]
            arms.append(statements)
        return arms if defaults==1 else None

    def exact_switch_pointer_join(self,node,state,fnname):
        """Only exhaustive flat arms: one identical raw-pointer retarget + break."""
        arms=self.exact_switch_cases(node)
        if arms is None:return None
        assignments=[];binding=None
        for statements in arms:
            if (len(statements)!=2 or statements[0].type!='expression_statement'
                    or statements[1].type!='break_statement'
                    or len(statements[0].named_children)!=1):
                return None
            assignment=statements[0].named_children[0]
            left=assignment.child_by_field_name('left');right=assignment.child_by_field_name('right')
            if (assignment.type!='assignment_expression' or self.text(assignment.child_by_field_name('operator'))!='='
                    or left is None or left.type!='identifier' or self.text(left) not in state.pointers
                    or right is None or right.type!='pointer_expression'
                    or self.text(right.child_by_field_name('operator'))!='&'):
                return None
            operand=right.child_by_field_name('argument')
            if operand is None or operand.type!='identifier':return None
            target=self.pointer_target(right,state.pointers,state.shadows)
            if not target.bound or target.slot in state.pointers:return None
            current=(self.text(left),target)
            if binding is not None and binding!=current:return None
            binding=current;assignments.append(assignment)
        branches=[]
        for assignment in assignments:
            branch=state.clone();self.effects(assignment,branch,fnname);branches.append(branch)
        self.gaps.add('exact flat switch pointer join; general case/fallthrough/control-flow proof remains unresolved')
        return self.merge(branches)

    @staticmethod
    def bounded_return_expression(node):
        """Only expression shapes whose existing value/effect walk is bounded."""
        if node.type in ('identifier','number_literal','string_literal','char_literal','null','true','false'):
            return True
        children=node.named_children
        if node.type=='parenthesized_expression':
            return len(children)==1 and LocalFlow.bounded_return_expression(children[0])
        if node.type=='comma_expression':
            return len(children)==2 and all(LocalFlow.bounded_return_expression(c) for c in children)
        if node.type=='call_expression':
            function=node.child_by_field_name('function');args=node.child_by_field_name('arguments')
            return (function is not None and function.type=='identifier' and args is not None
                    and all(LocalFlow.bounded_return_expression(c) for c in args.named_children))
        return False

    def direct_bounded_return(self,node):
        if node is None or node.type!='return_statement':return False
        values=node.named_children
        return len(values)<=1 and (not values or self.bounded_return_expression(values[0]))

    def bounded_switch_return_arm(self,node):
        """One return, or one if/else with a direct return in each branch."""
        if self.direct_bounded_return(node):return True
        if node.type!='if_statement':return False
        condition=node.child_by_field_name('condition')
        value=condition.child_by_field_name('value') if condition else None
        if (value is None or len(condition.named_children)!=1
                or not self.bounded_return_expression(value)):
            return False
        for field in ('consequence','alternative'):
            branch=node.child_by_field_name(field)
            if branch is not None and branch.type=='else_clause':
                children=[c for c in branch.named_children if c.type!='comment']
                branch=children[0] if len(children)==1 else None
            if branch is not None and branch.type=='compound_statement':
                children=[c for c in branch.named_children if c.type!='comment']
                branch=children[0] if len(children)==1 else None
            if not self.direct_bounded_return(branch):return False
        return True

    def exact_switch_returns(self,node,state,fnname):
        """Consecutive empty labels may share the next direct bounded return."""
        arms=self.exact_switch_cases(node)
        if arms is None or not arms[-1]:return None
        returning=[]
        for arm in arms:
            if not arm:continue # Consecutive labels enter the next nonempty arm.
            if len(arm)!=1 or not self.bounded_switch_return_arm(arm[0]):return None
            returning.append(arm[0])
        if not returning:
            return None
        # A goto can bypass this switch to a following label. Without a CFG,
        # reject the whole function rather than suppress such reachable code.
        function=node.parent
        while function is not None and function.type!='function_definition':function=function.parent
        if function is None or any(n.type in ('goto_statement','labeled_statement') for n in walk(function)):
            return None
        results=[self.statement(returned,state.clone(),fnname) for returned in returning]
        if any(result.fallthrough_state is not None for result in results):return None
        exits=tuple(exit for result in results for exit in result.exit_states)
        self.gaps.add('exact grouped return/if-else-return switch; general switch exits/feasibility remain unresolved')
        return BlockResult(None,exits)

    @staticmethod
    def restore_scope(state,entry,declared):
        if state is None:return
        for pointer,target in list(state.pointers.items()):
            if target.slot and target.slot.split('.')[0] in declared:
                state.pointers[pointer]=PointerTarget()
        for name in declared:
            if name in entry.values:state.values[name]=entry.values[name]
            else:state.values.pop(name,None)
            if name in entry.types:state.types[name]=entry.types[name]
            else:state.types.pop(name,None)
            if name in entry.shadows:state.shadows.add(name)
            else:state.shadows.discard(name)
            if name in entry.pointers:state.pointers[name]=entry.pointers[name]
            else:state.pointers.pop(name,None)

    def statement(self,node,state,fnname):
        kind=node.type
        if kind=='compound_statement':return self.block(node,state,fnname)
        if kind=='else_clause':
            children=node.named_children
            if len(children)==1:return self.statement(children[0],state,fnname)
            self.gaps.add('unsupported else-clause shape');return BlockResult(state)
        if kind in ('return_statement','break_statement','continue_statement','throw_statement'):
            returned=()
            if kind=='return_statement' and node.named_children:
                expression=node.named_children[0]
                self.effects(expression,state,fnname)
                returned=self.value(expression,state)
            if kind in ('break_statement','continue_statement'):
                self.gaps.add('break/continue exits need enclosing-loop proof; loops not analyzed')
            return BlockResult(None,(ExitState(kind,node.start_point[0]+1,state.clone(),returned),))
        if kind=='expression_statement':
            if any(x.type=='throw_expression' for x in node.named_children):
                self.gaps.add('throw/destructor effects not analyzed')
                return BlockResult(None,(ExitState('throw',node.start_point[0]+1,state.clone()),))
            for expr in node.named_children:self.effects(expr,state,fnname)
            return BlockResult(state)
        if kind=='if_statement':
            self.gaps.add('branch merge is may-flow; no path feasibility proof')
            entry=state.clone();cond=node.child_by_field_name('condition')
            declared=self.header_effects(cond,state,fnname)
            known=self.truth(cond);results=[]
            fields=('consequence',) if known is True else ('alternative',) if known is False else ('consequence','alternative')
            for field in fields:
                child=node.child_by_field_name(field);branch=state.clone()
                if child is None:result=BlockResult(branch)
                elif child.type=='declaration':
                    # Implicit branch scope: names do not escape the branch.
                    branch_entry=branch.clone();names=self.declaration(child,branch,fnname)
                    self.restore_scope(branch,branch_entry,names);result=BlockResult(branch)
                else:result=self.statement(child,branch,fnname)
                results.append(result)
            merged=self.merge([r.fallthrough_state for r in results])
            exits=tuple(exit for result in results for exit in result.exit_states)
            self.restore_scope(merged,entry,declared)
            for exit in exits:self.restore_scope(exit.state,entry,declared)
            return BlockResult(merged,exits)
        if kind=='switch_statement':
            cond=node.child_by_field_name('condition')
            if cond and any(x.type=='declaration' for x in walk(cond)):
                self.gaps.add('switch header binding only; case ordering/feasibility unresolved')
                entry=state.clone();declared=self.header_effects(cond,state,fnname)
                returned=self.exact_switch_returns(node,state,fnname)
                if returned is not None:
                    for exit in returned.exit_states:self.restore_scope(exit.state,entry,declared)
                    return returned
                joined=self.exact_switch_pointer_join(node,state,fnname)
                if joined is not None:
                    self.restore_scope(joined,entry,declared)
                    return BlockResult(joined)
                probe=state.clone();self.effects(node.child_by_field_name('body'),probe,fnname)
                merged=self.merge([state,probe]);self.restore_scope(merged,entry,declared)
                return BlockResult(merged)
            returned=self.exact_switch_returns(node,state,fnname)
            if returned is not None:return returned
            joined=self.exact_switch_pointer_join(node,state,fnname)
            if joined is not None:return BlockResult(joined)
        if kind in ('comment','empty_statement'):return BlockResult(state)
        if kind in ('while_statement','do_statement','for_statement','range_based_for_statement'):
            self.gaps.add(f'loop body analyzed for may-flow only at line {node.start_point[0]+1}; iteration count/path feasibility unresolved')
            body=node.child_by_field_name('body')
            if body is None:
                body=next((c for c in reversed(node.named_children) if c.type in ('compound_statement','expression_statement','if_statement','declaration')),None)
            if body is None:return BlockResult(state)
            # Evaluate the bounded loop header too: a for initializer or range
            # expression can carry the modeled value into the body. Treat all
            # header effects as possible and retain a partial-flow obligation.
            loop_entry=state.clone();header_declared=set()
            for header in node.named_children:
                if header.id == body.id:
                    continue
                header_declared.update(self.header_effects(header,state,fnname))
            branch=state.clone()
            result=self.statement(body,branch,fnname)
            merged=self.merge([state,result.fallthrough_state,
                               *(e.state for e in result.exit_states)])
            # A for-header declaration has loop scope, including when it shadows
            # an outer raw pointer. Body retargets of other names remain merged.
            self.restore_scope(merged,loop_entry,header_declared)
            return BlockResult(merged)
        # Preserve direct source/sink and unresolved-call candidates nested in
        # unsupported constructs such as switch/try. Scan on a clone so this
        # bounded may-flow pass cannot erase facts from the surrounding block.
        # Branch feasibility, ordering and case-specific state remain unknown.
        self.gaps.add(f'unsupported statement {kind} at line {node.start_point[0]+1}; nested call effects inspected as may-flow')
        probe = state.clone()
        self.effects(node, probe, fnname)
        return BlockResult(self.merge([state, probe]))

    def block(self,node,state,fnname):
        entry=state.clone();declared=set();exits=[];live=state
        for child in node.named_children:
            if live is None:break
            if child.type=='declaration':declared.update(self.declaration(child,live,fnname))
            else:
                result=self.statement(child,live,fnname)
                live=result.fallthrough_state;exits.extend(result.exit_states)
        self.restore_scope(live,entry,declared)
        for exit in exits:self.restore_scope(exit.state,entry,declared)
        return BlockResult(live,tuple(exits),tuple(sorted(self.gaps)))

    def run(self):
        if self.tree.root_node.has_error:self.gaps.add('detailed syntax partial')
        self.function_audits=[]
        file_gaps=set(self.gaps)|set(self.external_gaps);all_gaps=set(file_gaps)
        for fn in (n for n in walk(self.tree.root_node) if n.type=='function_definition'):
            self.gaps=set(file_gaps)
            body=fn.child_by_field_name('body');d=fn.child_by_field_name('declarator')
            fd=next((x for x in walk(d) if x.type=='function_declarator'),None) if d else None
            if not body or not fd:continue
            name=self.text(fd.child_by_field_name('declarator'));env={};types={};pointers={}
            params=fd.child_by_field_name('parameters')
            original_shadows=set(self.shadows)
            for index,p in enumerate(params.named_children if params else []):
                ident=self.name(p.child_by_field_name('declarator'))
                typ=self.text(p.child_by_field_name('type'))
                self.shadows.add(ident)
                if typ in self.fields:types[ident]=typ
                if self.raw_pointer(p.child_by_field_name('declarator')):
                    pointers[ident]=PointerTarget('*'+ident,False)
                if (self.u.path,name,index) in self.model.parameters:
                    env[ident]=(self.source(name+' parameter '+str(index),p),)
            result=self.block(body,LocalState(env,types,set(self.shadows),pointers),name)
            self.function_audits.append({'symbol':name,'start_line':fn.start_point[0]+1,'end_line':fn.end_point[0]+1,
                'fallthrough':result.fallthrough_state is not None,
                'exits':[{'kind':e.kind,'line':e.line} for e in result.exit_states],
                'limitations':sorted(self.gaps)})
            all_gaps.update(self.gaps)
            self.shadows=original_shadows
        self.gaps=all_gaps
        # Same line/symbol may have multiple sensitive operands; preserve traces in one finding.
        merged={}
        for f in self.findings:
            key=(f.file,f.line,f.symbol)
            if key not in merged:merged[key]=f
            else:
                from dataclasses import replace
                old=merged[key]
                merged[key]=replace(
                    old,
                    message=old.message if f.message in old.message else old.message+' | '+f.message,
                    evidence_obligations=tuple(dict.fromkeys(
                        old.evidence_obligations+f.evidence_obligations)))

        return list(merged.values())
