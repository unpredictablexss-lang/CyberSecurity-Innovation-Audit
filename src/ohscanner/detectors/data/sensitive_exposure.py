"""D v1: bounded function-local material flow to explicitly public log operands.

Uses the existing Tree-sitter infrastructure; detailed statement parsing is private
because shared outlines expose no expression/binding facts. No global IR changes.
"""
import ast
import re
from dataclasses import dataclass
import tree_sitter_c
import tree_sitter_cpp
from tree_sitter import Language, Parser
from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation
from .models import DEFAULT_SOURCE, SINKS

@dataclass(frozen=True)
class Flow:
    steps: tuple


@dataclass
class LocalState:
    values: dict
    types: dict
    shadows: set

    def clone(self):
        return LocalState(dict(self.values), dict(self.types), set(self.shadows))


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


class SensitiveExposureDetector:
    detector_id = 'ohscanner.data.sensitive_exposure'
    version = '0.3.0'
    supported_languages = ('c', 'cpp')
    required_facts = ('ast',)

    def __init__(self, model=DEFAULT_SOURCE):
        self.model = model

    def make_flow(self, unit):
        return LocalFlow(unit, self.model)

    def detect(self, context, units):
        if (context.request.repository, context.request.commit) != (self.model.repository, self.model.commit):
            return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                'No reviewed sensitive-source model for this repository/commit; not a clean scan.',))
        findings, outcomes, limits = [], [], set()
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
            analysis = self.make_flow(u)
            rows = analysis.run()
            findings.extend(rows)
            partial = analysis.gaps or u.parse_status != 'complete' or outline.get('parse_status') != 'complete'
            outcomes.append((u.path, 'partial' if partial else 'complete'))
            limits.update(u.path+': '+s for s in analysis.gaps)
        limits.update((
            'Candidate only: runtime log readers, production enablement and impact require independent review.',
            'Function-local syntax dependencies, not CFG/alias/full-program proof; no secret values recorded.',
            'Model scope is exact repository/commit; receiver/typedef identity and include binding remain obligations.',
            'Detailed private Tree-sitter statements pending owner-approved shared expression facts; no new global frontend.',
            'Private/default-private operands withheld under modeled HiLog semantics, not proof of all product privacy configurations.',
        ))
        return DetectorRun(self.detector_id, self.version,
            'completed' if outcomes and all(s == 'complete' for _, s in outcomes) else 'blocked',
            analyzed_files=tuple(p for p,s in outcomes if s in ('complete','partial')),
            findings=tuple(sorted(findings, key=lambda f:(f.file,f.line,f.rule_id,f.symbol or ''))),
            file_outcomes=tuple(outcomes), limitations=tuple(sorted(limits)))


class LocalFlow:
    def __init__(self, unit, model):
        self.u, self.model = unit, model
        self.b = unit.text.encode()
        self.gaps, self.findings = set(), []
        self.source_sites, self.sink_sites = [], []
        lang = tree_sitter_c if unit.language == 'c' else tree_sitter_cpp
        self.tree = Parser(Language(lang.language())).parse(self.b)
        self.sinks = {s.name:s for s in SINKS}
        self.fields = dict(model.fields)
        self.shadows = set()
        self.function_definitions = set()
        self.function_bodies = {}
        self.function_nodes = {}
        self.call_stack = []
        self.call_results = {}
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
        if n.type=='parenthesized_declarator' and len(n.named_children)==1:return self.name(n.named_children[0])
        return ''

    def source(self,desc,n):
        self.source_sites.append({'description':desc,'line':n.start_point[0]+1})
        return Flow((f'{self.u.path}:{n.start_point[0]+1} source {desc}',))

    def expr(self,n,env,types):
        if n is None:return ()
        if n.type=='identifier':return env.get(self.text(n),())
        if n.type in ('string_literal','char_literal','number_literal','sizeof_expression','null','true','false'):return ()
        if n.type=='field_expression':
            obj=n.child_by_field_name('argument'); field=self.text(n.child_by_field_name('field'))
            root=self.text(obj)
            if root in types and types[root] in self.type_conflicts:
                self.gaps.add('shadowed sensitive record type withheld');return ()
            if root in types and self.fields.get(types[root]) == field:
                self.gaps.add('record binding and initialization require compiler facts')
                return (self.source(types[root]+'.'+field,n),)
            if root in types:
                return () # known nonmaterial field (len/iv/index), not whole object taint
            if root in env:
                self.gaps.add('unknown field/alias propagation')
            return ()
        if n.type=='conditional_expression':
            self.gaps.add('conditional value is may-flow; no path feasibility proof')
            condition=n.child_by_field_name('condition')
            known=self.truth(condition)
            branches=('consequence',) if known is True else ('alternative',) if known is False else ('consequence','alternative')
            return tuple(v for field in branches for v in self.expr(n.child_by_field_name(field),env,types))
        if n.type=='lambda_expression':
            self.gaps.add('lambda body/capture value not analyzed');return ()
        if n.type=='assignment_expression':return self.expr(n.child_by_field_name('right'),env,types)
        if n.type=='binary_expression':
            op=self.text(n.child_by_field_name('operator'))
            if op in ('==','!=','<','>','<=','>=','&&','||'):return ()
        if n.type=='unary_expression' and self.text(n).lstrip().startswith('!'):return ()
        if n.type=='call_expression':
            if n.id in self.call_results:
                return self.call_results[n.id]
            fn=self.text(n.child_by_field_name('function'))
            if fn in ('strlen','strnlen','strnlen_s','wcslen') and fn not in self.function_definitions and fn not in self.shadows:
                return () # A scalar length is not the sensitive material itself.
            args=n.child_by_field_name('arguments')
            if fn not in self.shadows and fn not in self.function_definitions and (fn in dict(self.model.output_calls) or fn in ('memcpy_s','strcpy_s','snprintf','snprintf_s')):
                return () # modeled return is a status/count, not the output buffer
            vals=tuple(v for a in (args.named_children if args else []) for v in self.expr(a,env,types))
            # Unknown transform is not a sanitizer. Retain a tentative dependency and gap.
            if vals:self.gaps.add('unresolved transform/call '+fn)
            return vals
        return tuple(v for c in n.named_children for v in self.expr(c,env,types))

    def addstep(self,flows,text):
        return tuple(Flow(f.steps+(text,)) for f in flows)

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
        line=node.start_point[0]+1
        traces=sorted(set(' -> '.join(flow.steps+(f'{line} unresolved call {fn}',))
                          for flow in flows))
        self.findings.append(DetectorFinding(
            file=self.u.path,line=line,symbol=fnname,
            rule_id='data.sensitive.unresolved-escape',candidate_cwe=None,
            evidence_type='syntax',source_sha256=self.u.sha256,
            message='Candidate sensitive-data escape with unresolved callee: '
                    +reason+'; path='+' | '.join(traces),
            evidence_obligations=(
                EvidenceObligation('callee_binding','Resolve the exact overload, receiver, and implementation for '+fn+'.'),
                EvidenceObligation('sink_behavior','Determine whether the callee logs, serializes, stores, or safely transforms the sensitive value.'),
                EvidenceObligation('runtime_log_visibility','No log exposure or reader reachability is established by this call alone.'),
                EvidenceObligation('security_impact','Establish recoverable sensitive material and concrete impact independently.'),
            )))

    def expand_tainted_call(self,fn,args,env,types,call_line,call_node=None,fnname=''):
        """Analyze one bounded same-file helper call and summarize return/out flows."""
        definitions=self.function_nodes.get(fn,())
        if not definitions or fn in self.sinks:
            return False
        if fn in self.call_stack or len(self.call_stack)>=3:
            self.gaps.add('same-file call expansion stopped by recursion/depth bound: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'recursion/depth limit stopped body analysis')
            return True
        arg_flows=[self.expr(arg,env,types) for arg in args]
        matching=[]
        for definition in definitions:
            d=definition.child_by_field_name('declarator')
            fd=next((x for x in walk(d) if x.type=='function_declarator'),None) if d else None
            params=fd.child_by_field_name('parameters') if fd else None
            parameters=[p for p in params.named_children if p.type!='variadic_parameter'] if params else []
            if len(parameters)==len(args):matching.append((definition,parameters))
        if not matching:
            self.gaps.add('same-file helper call has unresolved overload/arity: '+fn)
            if call_node is not None:
                self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                            'same-file overload/arity binding failed')
            return True
        if len(matching)>1:
            self.gaps.add('same-file helper call has ambiguous definitions: '+fn)
        returned=[]
        outputs={}
        for definition,parameters in matching:
            d=definition.child_by_field_name('declarator')
            fd=next((x for x in walk(d) if x.type=='function_declarator'),None) if d else None
            body=definition.child_by_field_name('body')
            if not fd or not body:
                self.gaps.add('same-file helper definition lacks a supported body: '+fn)
                if call_node is not None:
                    self.emit_unresolved_escape(fn,args,env,types,call_node,fnname,
                                                'same-file helper body is unsupported')
                continue
            local_values={};local_types={};local_shadows=set();bound=[]
            for index,param in enumerate(parameters):
                ident=self.name(param.child_by_field_name('declarator'))
                bound.append(ident)
                if not ident:continue
                local_shadows.add(ident)
                local_values[ident]=self.addstep(arg_flows[index],
                    f'{call_line} call {fn} argument {index}')
                typ=self.text(param.child_by_field_name('type'))
                if typ in self.fields:local_types[ident]=typ
            self.call_stack.append(fn)
            try:
                self.gaps.add('bounded same-file helper expansion; cross-file and deeper call flows remain unknown')
                result=self.block(body,LocalState(local_values,local_types,local_shadows),fn)
            finally:
                self.call_stack.pop()
            returned.extend(flow for exit in result.exit_states
                            if exit.kind=='return_statement' for flow in exit.returned)
            states=([result.fallthrough_state] if result.fallthrough_state is not None else [])
            states.extend(exit.state for exit in result.exit_states)
            for index,(param,ident) in enumerate(zip(parameters,bound)):
                if not ident or not re.search(r'[&*]',self.text(param)):
                    continue
                actual=self.lvalue(args[index])
                if not actual:continue
                writes=tuple(dict.fromkeys(flow for state in states
                                           for flow in state.values.get(ident,())))
                if writes:
                    outputs.setdefault(actual,[]).extend(
                        self.addstep(writes,f'{call_line} {fn} may write through argument {index}'))
        for actual,flows in outputs.items():
            env[actual]=tuple(dict.fromkeys(tuple(env.get(actual,()))+tuple(flows)))
        call_flows=self.addstep(tuple(dict.fromkeys(returned)),
                                f'{call_line} return from {fn}')
        if call_node is not None:
            self.call_results[call_node.id]=call_flows
        return True

    def lvalue(self,node):
        if node is None:return ''
        if node.type=='identifier':return self.text(node)
        if node.type in ('pointer_expression','unary_expression'):
            op=self.text(node.child_by_field_name('operator'))
            if op=='&':
                return self.lvalue(node.child_by_field_name('argument'))
        return ''

    def emit_log_candidate(self,fn,fnname,node,flows,message,extra_obligation):
        line=node.start_point[0]+1
        traces=sorted(set(' -> '.join(flow.steps+(f'{line} {fn} unresolved public-operand status',))
                          for flow in flows))
        self.findings.append(DetectorFinding(
            file=self.u.path,line=line,symbol=fnname,rule_id='data.log.sensitive-value',
            candidate_cwe='CWE-532',evidence_type='syntax',source_sha256=self.u.sha256,
            message='Candidate local sensitive-material dependency: '+message+' path='+' | '.join(traces),
            evidence_obligations=(
                EvidenceObligation('local_flow',' | '.join(traces)),
                EvidenceObligation('source_semantics',self.model.provenance),
                extra_obligation,
                EvidenceObligation('runtime_log_visibility','Verify production level, privacy switches, build branch and unauthorized readers.'),
                EvidenceObligation('security_impact','Prove recoverable secret material and concrete impact; no automatic confirmation.'),
            )))

    def call(self,n,env,types,fnname):
        fn=self.text(n.child_by_field_name('function')); a=n.child_by_field_name('arguments')
        args=list(a.named_children) if a else []
        if fn in self.shadows:
            self.gaps.add('call target is shadowed by a local value: '+fn)
            return
        locally_defined=fn in self.function_definitions
        if fn in ('strlen','strnlen','strnlen_s','wcslen') and not locally_defined:
            return
        if locally_defined and fn in dict(self.model.output_calls):
            self.gaps.add('modeled source name has a same-file definition; source identity unresolved: '+fn)
            return
        if locally_defined and fn in ('memcpy_s','strcpy_s'):
            self.gaps.add('same-file copy-like definition has unresolved write semantics: '+fn)
            if len(args) >= 2:
                dst=self.text(args[0])
                if re.fullmatch(r'[A-Za-z_]\w*',dst):
                    source=args[2] if len(args)>2 else args[-1]
                    env[dst]=self.addstep(self.expr(source,env,types),f'{n.start_point[0]+1} unresolved {fn} may write {dst}')
            return
        if locally_defined and fn in ('snprintf','snprintf_s'):
            self.gaps.add('same-file formatting name has unresolved write semantics: '+fn)
            if len(args) >= 2:
                dst=self.text(args[0])
                if re.fullmatch(r'[A-Za-z_]\w*',dst):
                    flows=tuple(flow for arg in args[1:] for flow in self.expr(arg,env,types))
                    env[dst]=self.addstep(flows,f'{n.start_point[0]+1} unresolved {fn} may write {dst}')
            return
        if locally_defined and fn in self.sinks:
            bodies=self.function_bodies.get(fn, [])
            if len(bodies)==1 and bodies[0] is not None and not any(
                    child.type not in ('comment','empty_statement') for child in bodies[0].named_children):
                self.gaps.add('same-file modeled sink resolves to a visible empty body: '+fn)
                return
            self.gaps.add('same-file modeled sink has unresolved implementation identity: '+fn)
        if locally_defined and self.expand_tainted_call(
                fn,args,env,types,n.start_point[0]+1,n,fnname):
            return
        if fn in dict(self.model.output_calls):
            if len(args)!=2:
                self.gaps.add('source API argument count unresolved');return
            index=dict(self.model.output_calls)[fn]
            if index<len(args):
                dst=self.text(args[index]).lstrip('&')
                if re.fullmatch(r'[A-Za-z_]\w*',dst):env[dst]=(self.source(fn+' output argument '+str(index),n),)
                else:self.gaps.add('complex source output destination')
            return
        if fn in ('memcpy_s','strcpy_s'):
            if len(args)!=(4 if fn=='memcpy_s' else 3):
                self.gaps.add('copy API argument count unresolved');return
            dst=self.text(args[0])
            if re.fullmatch(r'[A-Za-z_]\w*',dst):
                env[dst]=self.addstep(self.expr(args[2],env,types),f'{n.start_point[0]+1} {fn} -> {dst}')
            else:self.gaps.add('member/pointer output copy unsupported')
            return
        if fn in ('snprintf','snprintf_s'):
            fi=2 if fn=='snprintf' else 3
            if len(args)<=fi:return
            try:
                slots,count=formats(self.literal(args[fi]))
                operands=args[fi+1:]
                if count!=len(operands):raise ValueError('format arity')
                vals=tuple(v for _,ids,_ in slots for i in ids for v in self.expr(operands[i],env,types))
                dst=self.text(args[0]);env[dst]=self.addstep(vals,f'{n.start_point[0]+1} {fn} -> {dst}')
            except (ValueError,SyntaxError):self.gaps.add('unsupported formatting propagation')
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
            slots,count=formats(self.literal(args[sink.format_index]), 'private' if sink.default_private else 'public')
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
                if any(self.expr(operands[i],env,types) for i in ids):
                    self.gaps.add('private operand requires runtime privacy-configuration review')
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
        return out

    def replace_state(self,state,new):
        state.values,state.types,state.shadows=new.values,new.types,new.shadows

    def apply_call(self,node,state,fnname):
        before=self.shadows
        self.shadows=state.shadows
        try:self.call(node,state.values,state.types,fnname)
        finally:self.shadows=before

    def value(self,node,state):
        before=self.shadows
        self.shadows=state.shadows
        try:return self.expr(node,state.values,state.types)
        finally:self.shadows=before

    def effects(self,node,state,fnname):
        """Bounded evaluation effects; short circuit/?: merge possible live states."""
        if node is None:return
        if node.type=='lambda_expression':
            self.gaps.add('lambda execution not analyzed');return
        if node.type=='assignment_expression':
            right=node.child_by_field_name('right');left=node.child_by_field_name('left')
            self.effects(right,state,fnname)
            if left is not None and left.type=='identifier':
                op=self.text(node.child_by_field_name('operator'))
                if op!='=':self.gaps.add('compound assignment semantics incomplete')
                state.values[self.text(left)]=self.addstep(self.value(right,state),f'{node.start_point[0]+1} assign {self.text(left)}')
            else:self.gaps.add('pointer/member assignment requires alias proof')
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
        for child in node.named_children:self.effects(child,state,fnname)

    def declaration(self,node,state,fnname):
        type_text=self.text(node.child_by_field_name('type'))
        declared=set()
        for d in node.named_children:
            if d.type not in ('init_declarator','identifier','pointer_declarator','array_declarator'):continue
            name=self.name(d)
            if not name:continue
            declared.add(name);state.types.pop(name,None);state.values[name]=();state.shadows.add(name)
            if type_text in self.fields:state.types[name]=type_text
            value=d.child_by_field_name('value')
            if value:
                self.effects(value,state,fnname)
                state.values[name]=self.addstep(self.value(value,state),f'{node.start_point[0]+1} assign {name}')
        return declared

    @staticmethod
    def restore_scope(state,entry,declared):
        if state is None:return
        for name in declared:
            if name in entry.values:state.values[name]=entry.values[name]
            else:state.values.pop(name,None)
            if name in entry.types:state.types[name]=entry.types[name]
            else:state.types.pop(name,None)
            if name in entry.shadows:state.shadows.add(name)
            else:state.shadows.discard(name)

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
            cond=node.child_by_field_name('condition');self.effects(cond,state,fnname)
            if cond and any(x.type=='declaration' for x in walk(cond)):
                self.gaps.add('if initializer binding not analyzed')
            known=self.truth(cond);results=[]
            fields=('consequence',) if known is True else ('alternative',) if known is False else ('consequence','alternative')
            for field in fields:
                child=node.child_by_field_name(field);branch=state.clone()
                if child is None:result=BlockResult(branch)
                elif child.type=='declaration':
                    # Implicit branch scope: names do not escape the branch.
                    entry=branch.clone();names=self.declaration(child,branch,fnname)
                    self.restore_scope(branch,entry,names);result=BlockResult(branch)
                else:result=self.statement(child,branch,fnname)
                results.append(result)
            return BlockResult(self.merge([r.fallthrough_state for r in results]),
                               tuple(exit for result in results for exit in result.exit_states))
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
            for header in node.named_children:
                if header.id == body.id:
                    continue
                if header.type=='declaration':self.declaration(header,state,fnname)
                else:self.effects(header,state,fnname)
            branch=state.clone()
            result=self.statement(body,branch,fnname)
            return BlockResult(self.merge([state,result.fallthrough_state,
                                           *(e.state for e in result.exit_states)]))
        # Switch/try effects are not interpreted or claimed safe.
        self.gaps.add(f'unsupported statement {kind} at line {node.start_point[0]+1}')
        return BlockResult(state)

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
        file_gaps=set(self.gaps);all_gaps=set(self.gaps)
        for fn in (n for n in walk(self.tree.root_node) if n.type=='function_definition'):
            self.gaps=set(file_gaps)
            body=fn.child_by_field_name('body');d=fn.child_by_field_name('declarator')
            fd=next((x for x in walk(d) if x.type=='function_declarator'),None) if d else None
            if not body or not fd:continue
            name=self.text(fd.child_by_field_name('declarator'));env={};types={}
            params=fd.child_by_field_name('parameters')
            original_shadows=set(self.shadows)
            for index,p in enumerate(params.named_children if params else []):
                ident=self.name(p.child_by_field_name('declarator'))
                typ=self.text(p.child_by_field_name('type'))
                self.shadows.add(ident)
                if typ in self.fields:types[ident]=typ
                if (self.u.path,name,index) in self.model.parameters:
                    env[ident]=(self.source(name+' parameter '+str(index),p),)
            result=self.block(body,LocalState(env,types,set(self.shadows)),name)
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
                merged[key]=replace(old,message=old.message+' | '+f.message,evidence_obligations=old.evidence_obligations+f.evidence_obligations)
        return list(merged.values())
