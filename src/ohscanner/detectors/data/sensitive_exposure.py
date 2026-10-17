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


@dataclass(frozen=True)
class BlockResult:
    fallthrough_state: object
    exit_states: tuple = ()
    limitations: tuple = ()


def walk(n):
    yield n
    for c in n.named_children:
        yield from walk(c)


def formats(value):
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
        out.append((match.group(1) or 'private', tuple(indexes), match.group(4)))
        pos = match.end()
    return out, arg


class SensitiveExposureDetector:
    detector_id = 'ohscanner.data.sensitive_exposure'
    version = '0.2.0'
    supported_languages = ('c', 'cpp')
    required_facts = ('ast',)

    def __init__(self, model=DEFAULT_SOURCE):
        self.model = model

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
            analysis = LocalFlow(u, self.model)
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
        self.type_conflicts = set()
        for n in walk(self.tree.root_node):
            if n.type == 'function_definition':
                d=n.child_by_field_name('declarator')
                if d:
                    fd=next((x for x in walk(d) if x.type=='function_declarator'),None)
                    if fd:self.shadows.add(self.text(fd.child_by_field_name('declarator')))
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
            fn=self.text(n.child_by_field_name('function'))
            args=n.child_by_field_name('arguments')
            if fn not in self.shadows and (fn in dict(self.model.output_calls) or fn in ('memcpy_s','strcpy_s','snprintf','snprintf_s')):
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

    def call(self,n,env,types,fnname):
        fn=self.text(n.child_by_field_name('function')); a=n.child_by_field_name('arguments')
        args=list(a.named_children) if a else []
        if fn in self.shadows:
            if fn in self.sinks or fn in dict(self.model.output_calls) or fn in ('memcpy_s','strcpy_s','snprintf','snprintf_s'):self.gaps.add('same-file modeled name shadowed: '+fn)
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
            if any(self.expr(x,env,types) for x in args):self.gaps.add('unmodeled call may mutate/escape sensitive value: '+fn)
            return
        sink=self.sinks[fn]
        self.sink_sites.append({'symbol':fn,'line':n.start_point[0]+1,'format_index':sink.format_index})
        if len(args)<=sink.format_index:
            self.gaps.add('missing log format');return
        try:
            slots,count=formats(self.literal(args[sink.format_index]))
            operands=args[sink.format_index+1:]
            if count!=len(operands):raise ValueError('format/argument mismatch')
        except (ValueError,SyntaxError):
            self.gaps.add('nonliteral/unsupported log format: '+fn);return
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
            if kind=='return_statement' and any(x.type=='call_expression' for x in walk(node)):
                self.gaps.add('calls in return expression not analyzed')
            if kind in ('break_statement','continue_statement'):
                self.gaps.add('break/continue exits need enclosing-loop proof; loops not analyzed')
            return BlockResult(None,(ExitState(kind,node.start_point[0]+1,state.clone()),))
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
        # Loop/switch/try effects are not interpreted or claimed safe.
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
