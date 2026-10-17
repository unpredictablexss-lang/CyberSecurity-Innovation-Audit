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
    version = '0.1.0'
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
        if n.type=='binary_expression':
            op=self.text(n.child_by_field_name('operator'))
            if op in ('==','!=','<','>','<=','>=','&&','||'):return ()
        if n.type=='unary_expression' and self.text(n).lstrip().startswith('!'):return ()
        if n.type=='call_expression':
            fn=self.text(n.child_by_field_name('function'))
            args=n.child_by_field_name('arguments')
            if fn in dict(self.model.output_calls) or fn in ('memcpy_s','strcpy_s','snprintf','snprintf_s'):
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
            if fn in self.sinks or fn in dict(self.model.output_calls):self.gaps.add('same-file modeled name shadowed: '+fn)
            return
        if fn in dict(self.model.output_calls):
            index=dict(self.model.output_calls)[fn]
            if index<len(args):
                dst=self.text(args[index]).lstrip('&')
                if re.fullmatch(r'[A-Za-z_]\w*',dst):env[dst]=(self.source(fn+' output argument '+str(index),n),)
                else:self.gaps.add('complex source output destination')
            return
        if fn in ('memcpy_s','strcpy_s') and len(args)>=3:
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

    def block(self,node,env,types,fnname):
        for n in node.named_children:
            if n.type=='return_statement':
                if any(x.type=='call_expression' for x in walk(n)):
                    self.gaps.add('calls in return expression not analyzed')
                return False
            if n.type=='declaration':
                type_text=self.text(n.child_by_field_name('type'))
                for d in n.named_children:
                    if d.type not in ('init_declarator','identifier','pointer_declarator','array_declarator'):continue
                    name=self.name(d)
                    if not name:continue
                    types.pop(name,None);env.pop(name,None)
                    if type_text in self.fields:types[name]=type_text
                    value=d.child_by_field_name('value')
                    if value:
                        for call in walk(value):
                            if call.type=='call_expression':self.call(call,env,types,fnname)
                        env[name]=self.addstep(self.expr(value,env,types),f'{n.start_point[0]+1} assign {name}')
            elif n.type=='expression_statement':
                for e in n.named_children:
                    if e.type=='assignment_expression':
                        left=e.child_by_field_name('left');right=e.child_by_field_name('right');name=self.text(left)
                        if left.type=='identifier':env[name]=self.addstep(self.expr(right,env,types),f'{e.start_point[0]+1} assign {name}')
                        else:self.gaps.add('pointer/member assignment requires alias proof')
                    elif e.type=='call_expression':self.call(e,env,types,fnname)
                    else:self.gaps.add('unsupported expression statement')
            elif n.type=='if_statement':
                self.gaps.add('branch merge is may-flow; no path feasibility proof')
                cond=n.child_by_field_name('condition')
                if cond:
                    for call in walk(cond):
                        if call.type=='call_expression':self.call(call,env,types,fnname)
                branches=[]
                for field in ('consequence','alternative'):
                    child=n.child_by_field_name(field);e=dict(env);t=dict(types)
                    if child and child.type=='compound_statement':self.block(child,e,t,fnname)
                    elif child:self.gaps.add('noncompound branch not analyzed')
                    branches.append(e)
                for key in env.keys()|branches[0].keys()|branches[1].keys():
                    if key in env:env[key]=tuple(dict.fromkeys(branches[0].get(key,())+branches[1].get(key,())))
            elif n.type=='compound_statement':
                # Restore block-local bindings; preserve assignments to outer names.
                e=dict(env);t=dict(types);self.block(n,e,t,fnname)
                declared={self.name(d) for x in n.named_children if x.type=='declaration' for d in x.named_children if d.type in ('init_declarator','identifier','pointer_declarator','array_declarator')}
                for key in env:
                    if key not in declared:env[key]=e.get(key,())
            elif n.type in ('comment',):continue
            else:self.gaps.add('unsupported statement '+n.type)
        return True

    def run(self):
        if self.tree.root_node.has_error:self.gaps.add('detailed syntax partial')
        for fn in (n for n in walk(self.tree.root_node) if n.type=='function_definition'):
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
            self.block(body,env,types,name)
            self.shadows=original_shadows
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
