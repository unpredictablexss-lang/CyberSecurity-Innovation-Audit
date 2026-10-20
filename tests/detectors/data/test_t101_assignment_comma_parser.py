"""T101 independent lawful assignment-comma parsing, precedence and original offsets."""
import hashlib
import unittest
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow
LOG='HILOG_INFO(1,"%{public}s",out);'
PROTO='int HILOG_INFO(int,const char*,...);void Use(unsigned);\n'


def body(statement):
    return PROTO+'void Callback(const char *key,bool flag){const char*out=nullptr;'+statement+'\n'+LOG+'\n}'


CASE_SEMANTICS={
 'initializer':'Assignment evaluates before builtin comma RHS zero; out receives key. Parser must not reassociate as out=(key,0).',
 'expression-statement':'Parenthesized assignment comma is a legal expression statement; lhs assignment effect reaches out log.',
 'multiple-comma':'Left assignment persists through additional discarded scalar operands.',
 'nested-comma':'Nested parenthesis and comma retain exact original grouping/assignment effect.',
 'call-argument':'One parenthesized comma expression is a single Use argument; comma is not an argument separator.',
 'conditional-assignment-rhs':'The assignment RHS is a conditional material pointer; comma zero is outside that assignment.',
 'conditional-branch-comma':'One conditional branch evaluates assignment comma; it may set out to material.',
 'bare-comma-control':'Unparenthesized assignment comma already parsed complete in baseline; do not regress it.',
 'double-parentheses-control':'Parenthesized assignment as lhs already parsed complete; preserve this control.',
 'return-comma-effect':'Return comma executes assignment before actual HILOG sink; caller invokes helper with material.',
 'return-pointer-output':'Return comma writes through out parameter; Caller local receives actual material and logs it.',
 'cpp-surrounding-syntax':'C++ namespace/template/class declarations outside repaired subtree must retain their C++ AST identity.',
 'utf8-crlf-offsets':'Non-ASCII and CRLF bytes before/around recovered expression cannot shift original calls or raw bytes.',
 'const-pointer-output-known-gap':'Const double-pointer output summary is not bound; the equivalent baseline complete double-parenthesis form also has only unresolved *out, not actual caller out log.',
 'const-pointer-output-complete-control':'Complete double-parenthesis control isolates the pre-existing const double-pointer summary gap from parser overlay.',
 'assignment-comma-code-value-known-gap':'Material reaches out, but literal-zero comma result code remains overtainted when assignment operand type proof is unsupported.',
 'scalar-assignment':'Scalar assignment receives key byte before discarded literal; actual scalar log remains.'}


def fixtures():
    rows=[]
    for name,stmt in (
      ('initializer','unsigned code=(out=key,0);'),
      ('expression-statement','(out=key,0);'),
      ('multiple-comma','unsigned code=(out=key,7,0);'),
      ('nested-comma','unsigned code=((out=key,0),1);'),
      ('call-argument','Use((out=key,0));'),
      ('conditional-assignment-rhs','unsigned code=(out=flag?key:"p",0);'),
      ('conditional-branch-comma','unsigned code=flag?(out=key,0):7;'),
      ('bare-comma-control','out=key,0;'),
      ('double-parentheses-control','unsigned code=((out=key),0);')):
        rows.append((name,body(stmt),LOG,'log'))
    effect=PROTO+'unsigned Status(const char *value){const char*out=nullptr;return(out=value,HILOG_INFO(1,"%{public}s",out),0); }\nvoid Callback(const char *key){unsigned code=Status(key);}'
    # This legal shape has mismatched raw C++ recovery span; kept below as coverage gap.
    output=PROTO+'unsigned Write(unsigned value,unsigned *out){return(*out=value,0); }\nvoid Callback(unsigned key){unsigned out=0;unsigned code=Write(key,&out);\nHILOG_INFO(1,"%{public}u",out);\n}'
    rows.append(('return-pointer-output',output,'HILOG_INFO(1,"%{public}u",out);','log'))
    cpp='namespace N { struct Tag{int member;}; template<typename T> T id(T value){return value;} }\n'+body('unsigned code=(out=key,0);')
    rows.append(('cpp-surrounding-syntax',cpp,LOG,'log'))
    unicode=('// 中文 offset witness\n'+body('unsigned code=(out=key,0);')).replace('\n','\r\n')
    rows.append(('utf8-crlf-offsets',unicode,LOG,'log'))
    scalar=PROTO+'void Callback(unsigned key){unsigned count=0;unsigned code=(count=key,0);\nHILOG_INFO(1,"%{public}u",count);\n}'
    rows.append(('scalar-assignment',scalar,'HILOG_INFO(1,"%{public}u",count);','log'))
    return rows


UNMATCHED_RETURN_SPAN=PROTO+'unsigned Status(const char *value){const char*out=nullptr;return(out=value,HILOG_INFO(1,"%{public}s",out),0); }\nvoid Callback(const char *key){unsigned code=Status(key);}'
CONST_POINTER_OUTPUT_GAP=PROTO+'unsigned Write(const char *value,const char **out){return(*out=value,0); }\nvoid Callback(const char *key){const char*out=nullptr;unsigned code=Write(key,&out);\n'+LOG+'\n}'

CODE_VALUE_GAP=body('unsigned code=(out=key,0);').replace('\n'+LOG,'\n'+LOG+'\nHILOG_INFO(1,"%{public}u",code);')

ILLEGAL=[body('unsigned code=(out=key,,0);'),body('unsigned code=(out=,0);'),body('unsigned code=(out key,0);'),body('unsigned code=(out=key,0;')]


UNSUPPORTED_CPP=[
    'template<int N> const char*Pick(const char*v){return v;}\n'+body('unsigned code=(out=Pick<0>(key),0);'),
    body('unsigned code=(out=[](const char*v){return v;}(key),0);'),
    body('unsigned code=(out=[](const char*v) [[nodiscard]] {return v;}(key),0);'),
    'struct Envelope{const char *text;};const char *operator,(Envelope,int);\n'+PROTO+'void Callback(const char*key){Envelope e{key};const char*out=nullptr;unsigned code=(out=operator,(e,0),0);\n'+LOG+'\n}',
    body('unsigned code=(out=key /* marker */,0);'),
    body('unsigned code=(out=key,\n#if FLAG\n0\n#else\n1\n#endif\n);'),
    '#include <typeinfo>\n'+body('unsigned code=(out=typeid(key).name(),0);')]


def nodes(node):
    yield node
    for child in node.named_children:yield from nodes(child)


class T101CommaParserTests(unittest.TestCase):
    def context(self,s):return t93.T93ScalarPointerTests().context(s)
    def rows(self,s,runner=False):return t93.T93ScalarPointerTests().rows(s,runner=runner)
    def check(self,name):
        for n,s,statement,_ in fixtures():
            if n!=name:continue
            ctx=self.context(s);unit=ctx.units[0]
            flow=LocalFlow(unit,t93.t89.MODEL)
            self.assertEqual('complete',unit.parse_status)
            self.assertFalse(flow.tree.root_node.has_error)
            self.assertEqual(s.encode(),flow.b)
            self.assertEqual(len(s.encode()),flow.tree.root_node.end_byte)
            line=next(i for i,text in enumerate(s.splitlines(),1) if statement in text)
            for runner in (False,True):
                with self.subTest(case=name,runner=runner):
                    rows=self.rows(s,runner)
                    self.assertTrue(any(r['line']==line and 'HILOG_INFO' in r['message'] and 'Callback parameter 0' in r['message'] for r in rows),rows)
    def test_initializer(self):self.check('initializer')
    def test_expression_statement(self):self.check('expression-statement')
    def test_multiple_comma(self):self.check('multiple-comma')
    def test_nested_comma(self):self.check('nested-comma')
    def test_call_argument(self):
        self.check('call-argument')
        s=next(row[1] for row in fixtures() if row[0]=='call-argument')
        call=next(c for c in self.context(s).shared_facts['ast']['service.cpp']['calls'] if c['name']=='Use')
        self.assertEqual(['(out=key,0)'],call['arguments'])
    def test_conditional_assignment_rhs(self):self.check('conditional-assignment-rhs')
    def test_conditional_branch_comma(self):self.check('conditional-branch-comma')
    def test_existing_bare_comma(self):self.check('bare-comma-control')
    def test_existing_double_parentheses(self):self.check('double-parentheses-control')
    def test_unmatched_recovery_span_stays_partial(self):
        ctx=self.context(UNMATCHED_RETURN_SPAN)
        self.assertEqual('partial',ctx.units[0].parse_status)
        self.assertTrue(LocalFlow(ctx.units[0],t93.t89.MODEL).tree.root_node.has_error)
        result,coverage=t93.T93ScalarPointerTests().analyze(UNMATCHED_RETURN_SPAN,runner=True)
        self.assertEqual('blocked',result['status'])
        self.assertEqual(1,coverage['detectors']['ohscanner.data.sensitive_exposure']['coverage_counts']['not_analyzed'])
    def test_return_pointer_output(self):self.check('return-pointer-output')
    def test_scalar_assignment(self):self.check('scalar-assignment')
    def test_cpp_surroundings(self):
        self.check('cpp-surrounding-syntax')
        s=next(r[1] for r in fixtures() if r[0]=='cpp-surrounding-syntax')
        flow=LocalFlow(self.context(s).units[0],t93.t89.MODEL)
        types=[n.type for n in nodes(flow.tree.root_node)]
        for kind in ('namespace_definition','struct_specifier','template_declaration'):self.assertIn(kind,types)
    def test_original_utf8_crlf_positions(self):
        self.check('utf8-crlf-offsets')
        for _,s,_,_ in fixtures():
            ctx=self.context(s);data=s.encode()
            for call in ctx.shared_facts['ast']['service.cpp']['calls']:
                start,end=call['start_byte'],call['end_byte']
                self.assertEqual(call['line'],data[:start].count(b'\n')+1)
                self.assertIn(call['name'].encode(),data[start:end])
                self.assertGreater(end,start)
    def test_assignment_comma_precedence_in_ast(self):
        s=next(row[1] for row in fixtures() if row[0]=='initializer')
        flow=LocalFlow(self.context(s).units[0],t93.t89.MODEL)
        paren=next(n for n in nodes(flow.tree.root_node) if n.type=='parenthesized_expression' and flow.text(n)=='(out=key,0)')
        self.assertEqual(1,len(paren.named_children))
        comma=paren.named_children[0]
        self.assertEqual('comma_expression',comma.type)
        assignment=comma.child_by_field_name('left')
        self.assertEqual('assignment_expression',assignment.type)
        self.assertEqual('out',flow.text(assignment.child_by_field_name('left')))
        self.assertEqual('key',flow.text(assignment.child_by_field_name('right')))
        self.assertEqual('0',flow.text(comma.child_by_field_name('right')))
    def test_illegal_expressions_stay_partial(self):
        for s in ILLEGAL:
            with self.subTest(source=s):
                ctx=self.context(s)
                self.assertEqual('partial',ctx.units[0].parse_status)
                self.assertTrue(LocalFlow(ctx.units[0],t93.t89.MODEL).tree.root_node.has_error)
    def test_cpp_only_and_protected_subtrees_stay_partial(self):
        for s in UNSUPPORTED_CPP:
            with self.subTest(source=s):
                ctx=self.context(s)
                self.assertEqual('partial',ctx.units[0].parse_status)
                self.assertTrue(LocalFlow(ctx.units[0],t93.t89.MODEL).tree.root_node.has_error)
    def test_lexical_lookalikes_do_not_create_assignments(self):
        s=PROTO+'// (out=key,0)\n#define UNUSED (out=key,0)\nvoid Callback(const char *key){const char*out="(out=key,0)";const char*raw=R"tag((out=key,0))tag";\n'+LOG+'\n}'
        ctx=self.context(s)
        self.assertEqual('complete',ctx.units[0].parse_status)
        for runner in (False,True):self.assertEqual([],self.rows(s,runner))

if __name__=='__main__':unittest.main()
