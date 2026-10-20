"""T100 independent builtin comma values, operand effects and overload guards."""
import unittest
from tests.detectors.data import test_t99_nested_return_arms as t99
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
FIRST_LOG='HILOG_INFO(1,"%{public}u",code);'
MATERIAL_LOG='HILOG_INFO(1,"%{public}s",out);'


def scalar(expr):
    return 'void HILOG_INFO(int,const char*,...);\nvoid Callback(const char *key,bool flag){unsigned code='+expr+';\n'+FIRST_LOG+'\n}'


def pointer(expr):
    return 'void HILOG_INFO(int,const char*,...);\nvoid Callback(const char *key,bool flag){const char *out='+expr+';\n'+MATERIAL_LOG+'\n}'


OVERLOAD_SOURCE='void HILOG_INFO(int,const char*,...);\nstruct Envelope{const char *text;};Envelope Wrap(const char*value){return {value};}\nconst char *operator,(Envelope e,int){return e.text;}\nconst char *Select(const char*value){return (Wrap(value),0);}\nvoid Callback(const char*key){const char*out=Select(key);\n'+MATERIAL_LOG+'\n}'
CLASS_NAMED_SINK='struct Envelope{const char *text;};Envelope HILOG_INFO(int,const char*,...);\nconst char *operator,(Envelope e,int){return e.text;}\nconst char *Select(const char*value){return (HILOG_INFO(1,"%{public}s",value),0);}\nvoid Callback(const char*key){const char*out=Select(key);\n'+MATERIAL_LOG+'\n}'
CALLBACK_SHADOW='void HILOG_INFO(int,const char*,...);struct Envelope{const char *text;};int Audit(const char*);\nconst char *operator,(Envelope e,int){return e.text;}\nvoid Callback(const char*key,Envelope(*Audit)(const char*)){const char *out=(Audit(key),0);\n'+MATERIAL_LOG+'\n}'

CASE_SEMANTICS={
 'scalar-literal':'Both operands are fundamental pointer/integer values: builtin comma yields literal zero and no source dependence.',
 'multi-literal':'Builtin scalar comma sequence returns only the final zero.',
 'nested-literal':'Parentheses preserve builtin comma value; nested discarded source operand cannot taint final integer.',
 'last-material':'Final pointer operand is the modeled material and must reach its log.',
 'multi-last-material':'Last operand controls builtin comma result, even with multiple earlier literals.',
 'conditional-last-material':'Final conditional may yield material; must retain the candidate without path feasibility claims.',
 'status-return':'T99 int-prototyped sink executes with material, but literal-zero builtin comma return must not taint caller code.',
 'overload-material':'Visible user-defined operator comma returns Envelope.text; literal RHS zero does not make the result public.',
 'class-named-sink':'HILOG_INFO spelling is not proof of scalar return; its class return can select overloaded comma.',
 'callback-shadow':'A class-returning callable parameter shadows global scalar-return Audit; no name-only prototype proof.',
 'macro-scope':'Selected preprocessing directive rejects bounded builtin proof; candidate conservatism is not actual leak truth.',
 'unknown-final-call':'Final unknown call receives material; its callee obligations and may-flow must remain.',
 'alias-unknown':'A selected using alias is outside the primitive type proof; preserved taint is conservative, not a leak label.',
 'overloaded-prototype-unknown':'Multiple Audit overloads reject unique prototype proof; calls retain unresolved obligations.',
 'left-assignment-effect':'Discarded lhs still executes assignment of material to out, which reaches its actual log.',
 'unique-call-literal':'A unique visible int Audit prototype proves scalar return type only; actual Audit behavior remains unresolved and effects cannot disappear.',
 'partial-selected-unit':'Selected partial header invalidates builtin proof in both entrypoints.'}


def fixtures():
    status=t99.COMMA_GAP_SOURCE
    unknown='const char *Unknown(const char*);\n'+pointer('(0,Unknown(key))')
    rows=[
      ('scalar-literal',scalar('(key,0)'),FIRST_LOG,'no-log'),
      ('multi-literal',scalar('(key,7,0)'),FIRST_LOG,'no-log'),
      ('nested-literal',scalar('((key,0),1)'),FIRST_LOG,'no-log'),
      ('last-material',pointer('(0,key)'),MATERIAL_LOG,'log'),
      ('multi-last-material',pointer('(0,7,key)'),MATERIAL_LOG,'log'),
      ('conditional-last-material',pointer('(0,flag?key:"public")'),MATERIAL_LOG,'log'),
      ('status-return',status,FIRST_LOG,'no-log'),
      ('status-return-internal-log',status,'HILOG_INFO(1,"%{public}s",value)','log'),
      ('overload-material',OVERLOAD_SOURCE,MATERIAL_LOG,'log'),
      ('class-named-sink',CLASS_NAMED_SINK,MATERIAL_LOG,'log'),
      ('callback-shadow',CALLBACK_SHADOW,MATERIAL_LOG,'log'),
      ('macro-scope','#define BUILD_FLAG 1\n'+scalar('(key,0)'),FIRST_LOG,'log'),
      ('unknown-final-call',unknown,MATERIAL_LOG,'log')]
    alias='using Text=const char*;\n'+scalar('(key,0)').replace('const char *key','Text key')
    overload='int Audit(const char*);int Audit(int);\n'+scalar('(Audit(key),0)')
    rows.extend([('alias-unknown',alias,FIRST_LOG,'log'),('overloaded-prototype-unknown',overload,FIRST_LOG,'log')])
    assign='void HILOG_INFO(int,const char*,...);\nvoid Callback(const char *key){const char*out=nullptr;unsigned code=((out=key),0);\n'+MATERIAL_LOG+'\n}'
    unique='int Audit(const char*);\n'+scalar('(Audit(key),0)')
    rows.extend([('left-assignment-effect',assign,MATERIAL_LOG,'log'),('unique-call-literal',unique,FIRST_LOG,'no-log'),('unique-call-literal-effect',unique,'Audit(key)','material')])
    return rows


class T100CommaTests(unittest.TestCase):
    def context(self,s):return t93.T93ScalarPointerTests().context(s)
    def rows(self,s,runner=False,**kw):return t93.T93ScalarPointerTests().rows(s,runner=runner,**kw)
    def check(self,prefix):
        for name,s,statement,contract in fixtures():
            if name!=prefix and not name.startswith(prefix+'-'):continue
            line=next(i for i,text in enumerate(s.splitlines(),1) if statement in text)
            for runner in (False,True):
                with self.subTest(case=name,runner=runner):
                    rows=self.rows(s,runner)
                    actual=any(r['line']==line and 'HILOG_INFO' in r['message'] for r in rows)
                    if contract=='material': self.assertTrue(any('Audit' in r['message'] and r['rule_id']=='data.sensitive.unresolved-escape' for r in rows),rows)
                    else:self.assertEqual(contract=='log',actual,rows)
    def test_scalar_literal(self):self.check('scalar-literal')
    def test_multi_literal(self):self.check('multi-literal')
    def test_nested_literal(self):self.check('nested-literal')
    def test_last_material(self):self.check('last-material')
    def test_multi_last_material(self):self.check('multi-last-material')
    def test_conditional_last_material(self):self.check('conditional-last-material')
    def test_status_return_and_real_sink(self):self.check('status-return')
    def test_explicit_overloaded_operator(self):self.check('overload-material')
    def test_sink_name_not_return_type(self):self.check('class-named-sink')
    def test_callable_shadow_not_global_prototype(self):self.check('callback-shadow')
    def test_macro_scope(self):self.check('macro-scope')
    def test_unknown_final_call(self):
        self.check('unknown-final-call')
        s=next(row[1] for row in fixtures() if row[0]=='unknown-final-call')
        for runner in (False,True):self.assertTrue(any('Unknown' in r['message'] and r['rule_id']=='data.sensitive.unresolved-escape' for r in self.rows(s,runner)))
    def test_partial_selected_header(self):
        s=scalar('(key,0)')
        for runner in (False,True):
            rows=self.rows(s,runner,extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any('HILOG_INFO' in r['message'] for r in rows),rows)
    def test_alias_declines_proof(self):self.check('alias-unknown')
    def test_overloaded_prototype_declines_proof(self):self.check('overloaded-prototype-unknown')
    def test_left_assignment_effect(self):self.check('left-assignment-effect')
    def test_unique_call_value_and_effect(self):self.check('unique-call-literal')
    def test_parser_partial_is_explicitly_blocked(self):
        s=next(row[1] for row in fixtures() if row[0]=='left-assignment-effect').replace('((out=key),0)','(out=key,0)')
        ctx=self.context(s)
        self.assertEqual('partial',ctx.units[0].parse_status)
        result,coverage=t93.T93ScalarPointerTests().analyze(s,runner=True)
        self.assertEqual('blocked',result['status'])
        self.assertEqual(1,coverage['detectors']['ohscanner.data.sensitive_exposure']['coverage_counts']['not_analyzed'])
    def test_non_comma_and_parenthesized_material(self):
        for expr in ('key','(key)'):
            s=pointer(expr)
            for runner in (False,True):self.assertTrue(any('HILOG_INFO' in r['message'] for r in self.rows(s,runner)),s)

if __name__=='__main__':unittest.main()
