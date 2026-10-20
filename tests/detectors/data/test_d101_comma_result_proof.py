"""D101 type-bounded builtin comma values, with operand effects retained."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D101CommaResultProofTests(unittest.TestCase):
    def source(self,expression,prefix='',tail='HILOG_INFO(1,"%{public}u",code);'):
        return '\n'.join((prefix,'void HILOG_INFO(int,const char*,...);',
            'void Callback(const char*key,int selector){',
            'unsigned code='+expression+';',tail,'}'))

    def test_scalar_comma_literal_and_nested_sequences_do_not_return_left_material(self):
        for expression in ('(key,0)','(key,7,0)','((key,0),1)','(key[0],0)'):
            for runner in (False,True):self.assertFalse(scan(self.source(expression),runner))

    def test_typed_sink_status_keeps_internal_log_only(self):
        source='\n'.join(('int HILOG_INFO(int,const char*,...);',
            'unsigned Status(const char*value,int sel){',
            'switch(sel){case 0:return(HILOG_INFO(1,"%{public}s",value),0);default:return 0;}}',
            'void Callback(const char*key,int selector){',
            'unsigned code=Status(key,selector);',
            'HILOG_INFO(1,"%{public}u",code);','}'))
        for runner in (False,True):self.assertEqual([f.line for f in scan(source,runner)],[3])

    def test_unique_primitive_call_value_can_be_discarded_but_escape_remains(self):
        source=self.source('(Audit(key),0)',prefix='int Audit(const char*);')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertTrue(any('unresolved call Audit' in f.message for f in findings))
            self.assertFalse(any(f.line==5 for f in findings))

    def test_last_material_is_preserved(self):
        source=('void HILOG_INFO(int,const char*,...);void Callback(const char*key){'
                'const char*out=(0,7,key);HILOG_INFO(1,"%{public}s",out);}')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertEqual(len(findings),1)
            self.assertIn('Callback parameter 0',findings[0].message)

    def test_user_defined_operator_and_sink_class_return_stay_unresolved(self):
        source=('struct Box{const char*text;};Box HILOG_INFO(int,const char*,...);'
                'const char*operator,(Box box,int){return box.text;}'
                'const char*Select(const char*value){return(HILOG_INFO(1,"%{public}s",value),0);}'
                'void Callback(const char*key){const char*out=Select(key);HILOG_INFO(1,"%{public}s",out);}')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertTrue(any('return from Select' in f.message for f in findings))

    def test_overload_macro_alias_and_partial_scope_cannot_prove_builtin(self):
        from tests.detectors.data.test_t93_scalar_pointer_writes import T93ScalarPointerTests
        for source in (self.source('(Audit(key),0)',prefix='int Audit(const char*);int Audit(int);'),
                       self.source('(key,0)',prefix='#define BUILD_FLAG 1'),
                       self.source('(key,0)',prefix='using Number=unsigned;')):
            for runner in (False,True):self.assertTrue(scan(source,runner))
        source=self.source('(key,0)')
        for runner in (False,True):
            rows=T93ScalarPointerTests().rows(source,runner=runner,
                extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any(row['line']==5 for row in rows))

    def test_noncomma_material_and_left_assignment_effect_are_not_suppressed(self):
        sources=('void Callback(const char*key){const char*out=(key);HILOG_INFO(1,"%{public}s",out);}',
                 'void Callback(const char*key){const char*out=nullptr;unsigned code=((out=key),0);HILOG_INFO(1,"%{public}s",out);}')
        for source in sources:
            for runner in (False,True):self.assertTrue(scan(source,runner))


if __name__=='__main__':unittest.main()
