"""D96 scoped selection/iteration header declarations, both detector pipelines."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D96ConditionPointerScopeTests(unittest.TestCase):
    def check(self,header,expected=(5,),tail=''):
        source='\n'.join(('void Callback(const char*key,bool flag){',
            'unsigned outer=0,inner=0;unsigned*p=&outer;',header,tail,
            'HILOG_INFO(1,"%{public}u",inner);',
            'HILOG_INFO(1,"%{public}u",outer);','}'))
        for runner in (False,True):
            with self.subTest(runner=runner,header=header):
                findings=scan(source,runner)
                self.assertEqual([f.line for f in findings],list(expected))

    def test_if_initializer_binds_shadowed_pointer(self):
        self.check('if(unsigned*p=&inner;flag){*p=(unsigned char)key[0];}')

    def test_if_condition_declaration_binds_shadowed_pointer(self):
        self.check('if(unsigned*p=&inner){*p=(unsigned char)key[0];}')

    def test_while_condition_declaration_binds_shadowed_pointer(self):
        self.check('while(unsigned*p=&inner){*p=(unsigned char)key[0];break;}')

    def test_switch_initializer_binds_shadowed_pointer(self):
        self.check('switch(unsigned*p=&inner;flag){case 0:*p=(unsigned char)key[0];break;}')

    def test_header_shadow_restores_outer_after_statement(self):
        for header in ('if(unsigned*p=&inner;flag){}','if(unsigned*p=&inner){}',
                       'while(unsigned*p=&inner){break;}',
                       'switch(unsigned*p=&inner;flag){default:break;}'):
            self.check(header,(6,),tail='*p=(unsigned char)key[0];')

    def test_literal_only_header_write_does_not_create_material(self):
        for header in ('if(unsigned*p=&inner;flag){*p=7;}',
                       'while(unsigned*p=&inner){*p=7;break;}',
                       'switch(unsigned*p=&inner;flag){default:*p=7;break;}'):
            self.check(header,())

    def test_condition_rebind_without_declaration_keeps_outer_mutation(self):
        self.check('if(p=&inner){*p=(unsigned char)key[0];}')


if __name__=='__main__':unittest.main()
