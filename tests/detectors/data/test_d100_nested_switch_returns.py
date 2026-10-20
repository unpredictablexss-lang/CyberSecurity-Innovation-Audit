"""D100 one simple if/else return split inside a flat switch arm."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D100NestedSwitchReturnsTests(unittest.TestCase):
    def source(self,arms,result='void',prefix='',before=''):
        return '\n'.join((prefix,result+' Callback(const char*key,int selector,bool flag){',
            'unsigned out=0;unsigned*p=&out;',before,
            'switch(selector){'+arms+'}',
            '*p=(unsigned char)key[0];',
            'HILOG_INFO(1,"%{public}u",out);',
            'return 9;' if result!='void' else '', '}'))

    def test_both_direct_if_branches_return_so_postlude_is_dead(self):
        source=self.source('case 0:if(flag)return;else return;default:return;')
        for runner in (False,True):self.assertFalse(scan(source,runner))

    def test_single_return_blocks_and_grouped_labels_are_bounded(self):
        source=self.source('case 0:case 1:if(flag){return;}else{return;}default:if(flag)return;else return;')
        for runner in (False,True):self.assertFalse(scan(source,runner))

    def test_condition_and_return_expression_effects_remain_candidates(self):
        source=self.source('case 0:if(Check(key))return Consume(key);else return 0;default:return 0;',
            result='unsigned',prefix='bool Check(const char*);unsigned Consume(const char*);')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertTrue(any('Check' in f.message for f in findings))
            self.assertTrue(any('Consume' in f.message for f in findings))
            self.assertFalse(any(f.line==7 for f in findings))

    def test_helper_material_returns_reach_caller_log(self):
        source='\n'.join(('const char*Choose(const char*value,int sel,bool flag){',
            'switch(sel){case 0:if(flag)return value;else return(value);default:return value;}}',
            'void Callback(const char*key,int selector,bool flag){',
            'const char*out=Choose(key,selector,flag);',
            'HILOG_INFO(1,"%{public}s",out);','}'))
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertEqual([f.line for f in findings],[5])
            self.assertIn('return from Choose',findings[0].message)

    def test_missing_else_live_exit_and_nested_control_do_not_grant_proof(self):
        for arms in ('case 0:if(flag)return;default:return;',
                     'case 0:if(flag)return;else break;default:return;',
                     'case 0:if(flag){}else return;default:return;',
                     'case 0:if(flag){while(flag){break;}}else return;default:return;',
                     'case 0:if(flag){switch(selector){default:return;}}else return;default:return;',
                     'case 0:if(flag){if(flag)return;else return;}else return;default:return;'):
            for runner in (False,True):self.assertTrue(scan(self.source(arms),runner))

    def test_partial_macro_and_goto_context_remain_conservative(self):
        from tests.detectors.data.test_t93_scalar_pointer_writes import T93ScalarPointerTests
        source=self.source('case 0:if(flag)return;else return;default:return;')
        for runner in (False,True):
            rows=T93ScalarPointerTests().rows(source,runner=runner,
                extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any(row['line']==7 for row in rows))
            self.assertTrue(scan('#define UNKNOWN_CONTEXT 1\n'+source,runner))
            jumping=source.replace('switch(selector)','if(flag)goto kept;switch(selector)').replace('*p=(unsigned char)key[0];','kept:*p=(unsigned char)key[0];')
            self.assertTrue(scan(jumping,runner))

    def test_real_log_before_nested_switch_remains(self):
        source=self.source('case 0:if(flag)return;else return;default:return;',
                           before='HILOG_INFO(1,"%{public}s",key);')
        for runner in (False,True):self.assertEqual([f.line for f in scan(source,runner)],[4])

    def test_literal_nested_helper_return_is_not_material(self):
        source=('unsigned Status(const char*value,int sel,bool flag){switch(sel){'
                'case 0:if(flag)return 0;else return 1;default:return 2;}}'
                'void Callback(const char*key,int selector,bool flag){'
                'unsigned code=Status(key,selector,flag);HILOG_INFO(1,"%{public}u",code);}')
        for runner in (False,True):self.assertFalse(scan(source,runner))


if __name__=='__main__':unittest.main()
