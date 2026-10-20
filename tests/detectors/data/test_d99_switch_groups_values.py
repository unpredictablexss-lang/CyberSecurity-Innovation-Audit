"""D99 consecutive labels and bounded return expressions preserve real effects."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D99SwitchGroupsValuesTests(unittest.TestCase):
    def source(self,arms,result='void',prefix=''):
        return '\n'.join((prefix,result+' Callback(const char*key,int selector){',
            'unsigned first=0;unsigned*p=&first;',
            'switch(selector){'+arms+'}',
            '*p=(unsigned char)key[0];',
            'HILOG_INFO(1,"%{public}u",first);',
            'return 9;' if result!='void' else '', '}'))

    def test_consecutive_case_and_default_labels_share_return(self):
        for arms in ('case 0:case 1:return;default:return;',
                     'case 0:default:return;case 2:case 3:return;'):
            for runner in (False,True):self.assertFalse(scan(self.source(arms),runner))

    def test_literal_return_values_remove_only_unreachable_followup(self):
        for runner in (False,True):
            self.assertFalse(scan(self.source('case 0:return 0;default:return 7;',result='unsigned'),runner))

    def test_unknown_call_in_return_retains_material_escape(self):
        source=self.source('case 0:return Consume(key);default:return 0;',
                           result='unsigned',prefix='unsigned Consume(const char*);')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertTrue(any('unresolved call Consume' in f.message for f in findings))
            self.assertFalse(any(f.line==6 for f in findings))

    def test_comma_return_keeps_real_log_and_removes_unreachable_log(self):
        source=self.source('case 0:return(HILOG_INFO(1,"%{public}s",key),0);default:return 0;',result='unsigned')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertEqual([f.line for f in findings],[4])
            self.assertEqual(findings[0].rule_id,'data.log.sensitive-value')

    def test_material_return_from_grouped_helper_reaches_caller_log(self):
        source='\n'.join(('const char* Select(const char*value,int selector){',
            'switch(selector){case 0:case 1:return value;default:return(value);}}',
            'void Callback(const char*key,int selector){',
            'const char*output=Select(key,selector);',
            'HILOG_INFO(1,"%{public}s",output);','}'))
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertEqual([f.line for f in findings],[5])
            self.assertIn('return from Select',findings[0].message)

    def test_nonterminating_group_and_executable_fallthrough_remain_candidates(self):
        for arms in ('case 0:return;default:',
                     'case 0:case 1:break;default:return;',
                     'case 0:*p=7;case 1:break;default:return;',
                     'case 0:case 0:return;default:return;',
                     'case 0x0:case 1:return;default:return;',
                     'case 0:case 1:return;'):
            for runner in (False,True):self.assertTrue(scan(self.source(arms),runner))

    def test_unsupported_return_expression_keeps_conservative_successor(self):
        source=self.source('case 0:return [](){return 0;}();default:return 0;',result='unsigned')
        for runner in (False,True):self.assertTrue(scan(source,runner))

    def test_partial_and_preprocessor_scope_never_grant_grouped_termination(self):
        from tests.detectors.data.test_t93_scalar_pointer_writes import T93ScalarPointerTests
        source=self.source('case 0:case 1:return;default:return;')
        for runner in (False,True):
            rows=T93ScalarPointerTests().rows(source,runner=runner,
                extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any(row['line']==6 for row in rows))
            self.assertTrue(scan('#define CONTEXT_UNKNOWN 1\n'+source,runner))


if __name__=='__main__':unittest.main()
