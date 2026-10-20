"""D97 exact non-fallthrough switch arms, without general case CFG claims."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D97SwitchSameTargetTests(unittest.TestCase):
    def source(self,body,pointer='nullptr',prefix='',literal=False):
        return '\n'.join((prefix,'void Callback(const char*key,int selector){',
            'unsigned first=0,second=0;unsigned*p='+pointer+';',
            'switch(selector){'+body+'}',
            '*p=7;' if literal else '*p=(unsigned char)key[0];',
            'HILOG_INFO(1,"%{public}u",first);',
            'HILOG_INFO(1,"%{public}u",second);','}'))

    def rows(self,source):
        return [scan(source,runner) for runner in (False,True)]

    def test_exhaustive_identical_pointer_targets_reach_only_second_log(self):
        for initial in ('nullptr','&first'):
            source=self.source('case 0:p=&second;break;default:p=&second;break;',initial)
            for findings in self.rows(source):
                self.assertEqual([(f.rule_id,f.line) for f in findings],[('data.log.sensitive-value',7)])

    def test_three_arms_with_default_not_last_keep_same_target(self):
        source=self.source('default:p=&second;break;case 0:p=&second;break;case 3:p=&second;break;')
        for findings in self.rows(source):
            self.assertEqual([f.line for f in findings],[7])

    def test_missing_default_divergence_and_unknown_remain_unresolved(self):
        for body in ('case 0:p=&second;break;',
                     'case 0:p=&first;break;default:p=&second;break;',
                     'case 0:p=GetDestination();break;default:p=&second;break;'):
            for findings in self.rows(self.source(body)):
                self.assertTrue(any('unresolved material write' in f.message for f in findings))
                self.assertFalse(any(f.rule_id=='data.log.sensitive-value' for f in findings))

    def test_fallthrough_return_nested_break_and_duplicate_labels_not_proved(self):
        for body in ('case 0:p=&first;default:p=&second;break;',
                     'case 0:return;default:p=&second;break;',
                     'case 0:if(selector){break;}p=&second;break;default:p=&second;break;',
                     'case 0:p=&second;break;case 0:p=&second;break;default:p=&second;break;'):
            for findings in self.rows(self.source(body)):
                self.assertTrue(any('unresolved material write' in f.message for f in findings))

    def test_macro_and_partial_input_do_not_admit_exact_join(self):
        body='case 0:p=&second;break;default:p=&second;break;'
        for source in (self.source(body,prefix='#define p GetDestination()'),):
            for findings in self.rows(source):
                self.assertFalse(any(f.rule_id=='data.log.sensitive-value' and f.line==7 for f in findings))
                self.assertTrue(any('unresolved material write' in f.message for f in findings))
        # Runner excludes a parser-partial unit; that is blocked, not safety.
        findings=self.rows(self.source(body)+'\nvoid malformed( {')[0]
        self.assertTrue(any('unresolved material write' in f.message for f in findings))
        self.assertFalse(any(f.rule_id=='data.log.sensitive-value' for f in findings))

    def test_literal_only_write_does_not_create_source(self):
        for findings in self.rows(self.source('case 0:p=&second;break;default:p=&second;break;',literal=True)):
            self.assertFalse(findings)

    def test_partial_selected_header_rejects_join_in_both_pipelines(self):
        from tests.detectors.data.test_t93_scalar_pointer_writes import T93ScalarPointerTests
        source=self.source('case 0:p=&second;break;default:p=&second;break;')
        for runner in (False,True):
            rows=T93ScalarPointerTests().rows(source,runner=runner,
                extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any('unresolved material write' in row['message'] for row in rows))
            self.assertFalse(any('HILOG_INFO' in row['message'] for row in rows))


if __name__=='__main__':unittest.main()
