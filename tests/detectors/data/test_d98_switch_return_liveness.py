"""D98 only exact flat void-return switches can terminate the live block."""
import unittest
from tests.detectors.data.test_d95_pointer_target_merge import scan


class D98SwitchReturnLivenessTests(unittest.TestCase):
    def source(self,arms,header='selector',before='',prefix=''):
        return '\n'.join((prefix,'void Callback(const char*key,int selector){',
            'unsigned first=0;unsigned*p=&first;',before,
            'switch('+header+'){'+arms+'}',
            '*p=(unsigned char)key[0];',
            'HILOG_INFO(1,"%{public}u",first);','}'))

    def check_absent(self,source):
        for runner in (False,True):
            with self.subTest(runner=runner):self.assertFalse(scan(source,runner))

    def test_all_direct_void_returns_remove_unreachable_write_and_log(self):
        self.check_absent(self.source('case 0:return;default:return;'))

    def test_three_arms_and_initializer_scope_also_have_no_live_exit(self):
        self.check_absent(self.source('default:return;case 0:return;case 2:return;',
                                     header='unsigned*q=&first;selector'))

    def test_actual_log_before_all_return_switch_is_retained(self):
        source=self.source('case 0:return;default:return;',
                           before='HILOG_INFO(1,"%{public}s",key);')
        for runner in (False,True):
            self.assertEqual([f.line for f in scan(source,runner)],[4])

    def test_missing_default_mixed_exit_and_unsupported_label_remain_candidates(self):
        for arms in ('case 0:return;', 'case 0:return;default:break;',
                     'case 0:break;default:return;',
                     'case Unknown:return;default:return;',
                     'case 0:return;case 0:return;default:return;',
                     'case 0:;default:return;',
                     'case 0:{return;}default:return;'):
            for runner in (False,True):
                with self.subTest(arms=arms,runner=runner):
                    self.assertTrue(scan(self.source(arms),runner))

    def test_return_expression_effects_are_not_silently_removed(self):
        source=self.source('case 0:return LeakKey(key);default:return;',
                           prefix='void LeakKey(const char*);')
        for runner in (False,True):
            findings=scan(source,runner)
            self.assertTrue(any('unresolved call LeakKey' in f.message for f in findings))
            # D99 now proves the direct return terminal, while retaining LeakKey.
            self.assertFalse(any(f.line==7 for f in findings))

    def test_selected_partial_and_macro_context_keep_post_switch_candidate(self):
        from tests.detectors.data.test_t93_scalar_pointer_writes import T93ScalarPointerTests
        source=self.source('case 0:return;default:return;')
        for runner in (False,True):
            rows=T93ScalarPointerTests().rows(source,runner=runner,
                extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any(row['line']==7 for row in rows))
            self.assertTrue(scan('#define UNKNOWN_CONTEXT 1\n'+source,runner))

    def test_goto_can_reach_label_after_switch_and_must_not_be_hidden(self):
        source=self.source('case 0:return;default:return;',
            before='if(selector==3){goto output;}',prefix='')
        source=source.replace('*p=(unsigned char)key[0];','output: *p=(unsigned char)key[0];')
        for runner in (False,True):self.assertTrue(scan(source,runner))


if __name__=='__main__':unittest.main()
