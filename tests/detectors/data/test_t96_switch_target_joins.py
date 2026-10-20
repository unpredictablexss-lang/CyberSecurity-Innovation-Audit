"""T96 independent bounded switch target joins; unresolved cases remain candidates."""
import unittest
from tests.detectors.data import test_t94_pointer_branch_targets as t94
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
WRITE,FIRST_LOG,SECOND_LOG=t94.WRITE,t94.FIRST_LOG,t94.SECOND_LOG


def source(body):
    return t94.T94PointerBranchTests().source(body).replace('bool flag','int selector')


def build(arms,prefix='unsigned *p=&first;',header='selector',write=WRITE):
    return source(prefix+'switch('+header+'){'+arms+'}\n'+write+'\n'+FIRST_LOG+'\n'+SECOND_LOG)


CASE_SEMANTICS={
    'same-full':'For all integer selectors, one matching case or default binds second and breaks; following write targets second.',
    'same-three-arms':'Two unique cases plus default exhaust dispatch; all three normal exits bind second.',
    'same-header-scope':'The header q is restored after switch; every normal arm binds external p to second.',
    'different-target':'Dispatch may select first or second; no unique post-switch target.',
    'missing-default':'No match preserves initial first; matching case binds second; neither exact destination is proved.',
    'fallthrough':'Case zero first binds first then falls into default, overriding with second; any other selector enters default. Actual post-switch target is second, but this remains outside bounded proof.',
    'return-live':'Case zero exits Callback; only default reaches following write with second. Actual live target is second, but this remains outside bounded exit proof.',
    'unknown-target':'One arm returns an unknown target; no unique proven post-switch target.',
    'duplicate-label':'Duplicate case zero is ill-formed C++; complete syntax AST does not prove valid dispatch and must not grant exact-target proof.',
    'macro-source':'Preprocessor macro resolves DEST only under a specific preprocessing environment; the scanner does not establish that environment.',
    'literal-only':'No operand depends on modeled Callback source; pointer binding alone cannot create material.',
    'known-all-return-unreachable-log':'Unique case and default both return: following write and log are unreachable; current scan reports a known over-candidate.'}

def fixtures():
    result=[]
    same=build('case 0:p=&second;break;default:p=&second;break;')
    same_many=build('case 0:p=&second;break;case 1:p=&second;break;default:p=&second;break;')
    header=build('case 0:p=&second;break;default:p=&second;break;',header='unsigned *q=&first;selector')
    for name,s in (('same-full',same),('same-three-arms',same_many),('same-header-scope',header)):
        result.extend([(name,s,SECOND_LOG,'log'),(name+'-not-first',s,FIRST_LOG,'no-log')])
    controls={
        'different-target':build('case 0:p=&first;break;default:p=&second;break;'),
        'missing-default':build('case 0:p=&second;break;'),
        'fallthrough':build('case 0:p=&first;default:p=&second;break;'),
        'return-live':build('case 0:return;default:p=&second;break;'),
        'unknown-target':'unsigned *GetDestination();\n'+build('case 0:p=GetDestination();break;default:p=&second;break;'),
        'duplicate-label':build('case 0:p=&second;break;case 0:p=&second;break;default:p=&second;break;'),
        'macro-source':'#define DEST second\n'+build('case 0:p=&DEST;break;default:p=&DEST;break;'),
    }
    for name,s in controls.items():
        result.extend([(name,s,WRITE,'material'),(name+'-not-first',s,FIRST_LOG,'no-log'),(name+'-not-second',s,SECOND_LOG,'no-log')])
    result.append(('literal-only',build('case 0:p=&second;break;default:p=&second;break;',write='*p=7;'),None,'none'))
    return result


KNOWN_ALL_RETURN_SOURCE=build('case 0:return;default:return;')


class T96SwitchTargetTests(unittest.TestCase):
    def context(self,s): return t94.T94PointerBranchTests().context(s)
    def rows(self,s,runner=False): return t94.T94PointerBranchTests().rows(s,runner)
    def check(self,prefix):
        for name,s,statement,contract in fixtures():
            if name!=prefix and not name.startswith(prefix+'-'): continue
            with self.subTest(case=name):
                if contract in ('log','no-log'): t94.T94PointerBranchTests().assert_log(s,statement,contract=='log')
                elif contract=='material': t94.T94PointerBranchTests().assert_unresolved_write(s)
                else:
                    for runner in (False,True): self.assertEqual([],self.rows(s,runner))
    def test_complete_same_target(self): self.check('same-full')
    def test_complete_three_arms(self): self.check('same-three-arms')
    def test_header_scope(self): self.check('same-header-scope')
    def test_different_target(self): self.check('different-target')
    def test_missing_default(self): self.check('missing-default')
    def test_fallthrough_preserves_unknown(self): self.check('fallthrough')
    def test_return_live_preserves_unknown(self): self.check('return-live')
    def test_unknown_target(self): self.check('unknown-target')
    def test_duplicate_label_no_semantic_proof(self): self.check('duplicate-label')
    def test_macro_source(self): self.check('macro-source')
    def test_literal_only(self): self.check('literal-only')
    def test_switch_condition_escape_is_not_hidden_by_target_proof(self):
        s='int GetSelector(const char*);\n'+build('case 0:p=&second;break;default:p=&second;break;',header='GetSelector(key)')
        for runner in (False,True):
            rows=self.rows(s,runner)
            self.assertTrue(any('GetSelector' in r['message'] and 'Callback parameter 0' in r['message'] for r in rows),rows)
        t94.T94PointerBranchTests().assert_unresolved_write(s)
    def test_partial_unit_does_not_grant_exact_target_proof(self):
        s=build('case 0:p=&second;break;default:p=&second;break;')
        for runner in (False,True):
            rows=t93.T93ScalarPointerTests().rows(s,runner=runner,extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any('unresolved material write' in r['message'] for r in rows),rows)
            self.assertFalse(any('HILOG_INFO' in r['message'] for r in rows),rows)
    def test_previous_scopes_copy_and_nullcast(self):
        t=t94.T94PointerBranchTests()
        t.test_for_initializer_shadow_is_removed_after_loop()
        t.test_copy_output_and_unknown_write_controls_remain()
        t.test_null_cast_sensitive_type_does_not_become_source()

if __name__=='__main__': unittest.main()
