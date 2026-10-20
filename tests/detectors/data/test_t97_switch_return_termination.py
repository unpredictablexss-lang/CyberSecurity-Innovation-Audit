"""T97 independent termination contracts for bounded switch returns."""
import unittest
from tests.detectors.data import test_t96_switch_target_joins as t96
from tests.detectors.data import test_t94_pointer_branch_targets as t94
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
WRITE,FIRST_LOG,SECOND_LOG=t94.WRITE,t94.FIRST_LOG,t94.SECOND_LOG


def build(arms,header='selector',prefix='unsigned *p=&first;'):
    return t96.build(arms,prefix,header)


CASE_SEMANTICS={
 'all-return':'Unique numeric case plus default both directly return; no following write/log is reachable.',
 'three-return-default-first':'Two unique cases and default, all direct return, exclude any live post-switch state.',
 'header-return':'Initializer q is switch-scoped and cannot revive fallthrough when every direct arm returns.',
 'missing-default':'Unmatched selectors bypass every arm and reach the following material write/log.',
 'mixed-break':'Case zero breaks; this live switch exit reaches the following material write/log.',
 'unknown-label':'Identifier case label is not admitted by bounded numeric-label proof; preserve unknown instead of claiming termination.',
 'duplicate-label':'Duplicate labels are ill-formed C++; a syntax tree is not semantic termination proof.',
 'nested-block-live':'An if(flag) break in a case block can reach post-switch log; nested return alone cannot establish all-return.',
 'nested-switch-live':'Only the inner switch is all-return; outer default breaks and reaches post-switch log.',
 'loop-continue-live':'A continue exits to enclosing loop while default break exits only switch; default reaches log.',
 'goto-bypass':'A conditional goto targets the post-switch label; this path bypasses all returns and reaches the material write/log.',
 'same-target':'Complete flat same-target assignment+break must retain the D97 exact second-log result.',
 'condition-escape':'Unknown GetSelector(key) condition is inspected; declaration-free non-identifier selector is outside the narrow termination proof.',
 'grouped-fallthrough-known-gap':'Case zero falls into default return; actually all dispatch paths return, but the grouped-label shape remains unproved.',
 'return-expression-known-gap':'Both arms return scalar constant zero; post-switch log is unreachable, but non-bare return remains outside proof.'}


def fixtures():
    rows=[]
    for name,s in (
        ('all-return',build('case 0:return;default:return;')),
        ('three-return-default-first',build('default:return;case 0:return;case 7:return;')),
        ('header-return',build('case 0:return;default:return;',header='unsigned *q=&second;selector'))):
        rows.extend([(name,s,FIRST_LOG,'no-log'),(name+'-no-second',s,SECOND_LOG,'no-log')])
    for name,arms in (
        ('missing-default','case 0:return;'),
        ('mixed-break','case 0:break;default:return;'),
        ('unknown-label','case LABEL:return;default:return;'),
        ('duplicate-label','case 0:return;case 0:return;default:return;'),
        ('nested-block-live','case 0:{if(flag){break;}return;}default:return;'),
        ('nested-switch-live','case 0:switch(other){case 0:return;default:return;}default:break;')):
        s=build(arms).replace('int selector','int selector,bool flag,int other')
        if name=='unknown-label': s='const int LABEL=0;\n'+s
        rows.append((name,s,FIRST_LOG,'log'))
    loop=t96.source('unsigned *p=&first;while(true){switch(selector){case 0:continue;default:break;}\n'+WRITE+'\n'+FIRST_LOG+'\nbreak;}')
    rows.append(('loop-continue-live',loop,FIRST_LOG,'log'))
    goto_source=t96.source('unsigned *p=&first;if(selector==3)goto kept;switch(selector){case 0:return;default:return;}\nkept:'+WRITE+'\n'+FIRST_LOG)
    rows.append(('goto-bypass',goto_source,FIRST_LOG,'log'))
    rows.append(('same-target',build('case 0:p=&second;break;default:p=&second;break;'),SECOND_LOG,'log'))
    return rows


KNOWN_GAPS=[
 ('grouped-fallthrough-known-gap',build('case 0:default:return;'),FIRST_LOG,'known_gap'),
 ('return-expression-known-gap',build('case 0:return 0;default:return 0;').replace('void Callback','unsigned Callback'),FIRST_LOG,'known_gap')]


class T97SwitchReturnTests(unittest.TestCase):
    def context(self,s): return t93.T93ScalarPointerTests().context(s)
    def rows(self,s,runner=False,**kw): return t93.T93ScalarPointerTests().rows(s,runner=runner,**kw)
    def check(self,prefix):
        for name,s,statement,contract in fixtures():
            if name!=prefix and not name.startswith(prefix+'-'): continue
            with self.subTest(case=name): t94.T94PointerBranchTests().assert_log(s,statement,contract=='log')
    def test_all_return(self): self.check('all-return')
    def test_three_return_default_first(self): self.check('three-return-default-first')
    def test_header_return(self): self.check('header-return')
    def test_missing_default(self): self.check('missing-default')
    def test_mixed_break(self): self.check('mixed-break')
    def test_unknown_label(self): self.check('unknown-label')
    def test_duplicate_label(self): self.check('duplicate-label')
    def test_nested_block_live(self): self.check('nested-block-live')
    def test_nested_switch_live(self): self.check('nested-switch-live')
    def test_loop_continue_live(self): self.check('loop-continue-live')
    def test_goto_bypass_remains_live(self): self.check('goto-bypass')
    def test_same_target(self): self.check('same-target')
    def test_partial_scope_never_claims_termination(self):
        s=build('case 0:return;default:return;')
        for runner in (False,True):
            rows=self.rows(s,runner,extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any('HILOG_INFO' in r['message'] for r in rows),rows)
    def test_condition_escape_is_retained(self):
        s='int GetSelector(const char*);\n'+build('case 0:return;default:return;',header='GetSelector(key)')
        for runner in (False,True):
            rows=self.rows(s,runner)
            self.assertTrue(any('GetSelector' in r['message'] and 'Callback parameter 0' in r['message'] for r in rows),rows)
    def test_reachable_log_before_switch_is_not_removed(self):
        s=build('case 0:return;default:return;',prefix='unsigned *p=&first;'+WRITE+'\n'+FIRST_LOG+'\n')
        for runner in (False,True):
            rows=self.rows(s,runner)
            before=s.splitlines().index(FIRST_LOG)+1
            self.assertTrue(any(r['line']==before and 'HILOG_INFO' in r['message'] for r in rows),rows)
    def test_literal_and_previous_memory_controls(self):
        s=build('case 0:return;default:return;').replace(WRITE,'*p=7;')
        for runner in (False,True): self.assertEqual([],self.rows(s,runner))
        t94.T94PointerBranchTests().test_copy_output_and_unknown_write_controls_remain()

if __name__=='__main__': unittest.main()
