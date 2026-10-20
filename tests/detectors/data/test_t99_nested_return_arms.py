"""T99 independent bounded nested-return exits and returned material."""
import unittest
from tests.detectors.data import test_t98_switch_groups_and_values as t98
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
from tests.detectors.data import test_t94_pointer_branch_targets as t94
WRITE,FIRST_LOG,SECOND_LOG=t94.WRITE,t94.FIRST_LOG,t94.SECOND_LOG


def build(arms,prefix='unsigned *p=&first;'):
    return t98.build(arms,prefix=prefix).replace('int selector','int selector,bool flag,int other')


def return_source(unknown=False):
    expression='Unknown(value)' if unknown else 'value'
    proto='const char *Unknown(const char*);\n' if unknown else ''
    return 'void HILOG_INFO(int,const char*,...);\n'+proto+'const char *Choose(const char *value,int sel,bool flag){switch(sel){case 0:if(flag)return '+expression+';else return '+expression+';default:return '+expression+';}}\nvoid Callback(const char *key,int sel,bool flag){const char *out=Choose(key,sel,flag);\nHILOG_INFO(1,"%{public}s",out);\n}'


CASE_SEMANTICS={
 'both-bare':'Both if branches return; default returns; all dispatches terminate without a live postlude.',
 'both-block':'A single return enclosed in each compound branch is still unconditional arm termination.',
 'grouped-if':'Grouped numeric labels share one if/else, both branches return; default independently returns.',
 'missing-else-live':'The non-returning branch reaches a direct break and then the post-switch log.',
 'one-break-live':'One conditional branch directly breaks switch; that path reaches the log.',
 'fallthrough-live':'One conditional branch falls to a breaking default, leaving the log reachable.',
 'nested-switch-live':'A nested switch may break; an outer default also breaks. Nested returns cannot kill the outer successor.',
 'nested-loop-live':'An inner loop may exit normally before switch break; the following log remains reachable.',
 'goto-bypass':'Conditional goto can reach the postlude even if all nominal switch arms return.',
 'continue-live':'A case continue transfers to the enclosing loop; a different switch arm breaks to the real body log.',
 'material-return-helper':'Every nested branch returns input material to Callback output; real caller log must be retained.',
 'condition-call':'Unknown GetFlag(key) is evaluated and may expose material; no termination optimization may erase its candidate.',
 'comma-result-metadata-known-gap':'Status logs value but returns literal zero through a comma expression; caller code log is reachable but should have no material dependency.',
 'unknown-return-callee':'Unknown callee receives material; retain unresolved obligations rather than claim type- or name-proven output semantics.',
 'same-target':'Previous exact same-target switch join still reaches second log.',
 'macro-scope':'A selected preprocessor directive rejects the bounded proof; retained candidate is admission conservatism.',
 'partial-selected-unit':'A selected partial header blocks bounded proof in both pipelines.'}


def fixtures():
    rows=[]
    for name,arms in (
      ('both-bare','case 0:if(flag)return;else return;default:return;'),
      ('both-block','case 0:if(flag){return;}else{return;}default:return;'),
      ('grouped-if','case 0:case 1:if(flag)return;else return;default:if(other)return;else return;')):
        rows.append((name,build(arms),FIRST_LOG,'no-log'))
    for name,arms in (
      ('missing-else-live','case 0:if(flag)return;break;default:return;'),
      ('one-break-live','case 0:if(flag)return;else break;default:return;'),
      ('fallthrough-live','case 0:if(flag)return;default:break;'),
      ('nested-switch-live','case 0:if(flag)return;else switch(other){case 0:return;default:break;}break;default:break;'),
      ('nested-loop-live','case 0:if(flag)return;else while(other){break;}break;default:return;')):
        rows.append((name,build(arms),FIRST_LOG,'log'))
    goto=build('case 0:if(flag)return;else return;default:return;',prefix='unsigned *p=&first;if(other==3)goto kept;').replace('\n'+WRITE,'\nkept:'+WRITE)
    rows.append(('goto-bypass',goto,FIRST_LOG,'log'))
    loop=t98.t97.t96.source('unsigned *p=&first;while(true){switch(selector){case 0:if(flag)return;else continue;default:break;}\n'+WRITE+'\n'+FIRST_LOG+'\nbreak;}').replace('int selector','int selector,bool flag')
    rows.append(('continue-live',loop,FIRST_LOG,'log'))
    rows.append(('material-return-helper',return_source(), 'HILOG_INFO(1,"%{public}s",out);','log'))
    condition='bool GetFlag(const char*);\n'+build('case 0:if(GetFlag(key))return;else return;default:return;')
    rows.append(('condition-call',condition,'if(GetFlag(key))','material'))
    rows.append(('same-target',build('case 0:p=&second;break;default:p=&second;break;'),SECOND_LOG,'log'))
    rows.append(('macro-scope','#define BUILD_FLAG 1\n'+build('case 0:if(flag)return;else return;default:return;'),FIRST_LOG,'log'))
    return rows


COMMA_GAP_SOURCE='int HILOG_INFO(int,const char*,...);\nunsigned Status(const char *value,int sel){switch(sel){case 0:return(HILOG_INFO(1,"%{public}s",value),0);default:return 0;}}\nvoid Callback(const char *key,int sel){unsigned code=Status(key,sel);\nHILOG_INFO(1,"%{public}u",code);\n}'


class T99NestedReturnTests(unittest.TestCase):
    def context(self,s):return t93.T93ScalarPointerTests().context(s)
    def rows(self,s,runner=False,**kw):return t93.T93ScalarPointerTests().rows(s,runner=runner,**kw)
    def check(self,name):
        for n,s,statement,contract in fixtures():
            if n!=name:continue
            line=next(i for i,text in enumerate(s.splitlines(),1) if statement in text)
            for runner in (False,True):
                with self.subTest(case=name,runner=runner):
                    rows=self.rows(s,runner)
                    selected=[r for r in rows if r['line']==line]
                    if contract in ('log','no-log'):self.assertEqual(contract=='log',any('HILOG_INFO' in r['message'] for r in selected),rows)
                    else:self.assertTrue(any('GetFlag' in r['message'] and 'Callback parameter 0' in r['message'] for r in selected),rows)
    def test_both_bare(self):self.check('both-bare')
    def test_both_blocks(self):self.check('both-block')
    def test_grouped_if(self):self.check('grouped-if')
    def test_missing_else(self):self.check('missing-else-live')
    def test_one_break(self):self.check('one-break-live')
    def test_fallthrough(self):self.check('fallthrough-live')
    def test_nested_switch(self):self.check('nested-switch-live')
    def test_nested_loop(self):self.check('nested-loop-live')
    def test_goto(self):self.check('goto-bypass')
    def test_continue(self):self.check('continue-live')
    def test_material_return_helper(self):self.check('material-return-helper')
    def test_condition_call(self):self.check('condition-call')
    def test_same_target(self):self.check('same-target')
    def test_macro(self):self.check('macro-scope')
    def test_partial(self):
        s=build('case 0:if(flag)return;else return;default:return;')
        for runner in (False,True):
            rows=self.rows(s,runner,extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any('HILOG_INFO' in r['message'] for r in rows),rows)
    def test_unknown_return_callee_remains_unresolved(self):
        for runner in (False,True):
            rows=self.rows(return_source(True),runner)
            self.assertTrue(any('Unknown' in r['message'] for r in rows),rows)
            self.assertTrue(any(r['rule_id']=='data.sensitive.unresolved-escape' for r in rows),rows)

if __name__=='__main__':unittest.main()
