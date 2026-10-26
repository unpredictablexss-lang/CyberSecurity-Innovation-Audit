"""T98 independent grouped-label and return-expression termination boundaries."""
import unittest
from tests.detectors.data import test_t97_switch_return_termination as t97
from tests.detectors.data import test_t94_pointer_branch_targets as t94
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
WRITE,FIRST_LOG,SECOND_LOG=t94.WRITE,t94.FIRST_LOG,t94.SECOND_LOG


def build(arms,value_return=False,header='selector',prefix='unsigned *p=&first;'):
    s=t97.build(arms,header,prefix)
    return s.replace('void Callback','unsigned Callback') if value_return else s


CASE_SEMANTICS={
 'grouped-bare':'Consecutive unique case labels enter the same bare return; default also returns; no normal successor.',
 'grouped-default':'A default label may share its return with preceding case; all remaining dispatch entries return.',
 'multiple-groups':'Every unique label belongs to a directly returning group, including default; no live successor.',
 'return-literal':'Return expressions terminate the function; literal values carry no material flow.',
 'return-unknown-call':'Unknown Consume(key) executes before returning and remains a material escape; following log is unreachable.',
 'return-log-expression':'The comma expression logs key before returning zero; real log remains, post-switch log is unreachable.',
 'missing-default':'No-match dispatch reaches the following log; grouped return labels alone are not exhaustive.',
 'duplicate-label':'Duplicate labels are ill-formed C++; syntax grouping cannot grant a termination proof.',
 'noncanonical-label':'A hexadecimal literal is outside canonical numeric proof; conservative candidate remains.',
 'group-with-break':'At least one grouped entry breaks out of switch; following log is reachable.',
 'executable-fallthrough-live':'Material write in one case can fall through to a break group; normal post-switch log remains reachable.',
 'nested-break-live':'A case block may break before reaching its return; a descendant return is not arm termination.',
 'partial-selected-unit':'Selected partial header invalidates exact termination admission in both entrypoints.',
 'goto-bypass':'A conditional goto bypasses all switch returns and enters the post-switch material write.',
 'material-return-summary':'Select returns its input material from grouped arms; Callback must propagate the returned pointer into its real public log.',
 'grouped-statement-real-log':'The public log executes before grouped-arm return; unsupported multi-statement arm cannot erase this real sink.',
 'unknown-return-syntax':'Lambda-call syntax is outside bounded expression support; retain partial/unknown proof obligations instead of using it to prune.',
 'trailing-empty-default':'A trailing default with an empty statement falls out normally; preceding returning groups do not terminate this entry.',
 'macro-selected-unit':'A selected preprocessor directive invalidates bounded preprocessing-free proof; preserved candidate is admission conservatism, not proof of real reachability.',
 'same-target':'Prior D97 same-target pointer joining remains compatible.'}


def fixtures():
    rows=[]
    for name,arms,val in (
      ('grouped-bare','case 0:case 1:return;default:return;',False),
      ('grouped-default','case 0:default:return;case 7:return;',False),
      ('multiple-groups','case 0:case 1:return;case 2:case 3:return;default:return;',False),
      ('return-literal','case 0:return 0;default:return 7;',True)):
        s=build(arms,val)
        rows.append((name,s,FIRST_LOG,'no-log'))
    call='unsigned Consume(const char*);\n'+build('case 0:return Consume(key);default:return 0;',True)
    rows.extend([('return-unknown-call',call,FIRST_LOG,'no-log'),('return-unknown-call-escape',call,'return Consume(key);','material')])
    actual='unsigned Report(const char*);\n'+build('case 0:return (HILOG_INFO(1,"%{public}s",key),0);default:return 0;',True)
    rows.extend([('return-log-expression',actual,FIRST_LOG,'no-log'),('return-log-expression-real',actual,'HILOG_INFO(1,"%{public}s",key)','log')])
    for name,arms in (
      ('missing-default','case 0:case 1:return;'),
      ('trailing-empty-default','case 0:case 1:return;default:;'),
      ('duplicate-label','case 0:case 0:return;default:return;'),
      ('noncanonical-label','case 0x0:return;default:return;'),
      ('group-with-break','case 0:case 1:break;default:return;'),
      ('executable-fallthrough-live','case 0:'+WRITE+'case 1:break;default:return;'),
      ('nested-break-live','case 0:{if(selector){break;}return;}default:break;')):
        rows.append((name,build(arms),FIRST_LOG,'log'))
    goto=build('case 0:case 1:return;default:return;',prefix='unsigned *p=&first;if(selector==3)goto kept;').replace('\n'+WRITE,'\nkept:'+WRITE)
    rows.append(('goto-bypass',goto,FIRST_LOG,'log'))
    summary='void HILOG_INFO(int,const char*,...);\nconst char *Select(const char *value,int selector){switch(selector){case 0:case 1:return value;default:return value;}}\nvoid Callback(const char *key,int selector){const char *output=Select(key,selector);\nHILOG_INFO(1,"%{public}s",output);\n}'
    rows.append(('material-return-summary',summary,'HILOG_INFO(1,"%{public}s",output);','log'))
    statement=build('case 0:case 1:HILOG_INFO(1,"%{public}s",key);return;default:return;')
    rows.append(('grouped-statement-real-log',statement,'HILOG_INFO(1,"%{public}s",key)','log'))
    rows.append(('unknown-return-syntax',build('case 0:return [](){return 0;}();default:return 0;',True),FIRST_LOG,'log'))
    rows.append(('macro-selected-unit','#define BUILD_FLAG 1\n'+build('case 0:case 1:return;default:return;'),FIRST_LOG,'log'))
    rows.append(('same-target',build('case 0:p=&second;break;default:p=&second;break;'),SECOND_LOG,'log'))
    return rows


class T98SwitchGroupTests(unittest.TestCase):
    def context(self,s): return t93.T93ScalarPointerTests().context(s)
    def rows(self,s,runner=False,**kw): return t93.T93ScalarPointerTests().rows(s,runner=runner,**kw)
    def check(self,prefix):
        for name,s,statement,contract in fixtures():
            if name!=prefix and not name.startswith(prefix+'-'): continue
            with self.subTest(case=name):
                line=next(i for i,text in enumerate(s.splitlines(),1) if statement in text)
                for runner in (False,True):
                    rows=self.rows(s,runner)
                    selected=[r for r in rows if r['line']==line]
                    if contract in ('log','no-log'):
                        self.assertEqual(contract=='log',any('HILOG_INFO' in r['message'] for r in selected),rows)
                    else:self.assertTrue(any('Consume' in r['message'] and 'Callback parameter 0' in r['message'] for r in selected),rows)
    def test_grouped_bare(self):self.check('grouped-bare')
    def test_grouped_default(self):self.check('grouped-default')
    def test_multiple_groups(self):self.check('multiple-groups')
    def test_literal_returns(self):self.check('return-literal')
    def test_unknown_return_call(self):self.check('return-unknown-call')
    def test_return_log_expression(self):self.check('return-log-expression')
    def test_missing_default(self):self.check('missing-default')
    def test_trailing_default(self):self.check('trailing-empty-default')
    def test_duplicate_label(self):self.check('duplicate-label')
    def test_noncanonical_label(self):self.check('noncanonical-label')
    def test_group_break(self):self.check('group-with-break')
    def test_executable_fallthrough(self):self.check('executable-fallthrough-live')
    def test_nested_break(self):self.check('nested-break-live')
    def test_goto_bypass(self):self.check('goto-bypass')
    def test_material_return_summary(self):self.check('material-return-summary')
    def test_grouped_statement_real_log(self):self.check('grouped-statement-real-log')
    def test_unknown_return_syntax_stays_conservative(self):self.check('unknown-return-syntax')
    def test_macro_scope_stays_unknown(self):self.check('macro-selected-unit')
    def test_same_target_compatibility(self):self.check('same-target')
    def test_partial_scope_stays_unknown(self):
        s=build('case 0:case 1:return;default:return;')
        for runner in (False,True):
            rows=self.rows(s,runner,extra=(('partial.h','struct Incomplete {'),),partial=('partial.h',))
            self.assertTrue(any(r['line']==5 and 'HILOG_INFO' in r['message'] for r in rows),rows)

if __name__=='__main__':unittest.main()
