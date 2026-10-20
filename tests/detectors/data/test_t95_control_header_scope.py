"""T95 independent C++ control-header scopes, exit restoration and target joins."""
import unittest
from tests.detectors.data import test_t94_pointer_branch_targets as t94
from tests.detectors.data import test_t93_scalar_pointer_writes as t93
WRITE, FIRST_LOG, SECOND_LOG = t94.WRITE, t94.FIRST_LOG, t94.SECOND_LOG


def fixtures():
    source=t94.T94PointerBranchTests().source
    prefix='unsigned *p=&first;'
    logs='\n'+FIRST_LOG+'\n'+SECOND_LOG
    cases=[]
    for name,control in (
        ('if-init','if(unsigned *p=&second;flag){'+WRITE+'}'),
        ('if-condition','if(unsigned *p=&second){'+WRITE+'}'),
        ('while-condition','while(unsigned *p=&second){'+WRITE+'break;}'),
        ('switch-init','switch(unsigned *p=&second;flag){case 0:'+WRITE+'break;default:break;}')):
        cases.append((name,source(prefix+control+logs),SECOND_LOG,'log'))
        cases.append((name+'-outer-not-written',source(prefix+control+logs),FIRST_LOG,'no-log'))
        empty=control.replace(WRITE,'*p=7;')
        cases.append((name+'-restore',source(prefix+empty+'\n'+WRITE+logs),FIRST_LOG,'log'))
        cases.append((name+'-no-inner-after',source(prefix+empty+'\n'+WRITE+logs),SECOND_LOG,'no-log'))
    rebind=source(prefix+'if((p=&second)){'+WRITE+'}'+logs)
    cases.extend([('condition-assignment-not-shadow',rebind,SECOND_LOG,'log'),('condition-assignment-invalidates-first',rebind,FIRST_LOG,'no-log')])
    unknown='unsigned *GetDestination();\n'+source(prefix+'if(unsigned *p=GetDestination()){'+WRITE+'}'+logs)
    cases.extend([('unknown-header-material',unknown,WRITE,'material'),('unknown-header-no-outer',unknown,FIRST_LOG,'no-log')])
    literal=source(prefix+'if(unsigned *p=&second;flag){*p=7;}'+logs)
    cases.append(('literal-only',literal,None,'none'))
    return cases


class T95ControlHeaderTests(unittest.TestCase):
    def context(self,source): return t94.T94PointerBranchTests().context(source)
    def analyze(self,source,runner=False): return t94.T94PointerBranchTests().analyze(source,runner)
    def rows(self,source,runner=False): return t94.T94PointerBranchTests().rows(source,runner)
    def check_cases(self,names):
        for name,source,statement,contract in fixtures():
            if not any(name.startswith(n) for n in names): continue
            with self.subTest(case=name):
                if contract in ('log','no-log'):
                    t94.T94PointerBranchTests().assert_log(source,statement,contract=='log')
                elif contract=='material': t94.T94PointerBranchTests().assert_unresolved_write(source)
                else:
                    for runner in (False,True): self.assertEqual([],self.rows(source,runner))
    def test_if_initializer(self): self.check_cases(('if-init',))
    def test_if_condition_declaration(self): self.check_cases(('if-condition',))
    def test_while_condition_declaration(self): self.check_cases(('while-condition',))
    def test_switch_initializer(self): self.check_cases(('switch-init',))
    def test_condition_assignment_keeps_rebind(self): self.check_cases(('condition-assignment',))
    def test_unknown_header_never_reuses_outer_target(self): self.check_cases(('unknown-header',))
    def test_switch_external_target_divergence_stays_unresolved(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;switch(unsigned *q=&second;flag){case 0:p=&first;break;default:p=&second;break;}\n'+WRITE+'\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t=t94.T94PointerBranchTests()
        t.assert_unresolved_write(s)
        t.assert_log(s,FIRST_LOG,False)
        t.assert_log(s,SECOND_LOG,False)
    def test_loop_continue_restores_outer_after_scope(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;while(unsigned *p=&second){if(flag){continue;}break;}\n'+WRITE+'\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t94.T94PointerBranchTests().assert_log(s,FIRST_LOG,True)
        t94.T94PointerBranchTests().assert_log(s,SECOND_LOG,False)
    def test_if_header_keeps_external_retarget_divergence(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;if(unsigned *q=&second;flag){p=q;}\n'+WRITE+'\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t=t94.T94PointerBranchTests()
        t.assert_unresolved_write(s)
        t.assert_log(s,FIRST_LOG,False)
        t.assert_log(s,SECOND_LOG,False)
    def test_literal_control(self): self.check_cases(('literal-only',))
    def test_returning_branch_restores_outer_on_fallthrough(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;if(unsigned *p=&second;flag){return;}\n'+WRITE+'\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t94.T94PointerBranchTests().assert_log(s,FIRST_LOG,True)
        t94.T94PointerBranchTests().assert_log(s,SECOND_LOG,False)
    def test_nested_block_shadow_with_header(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;if(unsigned *p=&second;flag){{unsigned *p=&first;*p=7;}'+WRITE+'}\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t94.T94PointerBranchTests().assert_log(s,FIRST_LOG,False)
        t94.T94PointerBranchTests().assert_log(s,SECOND_LOG,True)
    def test_loop_body_rebind_does_not_escape_shadow(self):
        s=t94.T94PointerBranchTests().source('unsigned *p=&first;while(unsigned *p=&second){p=&first;break;}\n'+WRITE+'\n'+FIRST_LOG+'\n'+SECOND_LOG)
        t94.T94PointerBranchTests().assert_log(s,FIRST_LOG,True)
        t94.T94PointerBranchTests().assert_log(s,SECOND_LOG,False)
    def test_branch_targets_and_for_scope_controls(self):
        t=t94.T94PointerBranchTests()
        t.test_if_else_same_target_retains_actual_log()
        t.test_if_else_different_targets_retains_unresolved_not_known_sinks()
        t.test_for_initializer_shadow_is_removed_after_loop()
    def test_copy_unknown_and_null_cast_controls(self):
        t=t94.T94PointerBranchTests()
        t.test_copy_output_and_unknown_write_controls_remain()
        t.test_null_cast_sensitive_type_does_not_become_source()

if __name__=='__main__': unittest.main()
