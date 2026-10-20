"""T94 independent path joins, scoped pointer targets and conservative writes."""
import unittest
from tests.detectors.data import test_t93_scalar_pointer_writes as t93

PROTO = 'void HILOG_INFO(int,const char*,...);\n'
WRITE = '*p=(unsigned char)key[0];'
FIRST_LOG = 'HILOG_INFO(1,"%{public}u",first);'
SECOND_LOG = 'HILOG_INFO(1,"%{public}u",second);'


class T94PointerBranchTests(unittest.TestCase):
    def source(self, body):
        return PROTO + 'void Callback(const char *key,bool flag){unsigned first=0,second=0;\n' + body + '\n}'

    def analyze(self, source, runner=False):
        return t93.T93ScalarPointerTests().analyze(source, runner=runner)

    def context(self, source):
        return t93.T93ScalarPointerTests().context(source)

    def rows(self, source, runner=False):
        result, _ = self.analyze(source, runner)
        return list(result.get('diagnostics', result.get('findings', [])))

    def assert_log(self, source, statement, expected):
        line = source.splitlines().index(statement) + 1
        for runner in (False, True):
            with self.subTest(runner=runner, statement=statement):
                actual = any(row['file'] == 'service.cpp' and row['line'] == line
                    and 'HILOG_INFO' in row['message'] and 'Callback parameter 0' in row['message']
                    for row in self.rows(source, runner))
                self.assertEqual(expected, actual)

    def assert_unresolved_write(self, source):
        for runner in (False, True):
            with self.subTest(runner=runner):
                rows = self.rows(source, runner)
                self.assertTrue(any('unresolved material write' in row['message']
                    and 'Callback parameter 0' in row['message'] for row in rows), rows)

    def test_if_else_same_target_retains_actual_log(self):
        source = self.source('unsigned *p=nullptr;if(flag){p=&first;}else{p=&first;}\n' + WRITE + '\n' + FIRST_LOG)
        self.assert_log(source, FIRST_LOG, True)

    def test_if_else_different_targets_retains_unresolved_not_known_sinks(self):
        source = self.source('unsigned *p=nullptr;if(flag){p=&first;}else{p=&second;}\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_unresolved_write(source)
        self.assert_log(source, FIRST_LOG, False)
        self.assert_log(source, SECOND_LOG, False)

    def test_one_branch_null_or_unknown_invalidates_known_destination(self):
        for branch in ('nullptr', 'GetDestination()'):
            source = 'unsigned *GetDestination();\n' + self.source('unsigned *p=&first;if(flag){p=' + branch + ';}\n' + WRITE + '\n' + FIRST_LOG)
            self.assert_unresolved_write(source)
            self.assert_log(source, FIRST_LOG, False)

    def test_explicit_rebind_after_divergence_restores_known_target(self):
        source = self.source('unsigned *p=nullptr;if(flag){p=&first;}else{p=&second;}p=&first;\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_log(source, FIRST_LOG, True)
        self.assert_log(source, SECOND_LOG, False)

    def test_only_live_branch_controls_target_after_return(self):
        source = self.source('unsigned *p=&first;if(flag){return;}else{p=&second;}\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_log(source, FIRST_LOG, False)
        self.assert_log(source, SECOND_LOG, True)

    def test_block_pointer_shadow_and_exit_restore_outer_target(self):
        source = self.source('unsigned *p=&first;{unsigned *p=&second;*p=7;}\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_log(source, FIRST_LOG, True)
        self.assert_log(source, SECOND_LOG, False)

    def test_loop_may_rebind_keeps_unknown_and_no_exact_sink(self):
        source = self.source('unsigned *p=&first;while(flag){p=&second;break;}\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_unresolved_write(source)
        self.assert_log(source, FIRST_LOG, False)
        self.assert_log(source, SECOND_LOG, False)

    def test_for_initializer_shadow_is_removed_after_loop(self):
        source = self.source('unsigned *p=&first;for(unsigned *p=&second;flag;){break;}\n' + WRITE + '\n' + FIRST_LOG + '\n' + SECOND_LOG)
        self.assert_log(source, FIRST_LOG, True)
        self.assert_log(source, SECOND_LOG, False)

    def test_literal_write_under_divergence_does_not_create_material(self):
        source = self.source('unsigned *p=nullptr;if(flag){p=&first;}else{p=&second;}*p=7;\n' + FIRST_LOG + '\n' + SECOND_LOG)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual([], self.rows(source, runner))

    def test_copy_output_and_unknown_write_controls_remain(self):
        copy = PROTO + 'void Copy(const char *value,char *out){memcpy_s(out,8,value,7);}\nvoid Callback(const char *key){char output[8]={0};Copy(key,output);\nHILOG_INFO(1,"%{public}s",output);\n}'
        self.assert_log(copy, 'HILOG_INFO(1,"%{public}s",output);', True)
        unknown = self.source('unsigned *p=nullptr;if(flag){p=&first;}\n' + WRITE)
        self.assert_unresolved_write(unknown)

    def test_null_cast_sensitive_type_does_not_become_source(self):
        t93.T93ScalarPointerTests().test_null_cast_to_sensitive_named_type_is_not_material()


if __name__ == '__main__':
    unittest.main()
