"""D95 loop declaration scope and conservative pointer-target joins."""
import unittest
from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage


def scan(source,runner=False):
    context=support.SensitiveTests().context(source)
    detector=SensitiveExposureDetector(support.MODEL)
    if not runner:return detector.detect(context,context.units).findings
    registry=DetectorRegistry();registry.register(detector)
    reports,_=run_all_with_coverage(context,registry)
    return reports[0].diagnostics


class D95PointerTargetMergeTests(unittest.TestCase):
    def test_for_initializer_pointer_shadow_restores_outer_target(self):
        source='\n'.join(('void Callback(const char *key,bool flag){',
            'unsigned outer=0,inner=0;unsigned *p=&outer;',
            'for(unsigned *p=&inner;flag;){break;}',
            '*p=(unsigned char)key[0];',
            'HILOG_INFO(1,"%{public}u",outer);',
            'HILOG_INFO(1,"%{public}u",inner);','}'))
        for runner in (False,True):
            with self.subTest(runner=runner):
                self.assertEqual([f.line for f in scan(source,runner)],[5])

    def test_identical_branch_targets_keep_real_sink(self):
        source=('void Callback(const char *key,bool flag){unsigned value=0;unsigned *p=nullptr;'
                'if(flag){p=&value;}else{p=&value;}*p=(unsigned char)key[0];\n'
                'HILOG_INFO(1,"%{public}u",value);}')
        self.assertEqual([f.line for f in scan(source)],[2])

    def test_divergent_and_invalid_targets_do_not_pollute_both_scalars(self):
        for other in ('&second','nullptr','GetDestination()'):
            with self.subTest(other=other):
                source=('void Callback(const char *key,bool flag){unsigned first=0,second=0;unsigned *p=&first;'
                        'if(flag){p=&first;}else{p='+other+';}*p=(unsigned char)key[0];\n'
                        'HILOG_INFO(1,"%{public}u",first);\nHILOG_INFO(1,"%{public}u",second);}')
                found=scan(source)
                self.assertTrue(any('unresolved material write' in f.message for f in found))
                self.assertFalse(any(f.rule_id=='data.log.sensitive-value' for f in found))

    def test_loop_body_retarget_is_not_undone_by_scope_restore(self):
        for loop in ('while(flag){p=&second;break;}',
                     'for(unsigned i=0;flag;){p=&second;break;}'):
            with self.subTest(loop=loop):
                source=('void Callback(const char *key,bool flag){unsigned first=0,second=0;unsigned *p=&first;'
                        +loop+'*p=(unsigned char)key[0];\nHILOG_INFO(1,"%{public}u",first);\n'
                        'HILOG_INFO(1,"%{public}u",second);}')
                found=scan(source)
                self.assertTrue(any('unresolved material write' in f.message for f in found))
                self.assertFalse(any(f.rule_id=='data.log.sensitive-value' for f in found))

    def test_block_pointer_shadow_and_local_retarget_keep_separate_destinations(self):
        source=('void Callback(const char *key){unsigned first=0,second=0;unsigned *p=&first;'
                '{unsigned *p=&second;*p=7;}*p=(unsigned char)key[0];\n'
                'HILOG_INFO(1,"%{public}u",first);\nHILOG_INFO(1,"%{public}u",second);}')
        self.assertEqual([f.line for f in scan(source)],[2])

    def test_literal_only_write_after_pointer_divergence_does_not_create_material(self):
        source=('void Callback(const char *key,bool flag){unsigned first=0,second=0;unsigned *p=&first;'
                'if(flag){p=&first;}else{p=&second;}*p=7;'
                'HILOG_INFO(1,"%{public}u %{public}u",first,second);}')
        self.assertEqual(len(scan(source)),0)


if __name__=='__main__':unittest.main()
