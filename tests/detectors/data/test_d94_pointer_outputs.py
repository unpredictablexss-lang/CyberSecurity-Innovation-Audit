"""D94 raw pointer output slots; unresolved material writes stay candidates."""
import json
from pathlib import Path
import unittest

from tests.detectors.data import test_sensitive_exposure as support


class D94PointerOutputTests(unittest.TestCase):
    def scan(self,source,**kwargs):
        return support.SensitiveTests().analyze(source,**kwargs)

    def test_exact_d93_negative_now_reaches_output_log(self):
        artifact=Path(__file__).resolve().parents[3]/'research/data_sensitive/D93_POINTER_OUTPUT_GAP_20261020.json'
        run=self.scan(json.loads(artifact.read_text())['source'])
        self.assertTrue(any(f.rule_id=='data.log.sensitive-value' and 'assign *length' in f.message for f in run.findings))

    def test_local_pointer_and_copy_reach_scalar_sink(self):
        source=('void Callback(const char *key){unsigned value=0;unsigned *p=&value;'
                'auto copy=p;*copy=(unsigned char)key[0];\n'
                'HILOG_INFO(1,"%{public}u",value);}')
        self.assertTrue(any(f.line==2 and f.rule_id=='data.log.sensitive-value' for f in self.scan(source).findings))

    def test_address_of_member_and_pointer_to_local_object_reach_member_sink(self):
        for write in ('unsigned *p=&value.count;*p=(unsigned char)key[0];',
                      'Box *p=&value;p->count=(unsigned char)key[0];'):
            with self.subTest(write=write):
                run=self.scan('struct Box{unsigned count;};void Callback(const char *key){Box value={0};'+
                              write+'\nHILOG_INFO(1,"%{public}u",value.count);}')
                self.assertTrue(any(f.line==2 and f.rule_id=='data.log.sensitive-value' for f in run.findings))
        source=('struct Box{unsigned count;};void Write(const char *value,Box *out){'
                'out->count=(unsigned char)value[0];}'
                'void Callback(const char *key){Box value={0};Write(key,&value);\n'
                'HILOG_INFO(1,"%{public}u",value.count);}')
        self.assertTrue(any(f.line==2 and f.rule_id=='data.log.sensitive-value' for f in self.scan(source).findings))

    def test_unknown_and_member_pointer_write_has_destination_obligation(self):
        for setup,left in (('unsigned *p=GetDestination();','*p'),
                           ('unsigned *p=nullptr;','*p'),
                           ('Box box;','*box.output')):
            with self.subTest(left=left,setup=setup):
                run=self.scan('struct Box{unsigned *output;};void Callback(const char *key){'+setup+
                              left+'=(unsigned char)key[0];}')
                self.assertTrue(any('unresolved material write' in f.message for f in run.findings))
                self.assertTrue(any(o.kind=='destination_binding' for f in run.findings for o in f.evidence_obligations))

    def test_retarget_and_overwrite_do_not_pollute_old_scalar(self):
        source=('void Callback(const char *key){unsigned old=0,next=0;unsigned *p=&old;'
                'p=&next;*p=(unsigned char)key[0];\n'
                'HILOG_INFO(1,"%{public}u",old);\nHILOG_INFO(1,"%{public}u",next);}')
        found=self.scan(source).findings
        self.assertEqual([f.line for f in found],[3])
        self.assertEqual(len(self.scan('void Callback(const char *key){unsigned value=0;unsigned *p=&value;'
            '*p=(unsigned char)key[0];value=0;HILOG_INFO(1,"%{public}u",value);}').findings),0)

    def test_literal_metadata_stays_without_material(self):
        source=('void Write(const char *value,unsigned *out){*out=7;}'
                'void Callback(const char *key){unsigned output=0;Write(key,&output);'
                'HILOG_INFO(1,"%{public}u",output);}')
        self.assertEqual(len(self.scan(source).findings),0)
        self.assertEqual(len(self.scan('void Callback(const char *key,unsigned *out){*out=7;}').findings),0)

    def test_macro_override_does_not_borrow_literal_body_safety(self):
        source=('void Write(const char *value,unsigned *out){*out=7;}\n'
                '#define Write(value,out) LeakKey(value)\n'
                'void Callback(const char *key){unsigned output=0;Write(key,&output);}')
        self.assertTrue(any('macro-overridden' in f.message for f in self.scan(source).findings))

    def test_partial_and_shadowed_aliases_remain_unresolved(self):
        source=('void Callback(const char *key){unsigned value=0;unsigned *p=&value;'
                '{unsigned value=0;*p=(unsigned char)key[0];}}')
        self.assertTrue(any('unresolved material write' in f.message for f in self.scan(source).findings))
        source='void Callback(const char *key){unsigned value=0;unsigned *p=&value;*p=(unsigned char)key[0];}'
        run=self.scan(source,partial='partial')
        self.assertTrue(any('unresolved material write' in f.message for f in run.findings))
        self.assertNotEqual(dict(run.file_outcomes)['service.cpp'],'complete')

    def test_cpp_pointer_cast_type_name_does_not_invent_material(self):
        from tests.detectors.data.test_d87_property_roles import analyze
        source='struct PrivateKeyInfo{int unused;};void sample(PrivateKeyInfo **output){*output=static_cast<PrivateKeyInfo *>(nullptr);}'
        self.assertEqual(len(analyze(source).findings),0)
        self.assertTrue(self.scan('void Callback(const char *key){const char *out=static_cast<const char*>(key);'
                                 'HILOG_INFO(1,"%{public}s",out);}').findings)
        self.assertTrue(analyze('#define static_cast UnknownCast\n'+source).findings)


if __name__=='__main__':
    unittest.main()
