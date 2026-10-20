"""T93 independent material-derived scalar pointee writes and alias controls."""
from dataclasses import asdict
import unittest
from tests.detectors.data import test_t89_cleanup_binding as t89
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

LOG_PROTO = 'void HILOG_INFO(int,const char *,...);\n'
HELPER = 'void Write(const char *value,unsigned *out){*out=(unsigned char)value[0];}\n'
META = 'void Write(const char *value,unsigned *out){*out=7;}\n'
NULL_CAST = 'struct PrivateKeyInfo{int unused;};\nvoid sample(PrivateKeyInfo **output){*output=static_cast<PrivateKeyInfo *>(nullptr);}'


class T93ScalarPointerTests(unittest.TestCase):
    def context(self, source, extra=(), partial=()):
        return t89.T89CleanupBindingTests().context(source, extra, partial)

    def analyze(self, source, extra=(), partial=(), runner=False):
        context = self.context(source, extra, partial)
        detector = SensitiveExposureDetector(t89.MODEL)
        if runner:
            registry = DetectorRegistry()
            registry.register(detector)
            reports, coverage = run_all_with_coverage(context, registry)
            return reports[0].to_dict(), coverage
        result = detector.detect(context, context.units)
        return asdict(result), None

    def rows(self, source, runner=False, **kwargs):
        result, _ = self.analyze(source, runner=runner, **kwargs)
        return list(result.get('diagnostics', result.get('findings', [])))

    def assert_log(self, source, statement):
        line = source.splitlines().index(statement) + 1
        for runner in (False, True):
            with self.subTest(runner=runner):
                rows = self.rows(source, runner=runner)
                self.assertTrue(any(row['file'] == 'service.cpp' and row['line'] == line
                    and 'HILOG_INFO' in row['message'] and 'Callback parameter 0' in row['message']
                    for row in rows), rows)

    def assert_no_log(self, source, statement):
        line = source.splitlines().index(statement) + 1
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertFalse(any(row['line'] == line and 'HILOG_INFO' in row['message']
                    for row in self.rows(source, runner=runner)))

    def assert_material_candidate(self, source, **kwargs):
        for runner in (False, True):
            with self.subTest(runner=runner):
                rows = self.rows(source, runner=runner, **kwargs)
                self.assertTrue(any('Callback parameter 0' in row['message'] for row in rows), rows)

    def test_material_scalar_parameter_write_reaches_log(self):
        log = 'HILOG_INFO(1,"%{public}u",output);'
        source = LOG_PROTO + HELPER + 'void Callback(const char *key){unsigned output=0;Write(key,&output);\n' + log + '\n}'
        self.assert_log(source, log)

    def test_proven_local_pointer_to_local_scalar_reaches_log(self):
        log = 'HILOG_INFO(1,"%{public}u",output);'
        source = LOG_PROTO + 'void Callback(const char *key){unsigned output=0;unsigned *p=&output;\n*p=(unsigned char)key[0];\n' + log + '\n}'
        self.assert_log(source, log)

    def test_transparent_parameter_pointer_alias_does_not_lose_material(self):
        log = 'HILOG_INFO(1,"%{public}u",output);'
        source = LOG_PROTO + 'void Write(const char *value,unsigned *out){unsigned *alias=out;*alias=(unsigned char)value[0];}\n'
        source += 'void Callback(const char *key){unsigned output=0;Write(key,&output);\n' + log + '\n}'
        self.assert_log(source, log)

    def test_unknown_pointee_material_write_is_a_candidate(self):
        source = 'unsigned *GetDestination();\nvoid Callback(const char *key){unsigned *p=GetDestination();\n*p=(unsigned char)key[0];\n}'
        self.assert_material_candidate(source)

    def test_member_pointer_material_write_is_not_silently_safe(self):
        source = 'struct Holder{unsigned *out;};\nvoid Callback(const char *key,Holder *holder){\n*holder->out=(unsigned char)key[0];\n}'
        self.assert_material_candidate(source)

    def test_literal_only_pointee_write_does_not_create_material(self):
        source = LOG_PROTO + META + 'void Callback(const char *key){unsigned output=0;Write(key,&output);HILOG_INFO(1,"%{public}u",output);}'
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual([], self.rows(source, runner=runner))

    def test_ordinary_scalar_overwrite_removes_later_log_dependency(self):
        log = 'HILOG_INFO(1,"%{public}u",output);'
        source = LOG_PROTO + HELPER + 'void Callback(const char *key){unsigned output=0;Write(key,&output);output=7;\n' + log + '\n}'
        self.assert_no_log(source, log)

    def test_pointer_retarget_does_not_taint_old_scalar(self):
        old_log = 'HILOG_INFO(1,"%{public}u",first);'
        new_log = 'HILOG_INFO(1,"%{public}u",second);'
        source = LOG_PROTO + 'void Callback(const char *key){unsigned first=0,second=0;unsigned *p=&first;p=&second;*p=(unsigned char)key[0];\n' + old_log + '\n' + new_log + '\n}'
        self.assert_no_log(source, old_log)
        self.assert_log(source, new_log)

    def test_shadowed_pointer_does_not_taint_outer_destination(self):
        inner_log = 'HILOG_INFO(1,"%{public}u",inner);'
        outer_log = 'HILOG_INFO(1,"%{public}u",outer);'
        source = LOG_PROTO + 'void Callback(const char *key){unsigned outer=0;unsigned *p=&outer;{unsigned inner=0;unsigned *p=&inner;*p=(unsigned char)key[0];\n' + inner_log + '\n}\n' + outer_log + '\n}'
        self.assert_no_log(source, outer_log)
        self.assert_log(source, inner_log)

    def test_custom_api_named_length_output_remains_material(self):
        source = LOG_PROTO + 'int napi_get_value_string_utf8(void *env,const char *value,char *buffer,unsigned size,unsigned *length){*length=(unsigned char)value[0];return 0;}\n'
        source += 'void Callback(const char *key){unsigned length=0;napi_get_value_string_utf8(nullptr,key,nullptr,0,&length);\nHILOG_INFO(1,"%{public}u",length);\n}'
        self.assert_log(source, 'HILOG_INFO(1,"%{public}u",length);')

    def test_callback_unknown_or_partial_declaration_keep_candidate(self):
        self.assert_material_candidate('void Callback(const char *key,void(*Write)(const char*,unsigned*)){unsigned output=0;Write(key,&output);}')
        source = '#include "write.h"\nvoid Callback(const char *key){unsigned output=0;Write(key,&output);}'
        self.assert_material_candidate(source)
        self.assert_material_candidate(source, extra=(('write.h','void Write(const char*,unsigned*);'),), partial=('write.h',))

    def test_macro_override_cannot_borrow_literal_body_proof(self):
        source = LOG_PROTO + 'void LeakKey(const char*);\n' + META
        source += '#define Write(value,out) LeakKey(value)\nvoid Callback(const char *key){unsigned output=0;Write(key,&output);}'
        self.assert_material_candidate(source)

    def test_null_cast_to_sensitive_named_type_is_not_material(self):
        # A language cast of nullptr has no bytes from a secret, irrespective of
        # the pointee type name. Exercise the unknown-profile heuristic too.
        source = NULL_CAST
        context = self.context(source)
        for runner in (False, True):
            detector = SensitiveExposureDetector()
            with self.subTest(runner=runner):
                if runner:
                    registry = DetectorRegistry()
                    registry.register(detector)
                    reports, _ = run_all_with_coverage(context, registry)
                    rows = list(reports[0].diagnostics)
                else:
                    rows = list(detector.detect(context, context.units).findings)
                self.assertEqual([], rows)


if __name__ == '__main__':
    unittest.main()
