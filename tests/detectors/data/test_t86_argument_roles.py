"""T86 independent property-key/value/binding controls; no accuracy labels."""
from dataclasses import replace
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource


KEY = 'const std::string CERT_PASSWORD="password";\n'
HAS = 'bool present=false; napi_has_named_property(env,obj,CERT_PASSWORD.c_str(),&present);'


class T86ArgumentRoleTests(unittest.TestCase):
    def scan(self, source, headers=(), partial_paths=()):
        sources = []
        for path, text in (('sample.cpp', source), *headers):
            data = text.encode()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            sources.append(GitSource(path, 'cpp', blob, data))
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted((replace(u, parse_status='partial') if u.path in partial_paths else u
                              for u in units), key=lambda unit: unit.path))
        for path in partial_paths:
            ast[path]['parse_status'] = 'partial'
        request = ScanRequest('t86-independent', 'fixture/t86', 'a' * 40, snapshot_digest(units),
                              'current-component:fixture/t86')
        return SensitiveExposureDetector().detect(ScanContext(request, units, {'ast': ast}), units)

    def test_exact_same_scope_property_key_is_distinct_from_value(self):
        has = self.scan(KEY + 'void sample(napi_env env,napi_value obj){' + HAS + '}')
        self.assertEqual((), has.findings)
        get = self.scan(KEY + '''void sample(napi_env env,napi_value obj){
            napi_value ordinaryOutput=nullptr;
            napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&ordinaryOutput); }''')
        self.assertEqual((), get.findings)
        self.assertEqual('blocked', has.status)

    def test_retrieved_password_output_is_not_the_property_key(self):
        run = self.scan(KEY + '''void sample(napi_env env,napi_value obj){
            napi_value password=nullptr;
            napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&password); }''')
        self.assertTrue(run.findings)
        self.assertTrue(any('identifier password' in f.message for f in run.findings))
        self.assertTrue(all('CERT_PASSWORD' not in f.message for f in run.findings))

    def test_get_password_material_reaches_unrelated_output_name(self):
        run = self.scan(KEY + '''void sample(napi_env env,napi_value obj){
            napi_value ordinaryOutput=nullptr;
            napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&ordinaryOutput);
            const char *text=ReadStringValue(env,ordinaryOutput);
            HILOG_INFO(1,"%{public}s",text); }''')
        self.assertTrue(any(f.rule_id == 'data.log.sensitive-value' for f in run.findings))

    def test_napi_status_and_has_boolean_are_not_password_material(self):
        for source in (
            KEY + '''void sample(napi_env env,napi_value obj){napi_value ordinaryOutput=nullptr;
                int status=napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&ordinaryOutput);
                HILOG_INFO(1,"%{public}d",status); }''',
            KEY + '''void sample(napi_env env,napi_value obj){bool present=false;
                napi_has_named_property(env,obj,CERT_PASSWORD.c_str(),&present);
                HILOG_INFO(1,"%{public}d",present); }''',
        ):
            with self.subTest(source=source):
                self.assertFalse(any(f.rule_id == 'data.log.sensitive-value' for f in self.scan(source).findings))

    def test_actual_password_value_and_dynamic_key_remain_candidates(self):
        for source in (
            'void sample(const char *password){HILOG_INFO(1,"%{public}s",password);}',
            'void sample(napi_env env,napi_value obj,napi_value password){napi_set_named_property(env,obj,"password",password);}',
            'void sample(napi_env env,napi_value obj,const char *password){bool present; napi_has_named_property(env,obj,password,&present);}',
        ):
            with self.subTest(source=source):
                self.assertTrue(self.scan(source).findings)

    def test_unknown_helper_and_short_log_wrapper_keep_unknown_binding(self):
        for expression in ('UnknownPropertyHelper(env,obj,CERT_PASSWORD.c_str());',
                           'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'):
            with self.subTest(expression=expression):
                run = self.scan(KEY + 'void sample(napi_env env,napi_value obj){' + expression + '}')
                self.assertTrue(run.findings)
                self.assertTrue(all(f.rule_id == 'data.sensitive.unresolved-escape' for f in run.findings))

    def test_unrelated_literal_and_unknown_initializer_do_not_gain_key_proof(self):
        for declaration in ('const std::string CERT_PASSWORD="actual-hardcoded-value";',
                            'const std::string CERT_PASSWORD=ReadSecret();',
                            'std::string CERT_PASSWORD="password";'):
            with self.subTest(declaration=declaration):
                self.assertTrue(self.scan(declaration + 'void sample(napi_env env,napi_value obj){' + HAS + '}').findings)

    def test_matching_explicit_header_and_namespace(self):
        source = '#include "defs.h"\nnamespace N {void sample(napi_env env,napi_value obj){' + HAS + '}}'
        for header in ('namespace N {' + KEY + '}',
                       '#ifndef DEFS_H\n#define DEFS_H\nnamespace N {' + KEY + '}\n#endif\n'):
            with self.subTest(header=header):
                self.assertEqual((), self.scan(source, (('defs.h', header),)).findings)

    def test_missing_include_partial_header_and_ambiguous_basename_keep_unknown(self):
        source = 'namespace N {void sample(napi_env env,napi_value obj){' + HAS + '}}'
        header = 'namespace N {' + KEY + '}'
        self.assertTrue(self.scan(source, (('defs.h', header),)).findings)
        included = '#include "defs.h"\n' + source
        self.assertTrue(self.scan(included, (('defs.h', header),), partial_paths=('defs.h',)).findings)
        self.assertTrue(self.scan(included, (('a/defs.h', header), ('b/defs.h', header))).findings)

    def test_local_and_parameter_shadow_do_not_use_global_constant(self):
        for source in (
            KEY + 'void sample(napi_env env,napi_value obj,const std::string &CERT_PASSWORD){' + HAS + '}',
            KEY + 'void sample(napi_env env,napi_value obj,std::string &&CERT_PASSWORD){' + HAS + '}',
            KEY + 'void sample(napi_env env,napi_value obj,const char *provided){const std::string CERT_PASSWORD=provided;' + HAS + '}',
            KEY + 'void sample(napi_env env,napi_value obj,const std::string &provided){const std::string &CERT_PASSWORD=provided;' + HAS + '}',
        ):
            with self.subTest(source=source):
                self.assertTrue(self.scan(source).findings)

    def test_api_macro_and_conditional_header_do_not_prove_binding(self):
        source = '#include "defs.h"\nvoid sample(napi_env env,napi_value obj){' + HAS + '}'
        conditional = '#ifdef FEATURE_PASSWORD\n' + KEY + '#endif\n'
        self.assertTrue(self.scan(source, (('defs.h', conditional),)).findings)
        source = '#define napi_has_named_property UnknownHelper\n' + KEY + 'void sample(napi_env env,napi_value obj){' + HAS + '}'
        self.assertTrue(self.scan(source).findings)

    def test_other_namespace_constant_cannot_prove_dynamic_same_name(self):
        source = ('namespace A {' + KEY + '}\nnamespace B {const std::string CERT_PASSWORD=ReadSecret();'
                  'void sample(napi_env env,napi_value obj){' + HAS + '}}')
        self.assertTrue(self.scan(source).findings)

    def test_same_name_local_api_definition_is_analyzed_as_local(self):
        source = KEY + '''int napi_has_named_property(napi_env env,napi_value obj,const char *name,bool *out){
            HILOG_INFO(1,"%{public}s",name);return 0;}
            void sample(napi_env env,napi_value obj){''' + HAS + '}'
        run = self.scan(source)
        self.assertTrue(run.findings)
        self.assertTrue(any(f.rule_id == 'data.log.sensitive-value' for f in run.findings))


if __name__ == '__main__':
    unittest.main()
