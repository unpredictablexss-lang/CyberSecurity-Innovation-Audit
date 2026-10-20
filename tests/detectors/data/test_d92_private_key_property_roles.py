"""D92 exact private-key schema text versus fetched private-key material."""
import unittest

from tests.detectors.data.test_d87_property_roles import context
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


KEY = 'const std::string CERT_PRIVATE_KEY="key";\n'
GET = 'napi_get_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&data);'
HAS = 'napi_has_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&present);'


def scan(source, extra=(), partial=(), runner=False):
    ctx = context((('service.cpp',source),)+extra,partial=partial)
    detector = SensitiveExposureDetector()
    if not runner:
        return detector.detect(ctx,ctx.units).findings
    registry = DetectorRegistry()
    registry.register(detector)
    reports,_ = run_all_with_coverage(ctx,registry)
    return reports[0].diagnostics


class D92PrivateKeyPropertyRoleTests(unittest.TestCase):
    def test_exact_read_key_excludes_only_input_text(self):
        for call,declaration in ((GET,'napi_value data=nullptr;'),(HAS,'bool present=false;')):
            for runner in (False,True):
                with self.subTest(call=call,runner=runner):
                    self.assertEqual(len(scan(KEY+'void f(){'+declaration+call+'}',runner=runner)),0)

    def test_get_creates_material_even_for_ordinary_output_name(self):
        source = KEY+'void f(){napi_value data=nullptr;'+GET+'\nConsume(data);}'
        for runner in (False,True):
            with self.subTest(runner=runner):
                found = scan(source,runner=runner)
                self.assertEqual(len(found),1)
                self.assertEqual(found[0].line,3)
                self.assertIn('private-key-property output argument 3',found[0].message)
                self.assertNotIn('suspected sensitive-return API CERT_PRIVATE_KEY.c_str',found[0].message)

    def test_actual_getter_and_material_log_still_consume_output(self):
        source = KEY+'void f(){napi_value data=nullptr;'+GET+'\n'
        source += 'napi_get_value_string_utf8(env,data,buffer,32,&length);\n'
        source += 'HILOG_INFO(1,"%{public}s",static_cast<const char*>(data));}'
        found = scan(source)
        self.assertEqual(len(found),2)
        self.assertTrue(all('private-key-property output argument 3' in f.message for f in found))
        self.assertTrue(any('napi_get_value_string_utf8' in f.message for f in found))
        self.assertTrue(any('HILOG_INFO' in f.message for f in found))

    def test_has_returns_status_and_boolean_without_inventing_material(self):
        source = KEY+'void f(){bool present=false;int status='+HAS[:-1]+';\n'
        source += 'HILOG_INFO(1,"%{public}d %{public}d",present,status);}'
        self.assertEqual(len(scan(source)),0)

    def test_pair_does_not_generalize_to_other_literals_names_or_mutability(self):
        for definition in ('std::string CERT_PRIVATE_KEY="key";',
                           'const std::string CERT_PRIVATE_KEY="actual-private-key-bytes";',
                           'const std::string CERT_PRIVATE_KEY=ReadOpaqueKey();',
                           'const std::string OTHER_PRIVATE_KEY="key";'):
            with self.subTest(definition=definition):
                call = GET.replace('CERT_PRIVATE_KEY','OTHER_PRIVATE_KEY') if 'OTHER_' in definition else GET
                self.assertTrue(scan(definition+'void f(){napi_value data=nullptr;'+call+'}'))

    def test_shadow_namespace_and_wrong_argument_or_wrapper_remain_unknown(self):
        cases = (
            'void f(const std::string &CERT_PRIVATE_KEY){napi_value data=nullptr;'+GET+'}',
            'void f(std::string &&CERT_PRIVATE_KEY){napi_value data=nullptr;'+GET+'}',
            'void f(const std::string &input){const auto &CERT_PRIVATE_KEY=input;napi_value data=nullptr;'+GET+'}',
            'namespace Other {std::string CERT_PRIVATE_KEY=ReadOpaqueKey();void f(){napi_value data=nullptr;'+GET+'}}',
            'void f(){napi_get_named_property(env,obj,"ordinary",CERT_PRIVATE_KEY.c_str());}',
            'void f(){UnknownWrapper(CERT_PRIVATE_KEY.c_str());}',
            'void f(){napi_set_named_property(env,obj,"ordinary",CERT_PRIVATE_KEY.c_str());}',
        )
        for body in cases:
            with self.subTest(body=body):
                self.assertTrue(scan(KEY+body))

    def test_header_requires_unique_explicit_complete_binding(self):
        source = '#include "keys.h"\nvoid f(){napi_value data=nullptr;'+GET+'}'
        self.assertEqual(len(scan(source,extra=(('inc/keys.h',KEY),))),0)
        self.assertTrue(scan(source))
        self.assertTrue(scan(source,extra=(('inc/keys.h',KEY),),partial=('inc/keys.h',)))
        self.assertTrue(scan(source,extra=(('inc/keys.h',KEY),('other/keys.h',KEY))))

    def test_api_override_and_separate_log_proof_are_not_extended(self):
        self.assertTrue(scan('#define napi_get_named_property(a,b,c,d) UnknownWrapper(c)\n'+KEY+
                             'void f(){napi_value data=nullptr;'+GET+'}'))
        source = ('void napi_get_named_property(int env,int obj,const char *key,void *out){'
                  'HILOG_INFO(1,"%{public}s",key);}\n'+KEY+
                  'void f(){napi_value data=nullptr;'+GET+'}')
        self.assertTrue(scan(source))
        # Even prior NAPI use does not add the new literal pair to D89 log roles.
        header = ('#define CF_LOG_E(fmt,...) HILOG_ERROR(LOG_CORE,"%{public}s[%{public}u]: " fmt "\\n",__FUNCTION__,__LINE__,##__VA_ARGS__)\n'
                  '#define LOGE CF_LOG_E\n')
        self.assertTrue(scan('#include "logger.h"\n'+KEY+'void f(){bool present=false;'+HAS+
                             'LOGE("%{public}s",CERT_PRIVATE_KEY.c_str());}',
                             extra=(('logger.h',header),)))
        password_control = ('#include "logger.h"\nconst std::string CERT_PASSWORD="password";'
                            'void f(){bool present=false;'+HAS.replace('CERT_PRIVATE_KEY','CERT_PASSWORD')+
                            'LOGE("%{public}s",CERT_PASSWORD.c_str());}')
        self.assertEqual(len(scan(password_control,extra=(('logger.h',header),))),0)


if __name__ == '__main__':
    unittest.main()
