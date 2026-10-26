"""D93 explicit helper roles versus unbound nullptr/zero getter calls."""
import unittest

from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


TYPES = ('using size_t=decltype(sizeof(0)); using napi_env=void*; '
         'using napi_value=const char*; using napi_status=int; '
         'const int napi_ok=0; void HILOG_INFO(int,const char*,...);\n')
SIGNATURE = ('napi_status napi_get_value_string_utf8(napi_env env,napi_value value,'
             'char *buffer,size_t size,size_t *length)')
QUERY = 'napi_get_value_string_utf8(nullptr,key,nullptr,0,&length)'
CALLER = 'void Callback(const char *key){size_t length=0;'+QUERY+';}'


class D93LengthProbeBoundaryTests(unittest.TestCase):
    def scan(self,source,runner=False):
        ctx=support.SensitiveTests().context(source)
        detector=SensitiveExposureDetector(support.MODEL)
        if not runner:
            return detector.detect(ctx,ctx.units).findings
        registry=DetectorRegistry();registry.register(detector)
        reports,_=run_all_with_coverage(ctx,registry)
        return reports[0].diagnostics

    def test_query_shape_alone_and_declaration_only_keep_candidate(self):
        for declaration in ('',SIGNATURE+';\n'):
            for runner in (False,True):
                with self.subTest(declaration=bool(declaration),runner=runner):
                    found=self.scan(TYPES+declaration+CALLER,runner)
                    self.assertEqual(len(found),1)
                    self.assertIn('unresolved',found[0].message)

    def test_complete_visible_length_and_status_only_body_does_not_invent_bytes(self):
        # This invented implementation is visible; it is not the real N-API library.
        helper=SIGNATURE+'{*length=17;return napi_ok;}\n'
        caller=('void Callback(const char *key){size_t length=0;int status='+QUERY+';'
                'HILOG_INFO(1,"%{public}u %{public}d",static_cast<unsigned>(length),status);}')
        self.assertEqual(len(self.scan(TYPES+helper+caller)),0)
        self.assertEqual(len(self.scan(TYPES+helper+caller,True)),0)

    def test_query_shaped_custom_body_can_log_material(self):
        helper=SIGNATURE+'{HILOG_INFO(1,"%{public}s",value);*length=17;return napi_ok;}\n'
        found=self.scan(TYPES+helper+CALLER)
        self.assertTrue(found)
        self.assertTrue(any('HILOG_INFO' in f.message for f in found))

    def test_callable_macro_and_wrapper_cannot_gain_query_exemption(self):
        callers=(
            'void Callback(const char *key,napi_status(*napi_get_value_string_utf8)'
            '(napi_env,napi_value,char*,size_t,size_t*)){size_t length=0;'+QUERY+';}',
            '#define napi_get_value_string_utf8(a,b,c,d,e) UnknownWrapper(b)\n'+CALLER,
            'void Callback(const char *key){size_t length=0;UnknownWrapper(nullptr,key,nullptr,0,&length);}',
        )
        for caller in callers:
            for runner in (False,True):
                with self.subTest(caller=caller,runner=runner):
                    self.assertTrue(self.scan(TYPES+caller,runner))

    def test_missing_or_partial_declaration_does_not_prove_length_role(self):
        source='#include "api.h"\n'+TYPES+CALLER
        self.assertTrue(self.scan(source))
        run=support.SensitiveTests().analyze_many((('service.cpp',source),
            ('api.h',TYPES+SIGNATURE+';')),partial_paths=('api.h',))
        self.assertTrue(run.findings)
        self.assertNotEqual(dict(run.file_outcomes)['service.cpp'],'complete')

    def test_visible_byte_copy_and_later_buffer_log_keep_candidate(self):
        helper=(SIGNATURE+'{if(buffer!=nullptr){memcpy_s(buffer,size,value,size-1);'
                '*length=size-1;}else{*length=17;}return napi_ok;}\n')
        caller=('void Callback(const char *key){char buffer[32]={0};size_t length=0;'
                'napi_get_value_string_utf8(nullptr,key,buffer,sizeof(buffer),&length);'
                'HILOG_INFO(1,"%{public}s",buffer);}')
        found=self.scan(TYPES+helper+caller)
        self.assertTrue(found)
        self.assertTrue(any('HILOG_INFO' in f.message and 'memcpy_s' in f.message for f in found))

    def test_custom_material_return_is_not_globally_a_status(self):
        helper=('const char *napi_get_value_string_utf8(napi_env env,napi_value value,'
                'char *buffer,size_t size,size_t *length){return value;}\n')
        caller=('void Callback(const char *key){size_t length=0;const char *out='+QUERY+';'
                'HILOG_INFO(1,"%{public}s",out);}')
        self.assertTrue(self.scan(TYPES+helper+caller))


if __name__=='__main__':
    unittest.main()
