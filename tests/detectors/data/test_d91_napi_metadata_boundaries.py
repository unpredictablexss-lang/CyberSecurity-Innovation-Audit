"""D91 role controls: unbound N-API names are not a metadata safety proof."""
import unittest

from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


TYPES = ('typedef int napi_status; typedef void *napi_env; typedef void *napi_value; '
         'enum napi_valuetype {napi_undefined,napi_string}; const int napi_ok=0;\n')
CALL = 'napi_typeof(env,key,&type);'
DECL = 'napi_status napi_typeof(napi_env env,napi_value value,napi_valuetype *result);\n'
CALLER = 'void Callback(napi_value key){napi_env env=nullptr;napi_valuetype type;'+CALL+'}'


class D91NapiMetadataBoundaryTests(unittest.TestCase):
    def scan(self, source, runner=False):
        ctx = support.SensitiveTests().context(source)
        detector = SensitiveExposureDetector(support.MODEL)
        if not runner:
            return detector.detect(ctx,ctx.units).findings
        registry = DetectorRegistry()
        registry.register(detector)
        reports,_ = run_all_with_coverage(ctx,registry)
        return reports[0].diagnostics

    def test_missing_and_signature_only_typeof_keep_material_binding_unknown(self):
        for declaration in ('',DECL):
            for runner in (False,True):
                with self.subTest(declaration=bool(declaration),runner=runner):
                    found = self.scan(TYPES+declaration+CALLER,runner)
                    self.assertEqual(len(found),1)
                    self.assertIn('unresolved',found[0].message)
                    self.assertIn('napi_typeof',found[0].message)

    def test_partial_declaration_is_not_proof(self):
        run = support.SensitiveTests().analyze_many((
            ('service.cpp','#include "api.h"\n'+CALLER),
            ('api.h',TYPES+DECL)),partial_paths=('api.h',))
        self.assertTrue(run.findings)
        self.assertIn('napi_typeof',run.findings[0].message)

    def test_visible_metadata_only_custom_body_is_analyzed_without_name_exemption(self):
        # This is a complete synthetic helper, not the unbound real N-API library.
        source = (TYPES+'napi_status napi_typeof(napi_env env,napi_value value,'
                  'napi_valuetype *result){*result=napi_string;return napi_ok;}\n'+CALLER)
        self.assertEqual(len(self.scan(source)),0)
        self.assertEqual(len(self.scan(source,True)),0)

    def test_same_name_body_that_outputs_value_keeps_real_candidate(self):
        source = (TYPES+'void HILOG_INFO(int,const char*,...);\n'
                  'napi_status napi_typeof(napi_env env,napi_value value,'
                  'napi_valuetype *result){HILOG_INFO(1,"%{public}s",static_cast<const char*>(value));'
                  '*result=napi_string;return napi_ok;}\n'+CALLER)
        found = self.scan(source)
        self.assertTrue(found)
        self.assertTrue(any('HILOG_INFO' in f.message for f in found))

    def test_callable_and_macro_overrides_keep_candidate(self):
        sources = (
            TYPES+'void Callback(napi_value key,napi_status(*napi_typeof)'
            '(napi_env,napi_value,napi_valuetype*)){napi_env env=nullptr;'
            'napi_valuetype type;'+CALL+'}',
            '#define napi_typeof(env,value,result) LeakPassword(value)\n'+TYPES+
            'napi_status LeakPassword(napi_value);\n'+CALLER,
        )
        for source in sources:
            for runner in (False,True):
                with self.subTest(source=source,runner=runner):
                    self.assertTrue(self.scan(source,runner))

    def test_actual_string_extraction_name_is_not_exempted(self):
        for output in ('nullptr','buffer'):
            with self.subTest(output=output):
                source = ('#include <cstddef>\n'+TYPES+
                          'napi_status napi_get_value_string_utf8(napi_env,napi_value,char*,size_t,size_t*);\n'
                          'void Callback(napi_value key){napi_env env=nullptr;char buffer[32];'
                          'size_t length=0;napi_get_value_string_utf8(env,key,'+
                          output+',sizeof(buffer),&length);}')
                found = self.scan(source)
                self.assertTrue(found)
                self.assertIn('napi_get_value_string_utf8',found[0].message)


if __name__ == '__main__':
    unittest.main()
