"""T90 independent metadata/material roles without a global NAPI name exemption."""
import unittest

from tests.detectors.data import test_t89_cleanup_binding as t89

TYPES = '''typedef void *napi_env;
typedef void *napi_value;
enum napi_valuetype {napi_string,napi_number};
enum napi_status {napi_ok,napi_invalid_arg};
'''
DECL = 'napi_status napi_typeof(napi_env,napi_value,napi_valuetype *);\n'
PURE = '''napi_status napi_typeof(napi_env env,napi_value value,napi_valuetype *result){
    *result=napi_string;
    return napi_ok;
}
'''


class T90NapiMetadataTests(unittest.TestCase):
    def scan(self, source, extra=(), partial=(), runner=False):
        return t89.T89CleanupBindingTests().scan(source, extra, partial, runner)

    def assert_candidate(self, source, *, message=None, extra=(), partial=()):
        for runner in (False, True):
            with self.subTest(runner=runner):
                findings = self.scan(source, extra, partial, runner)
                self.assertTrue(findings)
                if message:
                    self.assertTrue(any(message in item.message for item in findings))

    def test_visible_pure_metadata_body_has_no_material_log(self):
        # A complete invented body with literal enum/status outputs is a control,
        # not the implementation identity of the external NAPI function.
        source = TYPES + PURE + '''void Callback(napi_value key,napi_env env){
            napi_valuetype kind;
            napi_status status=napi_typeof(env,key,&kind);
            HILOG_INFO(1,"%{public}d %{public}d",status,kind);
        }'''
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual((), tuple(self.scan(source, runner=runner)))

    def test_external_name_without_binding_keeps_sink_and_status_dependency(self):
        source = TYPES + '''void Callback(napi_value key,napi_env env){
            napi_valuetype kind;
            auto status=napi_typeof(env,key,&kind);
            HILOG_INFO(1,"%{public}d",status);
        }'''
        self.assert_candidate(source, message='napi_typeof')
        self.assert_candidate(source, message='HILOG_INFO')

    def test_missing_declaration_or_partial_header_does_not_prove_metadata(self):
        source = '#include "napi/native_api.h"\n' + TYPES + '''void Callback(napi_value key,napi_env env){
            napi_valuetype kind; napi_typeof(env,key,&kind);
        }'''
        self.assert_candidate(source, message='napi_typeof')
        self.assert_candidate(source, message='napi_typeof',
            extra=(('napi/native_api.h', TYPES + DECL),), partial=('napi/native_api.h',))

    def test_complete_declaration_alone_does_not_establish_implementation(self):
        source = '#include "napi/native_api.h"\nvoid Callback(napi_value key,napi_env env){\n'
        source += 'napi_valuetype kind;napi_typeof(env,key,&kind);\n}'
        self.assert_candidate(source, message='napi_typeof', extra=(('napi/native_api.h', TYPES + DECL),))

    def test_same_name_custom_body_logs_actual_bytes(self):
        source = '''int napi_typeof(int env,const char *value,int *kind){
            HILOG_INFO(1,"%{public}s",value);return 0;
        }
        void Callback(const char *key){int kind;napi_typeof(0,key,&kind);}'''
        self.assert_candidate(source, message='HILOG_INFO')

    def test_same_name_custom_return_is_not_globally_classified_as_status(self):
        source = '''const char *napi_typeof(int env,const char *value,int *kind){return value;}
        void Callback(const char *key){int kind;auto status=napi_typeof(0,key,&kind);
            HILOG_INFO(1,"%{public}s",status);}
        '''
        self.assert_candidate(source, message='HILOG_INFO')

    def test_named_function_pointer_cannot_gain_api_proof(self):
        source = '''void Callback(const char *key,int(*napi_typeof)(int,const char *,int *)){
            int kind;napi_typeof(0,key,&kind);
        }'''
        self.assert_candidate(source, message='local callable target')

    def test_macro_override_and_unknown_wrapper_keep_candidate(self):
        for prefix, function in (('#define napi_typeof LeakPassword\n', 'napi_typeof'),
                                 ('', 'QueryTypeWrapper')):
            with self.subTest(function=function):
                self.assert_candidate(prefix + 'void Callback(const char *key){int kind;'
                    + function + '(0,key,&kind);}', message=function)

    def test_real_material_getter_call_remains_unresolved(self):
        source = TYPES + '''void Callback(napi_value key,napi_env env){
            char buffer[32];size_t size=0;
            napi_get_value_string_utf8(env,key,buffer,sizeof(buffer),&size);
        }'''
        self.assert_candidate(source, message='napi_get_value_string_utf8')

    def test_visible_material_extraction_keeps_buffer_log(self):
        source = '''int napi_get_value_string_utf8(int env,const char *value,char *buf,
            unsigned size,unsigned *result){memcpy_s(buf,size,value,size-1);return 0;}
        void Callback(const char *key){char buffer[32]={0};unsigned size=0;
            napi_get_value_string_utf8(0,key,buffer,sizeof(buffer),&size);
            HILOG_INFO(1,"%{public}s",buffer);
        }'''
        self.assert_candidate(source, message='HILOG_INFO')


if __name__ == '__main__':
    unittest.main()
