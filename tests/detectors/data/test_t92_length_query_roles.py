"""T92 length-only metadata controls never grant an external API name exemption."""
import unittest
from tests.detectors.data import test_t89_cleanup_binding as t89

TYPES = 'typedef void *napi_env;typedef void *napi_value;typedef unsigned long size_t;\n'
QUERY = 'napi_get_value_string_utf8(env,key,nullptr,0,&length);'
DECL = 'int napi_get_value_string_utf8(napi_env,napi_value,char *,size_t,size_t *);\n'
LENGTH_BODY = '''int napi_get_value_string_utf8(int env,const char *value,char *buffer,
    unsigned size,unsigned *result){*result=strlen(value);return 0;}
'''


class T92LengthQueryTests(unittest.TestCase):
    def scan(self, source, extra=(), partial=(), runner=False):
        return t89.T89CleanupBindingTests().scan(source, extra, partial, runner)

    def assert_candidate(self, source, *, message=None, extra=(), partial=()):
        for runner in (False, True):
            with self.subTest(runner=runner):
                rows = self.scan(source, extra, partial, runner)
                self.assertTrue(rows)
                if message:
                    self.assertTrue(any(message in row.message for row in rows))

    def test_visible_length_body_status_length_log_and_condition_are_metadata(self):
        # This invented complete body uses the pre-existing scalar strlen model;
        # it is not an identity proof for the real external NAPI implementation.
        source = LENGTH_BODY + '''void Callback(const char *key){unsigned length=0;
            auto status=napi_get_value_string_utf8(0,key,nullptr,0,&length);
            HILOG_INFO(1,"%{public}u %{public}d",length,status);
            if(length>0){HILOG_INFO(1,"nonempty");}
        }'''
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual((), tuple(self.scan(source, runner=runner)))

    def test_unbound_query_keeps_source_sink_and_unknown_status_flow(self):
        source = TYPES + '''void Callback(napi_value key,napi_env env){size_t length=0;
            auto status=napi_get_value_string_utf8(env,key,nullptr,0,&length);
            HILOG_INFO(1,"%{public}d",status);
        }'''
        self.assert_candidate(source, message='napi_get_value_string_utf8')
        self.assert_candidate(source, message='HILOG_INFO')

    def test_missing_partial_and_declaration_only_inputs_do_not_bind_api(self):
        source = '#include "napi/native_api.h"\n' + TYPES + 'void Callback(napi_value key,napi_env env){size_t length=0;\n' + QUERY + '\n}'
        self.assert_candidate(source)
        self.assert_candidate(source, extra=(('napi/native_api.h', TYPES + DECL),))
        self.assert_candidate(source, extra=(('napi/native_api.h', TYPES + DECL),), partial=('napi/native_api.h',))

    def test_same_name_custom_query_body_can_leak_content(self):
        source = '''int napi_get_value_string_utf8(int env,const char *value,char *buf,
            unsigned size,unsigned *out){HILOG_INFO(1,"%{public}s",value);*out=7;return 0;}
        void Callback(const char *key){unsigned length=0;
            napi_get_value_string_utf8(0,key,nullptr,0,&length);}
        '''
        self.assert_candidate(source, message='HILOG_INFO')

    def test_same_name_custom_return_is_not_assumed_to_be_status(self):
        source = '''const char *napi_get_value_string_utf8(int env,const char *value,
            char *buf,unsigned size,unsigned *out){return value;}
        void Callback(const char *key){unsigned length=0;
            auto status=napi_get_value_string_utf8(0,key,nullptr,0,&length);
            HILOG_INFO(1,"%{public}s",status);}
        '''
        self.assert_candidate(source, message='HILOG_INFO')

    def test_callback_macro_and_unknown_wrapper_do_not_gain_query_proof(self):
        source = TYPES + 'void Callback(napi_value key,napi_env env,int(*napi_get_value_string_utf8)(napi_env,napi_value,char*,size_t,size_t*)){size_t length=0;' + QUERY + '}'
        self.assert_candidate(source, message='local callable target')
        for prefix, name in (('#define napi_get_value_string_utf8 LeakValue\n', 'napi_get_value_string_utf8'),
                             ('', 'QueryLengthWrapper')):
            source = prefix + TYPES + 'void Callback(napi_value key,napi_env env){size_t length=0;' + QUERY.replace('napi_get_value_string_utf8', name) + '}'
            self.assert_candidate(source, message=name)

    def test_external_actual_byte_buffer_getter_is_not_excluded(self):
        source = TYPES + '''void Callback(napi_value key,napi_env env){size_t length=0;
            char buffer[32];napi_get_value_string_utf8(env,key,buffer,sizeof(buffer),&length);
        }'''
        self.assert_candidate(source, message='napi_get_value_string_utf8')

    def test_visible_byte_getter_retains_material_log(self):
        source = '''int napi_get_value_string_utf8(int env,const char *value,char *buf,
            unsigned size,unsigned *out){memcpy_s(buf,size,value,size-1);return 0;}
        void Callback(const char *key){unsigned length=0;char buffer[32]={0};
            napi_get_value_string_utf8(0,key,buffer,sizeof(buffer),&length);
            HILOG_INFO(1,"%{public}s",buffer);}
        '''
        self.assert_candidate(source, message='HILOG_INFO')

    def test_custom_strlen_inside_visible_query_is_not_trusted_by_name(self):
        source = '''unsigned strlen(const char *value){HILOG_INFO(1,"%{public}s",value);return 7;}
        ''' + LENGTH_BODY + '''void Callback(const char *key){unsigned length=0;
            napi_get_value_string_utf8(0,key,nullptr,0,&length);}
        '''
        self.assert_candidate(source, message='HILOG_INFO')


if __name__ == '__main__':
    unittest.main()
