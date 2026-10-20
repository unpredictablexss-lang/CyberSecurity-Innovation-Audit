"""T91 independent private-key schema operand versus returned material controls."""
import unittest
from tests.detectors.data import test_t88_macro_roles as t88

KEY = 'const std::string CERT_PRIVATE_KEY="key";\n'
GET = 'napi_get_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&output);'
HAS = 'napi_has_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),&present);'


class T91PrivateKeyRoleTests(unittest.TestCase):
    def source(self, statement, parameters='napi_env env,napi_value obj'):
        return '#include "schema.h"\nvoid sample(' + parameters + '){\n' + statement + '\n}\n'

    def scan(self, source, header=KEY, partial=False, runner=False, **kwargs):
        return t88.T88MacroRoleTests().scan(source, header=header, partial=partial,
            runner=runner, header_path='schema.h', **kwargs)

    def at(self, source, statement, **kwargs):
        line = source.splitlines().index(statement) + 1
        return tuple(item for item in self.scan(source, **kwargs) if item.file == 'sample.cpp' and item.line == line)

    def test_only_exact_schema_get_operand_is_excluded(self):
        source = self.source('napi_value output=nullptr;\n' + GET)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual((), self.at(source, GET, runner=runner))

    def test_has_key_does_not_generate_material_in_boolean_flag(self):
        source = self.source('bool present=false;\n' + HAS + '\nHILOG_INFO(1,"%{public}d",present);')
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual((), tuple(self.scan(source, runner=runner)))

    def test_get_output_with_neutral_name_becomes_material(self):
        consume = 'Consume(output);'
        source = self.source('napi_value output=nullptr;\n' + GET + '\n' + consume)
        for runner in (False, True):
            with self.subTest(runner=runner):
                items = self.at(source, consume, runner=runner)
                self.assertTrue(items)
                self.assertTrue(any('private-key-property output argument 3' in item.message for item in items))
                self.assertTrue(all('password-property' not in item.message for item in items))

    def test_actual_string_byte_getter_still_consumes_key_output(self):
        getter = 'napi_get_value_string_utf8(env,output,buffer,sizeof(buffer),&length);'
        source = self.source('napi_value output=nullptr;char buffer[32];size_t length=0;\n' + GET + '\n' + getter)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.at(source, getter, runner=runner))

    def test_unresolved_destination_is_not_silently_dropped(self):
        get = 'napi_get_named_property(env,obj,CERT_PRIVATE_KEY.c_str(),GetDestination());'
        source = self.source(get)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.at(source, get, runner=runner))

    def test_parameters_references_and_local_values_shadow_global(self):
        for parameter in ('const std::string &CERT_PRIVATE_KEY', 'std::string &&CERT_PRIVATE_KEY'):
            source = self.source('napi_value output=nullptr;\n' + GET,
                'napi_env env,napi_value obj,' + parameter)
            for runner in (False, True):
                with self.subTest(parameter=parameter, runner=runner):
                    self.assertTrue(self.at(source, GET, runner=runner))
        source = self.source('std::string CERT_PRIVATE_KEY=GetSecret();napi_value output=nullptr;\n' + GET)
        self.assertTrue(self.at(source, GET))

    def test_mutable_dynamic_wrong_literal_or_wrong_name_are_not_approved(self):
        for header in ('std::string CERT_PRIVATE_KEY="key";\n',
                       'const std::string CERT_PRIVATE_KEY=GetSecret();\n',
                       'const std::string CERT_PRIVATE_KEY="actual private key";\n',
                       'const std::string OTHER_PRIVATE_KEY="key";\n'):
            get = GET.replace('CERT_PRIVATE_KEY', 'OTHER_PRIVATE_KEY') if 'OTHER_PRIVATE_KEY' in header else GET
            source = self.source('napi_value output=nullptr;\n' + get)
            for runner in (False, True):
                with self.subTest(header=header, runner=runner):
                    self.assertTrue(self.at(source, get, header=header, runner=runner))

    def test_wrong_operand_and_unknown_wrapper_keep_candidates(self):
        for call in ('napi_get_named_property(env,obj,"other",&privateKey);',
                     'ReadWrapper(env,obj,CERT_PRIVATE_KEY.c_str(),&output);'):
            source = self.source('napi_value output=nullptr; napi_value privateKey=nullptr;\n' + call)
            for runner in (False, True):
                with self.subTest(call=call, runner=runner):
                    self.assertTrue(self.at(source, call, runner=runner))

    def test_missing_partial_or_ambiguous_header_does_not_prove_schema(self):
        source = self.source('napi_value output=nullptr;\n' + GET)
        for kwargs in ({'header': None}, {'partial': True}):
            for runner in (False, True):
                with self.subTest(kwargs=kwargs, runner=runner):
                    self.assertTrue(self.at(source, GET, runner=runner, **kwargs))
        self.assertTrue(self.at(source, GET, header=KEY + KEY))

    def test_api_or_symbol_macro_override_cannot_gain_schema_proof(self):
        for macro in ('#define napi_get_named_property LeakPrivateKey\n',
                      '#define CERT_PRIVATE_KEY OTHER_PRIVATE_KEY\n'):
            source = macro + self.source('napi_value output=nullptr;\n' + GET)
            for runner in (False, True):
                with self.subTest(macro=macro, runner=runner):
                    self.assertTrue(self.at(source, GET, runner=runner))

    def test_same_name_custom_body_or_callback_is_not_reviewed_api(self):
        body = 'int napi_get_named_property(napi_env env,napi_value obj,const char *text,napi_value *out){\nHILOG_INFO(1,"%{public}s",text);return 0;\n}\n'
        source = body + self.source('napi_value output=nullptr;\n' + GET)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.scan(source, runner=runner))
        source = self.source('napi_value output=nullptr;\n' + GET,
            'napi_env env,napi_value obj,int(*napi_get_named_property)(napi_env,napi_value,const char*,napi_value*)')
        self.assertTrue(self.at(source, GET))

    def test_new_key_role_does_not_automatically_enable_log_exclusion(self):
        log = 'LOGE("%{public}s",CERT_PRIVATE_KEY.c_str());'
        source = '#include "schema.h"\n' + KEY + 'void sample(napi_env env,napi_value obj){\nnapi_value output=nullptr;\n' + GET + '\n' + log + '\n}\n'
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.at(source, log, header=t88.HILOG_ONLY, runner=runner))


if __name__ == '__main__':
    unittest.main()
