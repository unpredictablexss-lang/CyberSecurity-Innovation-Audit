"""D87 precise global property-key binding; hard-coded material stays unknown."""
from dataclasses import replace
import hashlib
import unittest
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector

KEY = 'const std::string CERT_PASSWORD="password"; '
HAS = 'bool result=false; napi_has_named_property(env,obj,CERT_PASSWORD.c_str(),&result);'


def context(sources, partial=()):
    values = []
    for path, text in sources:
        data = text.encode()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        values.append(GitSource(path, 'cpp', blob, data))
    units, ast, _ = index_sources(tuple(values))
    units = tuple(sorted((replace(u, parse_status='partial') if u.path in partial else u for u in units),
                         key=lambda u: u.path))
    for path in partial:
        ast[path]['parse_status'] = 'partial'
    request = ScanRequest('d87-controls', 'fixture/d87', 'f' * 40,
                          snapshot_digest(units), 'current-component:fixture/d87')
    return ScanContext(request, units, {'ast': ast})


def analyze(text, **kwargs):
    ctx = context((('service.cpp', text),), **kwargs)
    return SensitiveExposureDetector().detect(ctx, ctx.units)


class D87PropertyRoleTests(unittest.TestCase):
    def test_global_const_schema_key_is_excluded_only_in_reviewed_key_position(self):
        run = analyze(KEY + 'void f(){' + HAS + '}')
        self.assertEqual(len(run.findings), 0)
        self.assertEqual(run.status, 'blocked')
        self.assertIn('bound constant service.cpp', ' '.join(run.limitations))

    def test_unknown_wrappers_and_real_material_are_retained(self):
        for call in (
                'UnknownWrapper(CERT_PASSWORD.c_str());',
                'LOGE("key=%{public}s",CERT_PASSWORD.c_str());',
                'napi_set_named_property(env,obj,"value",CERT_PASSWORD.c_str());',
                'napi_has_named_property(env,obj,password,&result);'):
            with self.subTest(call=call):
                run = analyze(KEY + 'void f(const char *password){ bool result=false; ' + call + '}')
                self.assertGreaterEqual(len(run.findings), 1)

    def test_literal_initializer_is_not_sufficient_to_remove_material(self):
        for definition in (
                'const std::string CERT_PASSWORD="actual-hardcoded-secret"; ',
                'std::string CERT_PASSWORD="password"; ',
                'const std::string CERT_PASSWORD=GetOpaqueValue(); '):
            with self.subTest(definition=definition):
                self.assertEqual(len(analyze(definition + 'void f(){' + HAS + '}').findings), 1)

    def test_get_retains_output_operand_and_propagates_actual_property_result(self):
        run = analyze(KEY + 'void f(){ napi_value password=nullptr; '
                      'napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&password); }')
        self.assertEqual(len(run.findings), 1)
        self.assertIn('identifier password', run.findings[0].message)
        self.assertNotIn('CERT_PASSWORD.c_str', run.findings[0].message)
        run = analyze(KEY + 'void f(){ napi_value out=nullptr; '
                      'napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),&out);\n'
                      'Consume(out); }')
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].line, 2)
        self.assertIn('password-property output argument 3', run.findings[0].message)

    def test_return_status_does_not_inherit_schema_name(self):
        run = analyze(KEY + 'void f(){ bool result=false; int ret='
                      'napi_has_named_property(env,obj,CERT_PASSWORD.c_str(),&result); '
                      'HILOG_INFO(1,"%{public}d",ret); }')
        self.assertEqual(len(run.findings), 0)

    def test_parameter_or_local_shadow_retains_candidate(self):
        for prefix, body in (
                ('const std::string &CERT_PASSWORD', HAS),
                ('std::string &&CERT_PASSWORD', HAS),
                ('const std::string &input', 'const std::string &CERT_PASSWORD=input; ' + HAS),
                ('', 'std::string CERT_PASSWORD=GetOpaqueValue(); ' + HAS)):
            with self.subTest(prefix=prefix):
                run = analyze(KEY + 'void f(' + prefix + '){' + body + '}')
                self.assertEqual(len(run.findings), 1)

    def test_explicit_unique_header_with_same_namespace_can_bind(self):
        header = '#ifndef KEYS_H\n#define KEYS_H\nnamespace A {' + KEY + '}\n#endif\n'
        source = '#include "keys.h"\nnamespace A {void f(){' + HAS + '}}'
        ctx = context((('inc/keys.h', header), ('service.cpp', source)))
        run = SensitiveExposureDetector().detect(ctx, ctx.units)
        self.assertEqual(len(run.findings), 0)
        self.assertIn('bound constant inc/keys.h', ' '.join(run.limitations))

    def test_missing_ambiguous_or_partial_header_does_not_bind(self):
        header = 'namespace A {' + KEY + '}'
        for source, extra, partial in (
                ('namespace A {void f(){' + HAS + '}}', (), ()),
                ('#include "keys.h"\nnamespace A {void f(){' + HAS + '}}',
                 (('other/keys.h', header),), ()),
                ('#include "keys.h"\nnamespace A {void f(){' + HAS + '}}', (), ('inc/keys.h',))):
            with self.subTest(source=source, partial=partial, extra=extra):
                ctx = context((('inc/keys.h', header), ('service.cpp', source)) + extra, partial=partial)
                run = SensitiveExposureDetector().detect(ctx, ctx.units)
                self.assertEqual(len(run.findings), 1)

    def test_namespace_collision_and_conditional_global_definition_do_not_bind(self):
        source = 'namespace A {' + KEY + '} namespace B {std::string CERT_PASSWORD=GetOpaqueValue(); '
        self.assertEqual(len(analyze(source + 'void f(){' + HAS + '}}').findings), 1)
        source = KEY + '\n#if OTHER_BUILD\nstd::string CERT_PASSWORD=GetOpaqueValue();\n#endif\n'
        self.assertEqual(len(analyze(source + 'void f(){' + HAS + '}').findings), 1)

    def test_same_name_api_body_or_macro_is_not_credited(self):
        source = ('void napi_has_named_property(int env,int obj,const char *value,bool *out){'
                  'HILOG_INFO(1,"%{public}s",value); } ' + KEY + 'void f(){' + HAS + '}')
        self.assertGreaterEqual(len(analyze(source).findings), 1)
        for macro in ('#define napi_has_named_property(a,b,c,d) UnknownWrapper(c)',
                      '#define string CustomString', '#define c_str SecretAccessor'):
            with self.subTest(macro=macro):
                source = macro + '\n' + KEY
                self.assertGreaterEqual(len(analyze(source + 'void f(){' + HAS + '}').findings), 1)

    def test_partial_caller_and_unknown_output_destination_remain_candidates(self):
        self.assertEqual(len(analyze(KEY + 'void f(){' + HAS + '}', partial=('service.cpp',)).findings), 1)
        run = analyze(KEY + 'void f(napi_value *out){ '
                      'napi_get_named_property(env,obj,CERT_PASSWORD.c_str(),out); }')
        self.assertEqual(len(run.findings), 1)
        self.assertTrue(any(o.kind == 'destination_binding' for o in run.findings[0].evidence_obligations))


if __name__ == '__main__':
    unittest.main()
