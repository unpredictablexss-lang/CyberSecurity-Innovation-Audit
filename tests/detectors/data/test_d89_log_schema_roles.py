"""D89 schema identity plus bounded macro/format argument roles."""
import unittest
from unittest.mock import patch
import hashlib
from tests.detectors.data.test_d87_property_roles import context, KEY, HAS
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

TARGET = ('#define CF_LOG_E(fmt, ...) HILOG_ERROR(LOG_CORE, '
          '"%{public}s[%{public}u]: " fmt "\\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)\n')
ALIAS = '#define LOGE CF_LOG_E\n'
HEADER = TARGET + ALIAS
LOG = 'LOGE("key=%{public}s",CERT_PASSWORD.c_str());'


def analyze(body, header=HEADER, partial=(), extra=()):
    source = '#include "logger.h"\n' + KEY + body
    ctx = context((('logger.h', header), ('service.cpp', source)) + extra, partial=partial)
    return SensitiveExposureDetector().detect(ctx, ctx.units)


class D89LogSchemaRoleTests(unittest.TestCase):
    def test_prior_same_function_schema_role_is_required(self):
        self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}').findings), 0)
        self.assertEqual(len(analyze('void f(){' + LOG + '}').findings), 1)
        self.assertEqual(len(analyze('void a(){' + HAS + '} void b(){' + LOG + '}').findings), 1)

    def test_same_line_different_constant_does_not_borrow_schema_identity(self):
        run = analyze('const std::string SECOND_PASSWORD="password"; '
                      'void f(){' + HAS + 'LOGE("%{public}s",SECOND_PASSWORD.c_str());}')
        self.assertEqual(len(run.findings), 1)
        self.assertIn('SECOND_PASSWORD', run.findings[0].message)

    def test_real_and_mixed_material_operands_are_not_excluded(self):
        for call in ('LOGE("%{public}s",password);',
                     'LOGE("%{public}s %{public}s",CERT_PASSWORD.c_str(),password);',
                     'LOGE(password,CERT_PASSWORD.c_str());',
                     'LOGE("%{private}s",password);'):
            with self.subTest(call=call):
                run = analyze('void f(const char *password){' + HAS + call + '}')
                self.assertEqual(len(run.findings), 1)
                self.assertIn('password', run.findings[0].message)

    def test_format_value_slot_handles_stars_and_escaped_percent(self):
        run = analyze('void f(){' + HAS +
                      'LOGE("%% %{public}*.*s",7,3,CERT_PASSWORD.c_str());}')
        self.assertEqual(len(run.findings), 0)
        for fmt in ('%%', '%{public}u', '%{public}s %{public}s'):
            with self.subTest(fmt=fmt):
                run = analyze('void f(){' + HAS + 'LOGE("' + fmt + '",CERT_PASSWORD.c_str());}')
                self.assertEqual(len(run.findings), 1)

    def test_partial_missing_and_ambiguous_macro_headers_are_unknown(self):
        body = 'void f(){' + HAS + '\n' + LOG + '}'
        self.assertEqual(len(analyze(body, partial=('logger.h',)).findings), 2)
        ctx = context((('service.cpp', KEY + 'void f(){' + HAS + LOG + '}'),))
        self.assertEqual(len(SensitiveExposureDetector().detect(ctx, ctx.units).findings), 1)
        self.assertEqual(len(analyze(body,
                                    extra=(('other/logger.h', HEADER),)).findings), 2)

    def test_redefinition_undef_and_wrong_terminal_roles_are_unknown(self):
        headers = (
            HEADER + '#define LOGE UnknownWrapper\n',
            HEADER + '#undef LOGE\n#define LOGE CF_LOG_E\n',
            HEADER + TARGET,
            '#define CF_LOG_E(fmt, ...) UnknownWrapper(fmt, ##__VA_ARGS__)\n' + ALIAS,
            TARGET.replace('__FUNCTION__, __LINE__, ', '') + ALIAS,
            TARGET.replace('##__VA_ARGS__)', '##__VA_ARGS__, __VA_ARGS__)') + ALIAS,
            HEADER + '#define HILOG_ERROR UnknownWrapper\n',
        )
        for header in headers:
            with self.subTest(header=header):
                self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}', header=header).findings), 1)

    def test_every_conditional_macro_branch_must_have_same_format_role(self):
        good = '#ifdef ENABLE\n' + TARGET + '#else\n' + TARGET + '#endif\n' + ALIAS
        self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}', header=good).findings), 0)
        bad = good.replace(TARGET, '#define CF_LOG_E(fmt, ...) UnknownWrapper(fmt, ##__VA_ARGS__)\n', 1)
        self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}', header=bad).findings), 1)
        missing_else = '#ifdef ENABLE\n' + TARGET + '#endif\n' + ALIAS
        self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}', header=missing_else).findings), 1)

    def test_arbitrary_fallback_name_or_visible_leaf_body_is_not_trusted(self):
        fallback = ('#define CF_LOG_E(fmt, ...) CfPrintLog("ERROR", __FILE__, __LINE__, '
                    '__FUNCTION__, fmt, ##__VA_ARGS__)\n' + ALIAS)
        self.assertEqual(len(analyze('void f(){' + HAS + LOG + '}', header=fallback).findings), 1)
        fake_leaf = 'void HILOG_ERROR(int tag,const char *fmt,...){UnknownWrapper(fmt);} '
        self.assertGreaterEqual(len(analyze(fake_leaf + 'void f(){' + HAS + LOG + '}').findings), 1)

    def test_unknown_wrapper_and_same_named_local_body_remain_candidates(self):
        self.assertEqual(len(analyze('void f(){' + HAS + 'UnknownWrapper(CERT_PASSWORD.c_str());}').findings), 1)
        source = (KEY + 'void LOGE(const char *fmt,const char *value){UnknownWrapper(value);} '
                  'void f(){' + HAS + LOG + '}')
        ctx = context((('service.cpp', source),))
        self.assertGreaterEqual(len(SensitiveExposureDetector().detect(ctx, ctx.units).findings), 1)

    def test_implicit_metadata_overrides_and_call_site_aliases_preserve_unknown(self):
        for token in ('__FUNCTION__', '__FILE__', '__LINE__', 'LOG_CORE'):
            with self.subTest(token=token):
                header = '#define ' + token + ' password\n' + HEADER
                run = analyze('void f(const char *password){' + HAS + LOG + '}', header=header)
                self.assertEqual(len(run.findings), 1)
                self.assertIn('metadata', ' '.join(run.limitations))
        run = analyze('void f(void *CfPrintLog){' + HAS + LOG + '}')
        self.assertEqual(len(run.findings), 1)

    def test_runner_and_reviewed_fallback_reject_caller_metadata_override(self):
        # Synthetic reviewed-body identity for this control only. The production
        # profile remains pinned to the original certificate header's SHA.
        fallback = ('static void CfPrintLog(const char *level,const char *file,int line,'
                    'const char *func,const char *fmt,...){va_list args;va_start(args,fmt);'
                    'vfprintf(stderr,fmt,args);va_end(args);}\n'
                    '#define CF_LOG_E(fmt, ...) CfPrintLog("ERROR", __FILE__, __LINE__, '
                    '__FUNCTION__, fmt, ##__VA_ARGS__)\n' + ALIAS)
        with patch('src.ohscanner.detectors.data.log_macro_roles.CERT_LOG_PATH', 'logger.h'), \
                patch('src.ohscanner.detectors.data.log_macro_roles.CERT_LOG_SHA256', hashlib.sha256(fallback.encode()).hexdigest()):
            for header in (HEADER, fallback):
                for override, expected in (('', 0), ('#define __FUNCTION__ password\n', 1),
                                           ('#undef __FILE__\n#define __FILE__ password\n', 1)):
                    with self.subTest(header=header, override=override):
                        source = override + '#include "logger.h"\n' + KEY + 'void f(const char *password){' + HAS + LOG + '}'
                        ctx = context((('logger.h', header), ('service.cpp', source)))
                        direct = SensitiveExposureDetector().detect(ctx, ctx.units)
                        registry = DetectorRegistry();registry.register(SensitiveExposureDetector())
                        reports, _ = run_all_with_coverage(ctx, registry)
                        self.assertEqual(len(direct.findings), expected)
                        self.assertEqual(len(reports[0].diagnostics), expected)

    def test_selected_transitive_header_metadata_override_is_not_ignored(self):
        run = analyze('void f(const char *password){' + HAS + LOG + '}',
                      header='#include "extra.h"\n' + HEADER,
                      extra=(('extra.h', '#define __FUNCTION__ password\n'),))
        self.assertEqual(len(run.findings), 1)


if __name__ == '__main__':
    unittest.main()
