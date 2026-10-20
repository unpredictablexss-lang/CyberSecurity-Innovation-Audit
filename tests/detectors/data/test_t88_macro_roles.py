"""T88 independent schema-key/material separation through logging macros."""
from dataclasses import replace
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

KEY = 'const std::string CERT_PASSWORD="password";\n'
READ = 'bool present=false; napi_has_named_property(env,obj,CERT_PASSWORD.c_str(),&present);'
HILOG_ONLY = r'''#ifndef TEST_CF_LOG_H
#define TEST_CF_LOG_H
#define CF_LOG_E(fmt, ...) \
HILOG_ERROR(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGE CF_LOG_E
#endif
'''


class T88MacroRoleTests(unittest.TestCase):
    def source(self, statement, prior=True):
        return ('#include "cf_log.h"\n' + KEY +
            'void sample(napi_env env,napi_value obj,const char *password){\n' +
            (READ + '\n' if prior else '') + statement + '\n}\n')

    def scan(self, source, header=HILOG_ONLY, partial=False, runner=False, header_path='cf_log.h', context_only=False):
        inputs = [('sample.cpp', source)]
        if header is not None:
            inputs.append((header_path, header))
        sources = []
        for path, text in inputs:
            data = text.encode()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            sources.append(GitSource(path, 'cpp', blob, data))
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted((replace(unit, parse_status='partial') if partial and unit.path == header_path
                              else unit for unit in units), key=lambda unit: unit.path))
        if partial:
            ast[header_path]['parse_status'] = 'partial'
        request = ScanRequest('t88-independent', 'fixture/t88', 'a' * 40, snapshot_digest(units),
                              'current-component:fixture/t88')
        ctx = ScanContext(request, units, {'ast': ast})
        if context_only:
            return ctx
        detector = SensitiveExposureDetector()
        if runner:
            registry = DetectorRegistry()
            registry.register(detector)
            reports, _ = run_all_with_coverage(ctx, registry)
            return reports[0].diagnostics
        return detector.detect(ctx, units).findings

    def at_statement(self, source, statement, **kwargs):
        line = source.splitlines().index(statement) + 1
        return tuple(finding for finding in self.scan(source, **kwargs)
                     if finding.file == 'sample.cpp' and finding.line == line)

    def test_bound_key_is_excluded_only_through_exact_visible_wrapper(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        source = self.source(statement)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertEqual((), self.at_statement(source, statement, runner=runner))

    def test_real_password_values_and_secret_format_remain_candidates(self):
        for statement in (
            'LOGE("value=%{public}s",password);',
            'LOGE("value=%{private}s",password);',
            'LOGE(password);',
        ):
            source = self.source(statement)
            for runner in (False, True):
                with self.subTest(statement=statement, runner=runner):
                    self.assertTrue(self.at_statement(source, statement, runner=runner))

    def test_mixed_key_and_actual_password_filters_only_the_key_operand(self):
        statement = 'LOGE("%{public}s %{public}s",CERT_PASSWORD.c_str(),password);'
        source = self.source(statement)
        for runner in (False, True):
            with self.subTest(runner=runner):
                findings = self.at_statement(source, statement, runner=runner)
                self.assertTrue(findings)
                self.assertTrue(any('identifier password' in finding.message for finding in findings))
                self.assertTrue(all('CERT_PASSWORD.c_str' not in finding.message for finding in findings))

    def test_format_percent_escapes_and_star_operands_bind_correctly(self):
        for statement in (
            'LOGE("%% %{public}*.*s",4,3,CERT_PASSWORD.c_str());',
            'LOGE("%{public}d %{public}s",7,CERT_PASSWORD.c_str());',
        ):
            with self.subTest(statement=statement):
                self.assertEqual((), self.at_statement(self.source(statement), statement))

    def test_unknown_or_mismatched_format_does_not_gain_key_proof(self):
        for statement in (
            'LOGE(password,CERT_PASSWORD.c_str());',
            'LOGE("%2$s",CERT_PASSWORD.c_str());',
            'LOGE("%{public}s %{public}s",CERT_PASSWORD.c_str());',
        ):
            with self.subTest(statement=statement):
                self.assertTrue(self.at_statement(self.source(statement), statement))

    def test_prior_read_proof_is_local_to_the_actual_function(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        without = self.source(statement, prior=False)
        self.assertTrue(self.at_statement(without, statement))
        elsewhere = ('#include "cf_log.h"\n' + KEY + 'void first(napi_env env,napi_value obj){' + READ + '}\n'
                     'void second(){\n' + statement + '\n}\n')
        self.assertTrue(self.at_statement(elsewhere, statement))

    def test_unknown_helper_missing_and_partial_headers_keep_candidate(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        source = self.source(statement)
        for kwargs in ({'header': None}, {'partial': True}):
            for runner in (False, True):
                with self.subTest(kwargs=kwargs, runner=runner):
                    self.assertTrue(self.at_statement(source, statement, runner=runner, **kwargs))
        unknown = 'UnknownLog("%{public}s",CERT_PASSWORD.c_str());'
        self.assertTrue(self.at_statement(self.source(unknown), unknown))

    def test_macro_changes_redefinition_and_unproved_alternate_are_not_trusted(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        source = self.source(statement)
        variants = (
            HILOG_ONLY.replace('#define LOGE CF_LOG_E', '#define LOGE UnknownLog'),
            HILOG_ONLY.replace('__FUNCTION__, __LINE__, ##__VA_ARGS__', 'password, __LINE__, ##__VA_ARGS__'),
            HILOG_ONLY + '\n#undef LOGE\n#define LOGE UnknownLog\n',
            '#ifdef HILOG_ENABLE\n' + HILOG_ONLY + '#else\n#define LOGE UnknownLog\n#endif\n',
        )
        for header in variants:
            with self.subTest(header=header):
                self.assertTrue(self.at_statement(source, statement, header=header))

    def test_redefined_implicit_function_metadata_cannot_hide_password(self):
        # The reviewed prefix contains a public %s for __FUNCTION__. A caller
        # macro can replace that implicit operand with the real password value.
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        source = '#define __FUNCTION__ password\n' + self.source(statement)
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.at_statement(source, statement, runner=runner))

    def test_redefined_line_metadata_cannot_hide_numeric_password(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        source = ('#define __LINE__ passwordCode\n' + self.source(statement)).replace(
            'const char *password)', 'const char *password,unsigned passwordCode)')
        for runner in (False, True):
            with self.subTest(runner=runner):
                self.assertTrue(self.at_statement(source, statement, runner=runner))

    def test_parameter_shadow_cannot_gain_schema_or_implicit_metadata_proof(self):
        statement = 'LOGE("get property %{public}s failed!",CERT_PASSWORD.c_str());'
        for parameter in ('const std::string &CERT_PASSWORD', 'const char *__FUNCTION__'):
            source = self.source(statement).replace('const char *password)', parameter + ')')
            for runner in (False, True):
                with self.subTest(parameter=parameter, runner=runner):
                    self.assertTrue(self.at_statement(source, statement, runner=runner))

    def test_local_value_shadow_after_prior_read_does_not_use_global_proof(self):
        statement = 'LOGE("%{public}s",CERT_PASSWORD.c_str());'
        source = ('#include "cf_log.h"\n' + KEY +
            'void sample(napi_env env,napi_value obj,const std::string &provided){\n' + READ + '\n'
            '{const std::string &CERT_PASSWORD=provided;\n' + statement + '\n}\n}\n')
        self.assertTrue(self.at_statement(source, statement))

    def test_same_name_local_log_body_is_analyzed(self):
        source = ('#include "cf_log.h"\n#undef LOGE\n' + KEY +
            'void LOGE(const char *fmt,const char *value){\nHILOG_INFO(1,"%{public}s",value);}\n'
            'void sample(napi_env env,napi_value obj,const char *password){\n' + READ + '\n'
            'LOGE("%{public}s",password);\n}\n')
        findings = self.scan(source)
        self.assertTrue(any(finding.rule_id == 'data.log.sensitive-value' for finding in findings))


if __name__ == '__main__':
    unittest.main()
