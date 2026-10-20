"""Independent T83 sensitive-flow/format operand controls; synthetic, not accuracy labels."""
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.models import SensitiveSourceModel
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector, formats
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource

MODEL = SensitiveSourceModel('fixture/t83', 'b' * 40,
    parameters=(('service.cpp', 'Callback', 0),), provenance='Explicit synthetic parameter source; no product claim')


class D84AdversarialTests(unittest.TestCase):
    def scan(self, body, parameter='const char *key'):
        data = ('void Callback(' + parameter + ') {' + body + '}').encode()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        units, ast, _ = index_sources((GitSource('service.cpp', 'cpp', blob, data),))
        context = ScanContext(ScanRequest('t83-flow', MODEL.repository, MODEL.commit,
            snapshot_digest(units), 'current-component:' + MODEL.repository), units, {'ast': ast})
        return SensitiveExposureDetector(MODEL).detect(context, units)

    def test_compound_assignment_preserves_lhs_or_rhs_dependencies(self):
        for body in (
            'unsigned value=key; value ^= 1;',
            'unsigned value=1; value ^= key;',
            'unsigned value=key; unsigned other=(value ^= 1); value=other;',
        ):
            with self.subTest(body=body):
                self.assertTrue(self.scan(body + 'HILOG_INFO(1,"%{public}u",value);',
                                          parameter='unsigned key').findings)

    def test_plain_assignment_kills_explicit_parameter_dependency(self):
        for body in ('unsigned value=key; value=7;',
                     'unsigned value=key; value ^= 1; value=7;',
                     'unsigned value=7; value ^= 1;'):
            with self.subTest(body=body):
                self.assertEqual((), self.scan(body + 'HILOG_INFO(1,"%{public}u",value);',
                                              parameter='unsigned key').findings)

    def test_private_slot_and_public_slot_do_not_mix(self):
        private = self.scan('HILOG_INFO(1,"%{private}s %{public}d",key,7);')
        self.assertTrue(private.findings)
        self.assertTrue(all(any(o.kind == 'sink_privacy' for o in f.evidence_obligations)
                            for f in private.findings))
        public = self.scan('HILOG_INFO(1,"%{private}d %{public}s",7,key);')
        self.assertTrue(public.findings)
        self.assertTrue(all(not any(o.kind == 'sink_privacy' for o in f.evidence_obligations)
                            for f in public.findings))

    def test_escaped_percent_star_width_and_precision_argument_binding(self):
        self.assertEqual(([('public', (0, 1, 2), 's'), ('private', (3,), 'u')], 4),
                         formats('%% %{public}*.*s %{private}u'))
        escaped = self.scan('HILOG_INFO(1,"%%{public}s %{public}s","public");')
        self.assertEqual((), escaped.findings)
        material = self.scan('HILOG_INFO(1,"%% %{public}*.*s",8,3,key);')
        self.assertTrue(material.findings)
        self.assertEqual((), self.scan('HILOG_INFO(1,"%{public}p",key);').findings)

    def test_unsupported_format_keeps_resolution_obligation(self):
        run = self.scan('HILOG_INFO(1,"%2$s",key);')
        self.assertTrue(run.findings)
        self.assertTrue(any(o.kind == 'format_resolution' for f in run.findings
                            for o in f.evidence_obligations))

    def test_explicit_string_c_str_keeps_receiver_dependency(self):
        for body in (
            'std::string value=key;',
            'const std::string value=key;',
            'std::string value{key};',
            'std::string value=key; value += "suffix";',
            'std::string value="prefix"; value += key;',
            'std::string value=key; std::string copy=value; value=copy;',
        ):
            with self.subTest(body=body):
                run = self.scan(body + 'HILOG_INFO(1,"%{public}s",value.c_str());')
                self.assertTrue(run.findings)
                self.assertTrue(any('std::string' in f.message for f in run.findings))

    def test_string_c_str_literal_overwrite_and_unrelated_receiver_controls(self):
        for body in (
            'std::string value="public";',
            'std::string value=key; value="public";',
            'std::string value=key; value += "suffix"; value="public";',
            'struct Fake { const char *c_str(){return "public";} }; Fake value;',
        ):
            with self.subTest(body=body):
                self.assertEqual((), self.scan(body + 'HILOG_INFO(1,"%{public}s",value.c_str());').findings)
        shadowed = ('struct Fake { const char *c_str(){return "public";} }; '
                    'std::string value=key; {Fake value; '
                    'HILOG_INFO(1,"%{public}s",value.c_str());}')
        self.assertEqual((), self.scan(shadowed).findings)

    def test_string_private_c_str_remains_conditional(self):
        run = self.scan('std::string value=key; HILOG_INFO(1,"%{private}s",value.c_str());')
        self.assertTrue(run.findings)
        self.assertTrue(all(any(o.kind == 'sink_privacy' for o in f.evidence_obligations)
                            for f in run.findings))


if __name__ == '__main__':
    unittest.main()
