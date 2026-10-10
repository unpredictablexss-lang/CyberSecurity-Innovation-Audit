import unittest

from scripts.run_component_clang_host import host_sources
from src.benchmark.component import validate_component_report as validate_report


class ComponentHostTests(unittest.TestCase):
    def test_host_sources_exclude_conditional_device_additions(self):
        gn = 'sources_utils = ["src/a.cpp", "src/b.cpp"]\nif (!is_host_product) { sources_utils += ["src/ashmem.cpp"] }'
        self.assertEqual(host_sources(gn), ['base/src/a.cpp', 'base/src/b.cpp'])

    def test_unsupported_gn_sources_are_rejected(self):
        for gn in ('nothing', 'sources_utils = ["../outside.cpp"]',
                   'sources_utils = ["src/a.cpp", "src/a.cpp"]'):
            with self.assertRaises(ValueError):
                host_sources(gn)

    def test_review_rejects_different_version_and_historical_target(self):
        manifest = dict(repository='openharmony/commonlibrary_c_utils', commit='a' * 40)
        target = 'current-component:openharmony/commonlibrary_c_utils'
        validate_report(dict(target_id=target, commit='a' * 40), manifest)
        validate_report(dict(target_id=target + ':utilsbase-linux-host-bootstrap', commit='a' * 40), manifest)
        for report in (dict(target_id='c_utils-singleton-uaf-2026-01', commit='a' * 40),
                       dict(target_id=target, commit='b' * 40)):
            with self.assertRaises(ValueError):
                validate_report(report, manifest)
