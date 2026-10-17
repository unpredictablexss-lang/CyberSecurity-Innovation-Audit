"""No implicit network. Supply the already-synced source Git store explicitly."""
import os
from pathlib import Path
import unittest

from research.experiments.ark_runtime.c2_20261017.replay import MANIFEST, pinned_context
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
import json


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'), 'Pinned Ark Git store not supplied; no implicit fetch')
class HistoricalPairTests(unittest.TestCase):
    def run_version(self, index):
        manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
        entry = manifest['sources'][index]
        ctx, _, _, _, _ = pinned_context(Path(os.environ['OHSCANNER_ARK_REPO']), entry['commit'], entry['source_sha256'])
        self.assertEqual(ctx.units[0].parse_status, 'partial')
        return analyze_unit(ctx.units[0], research_partial=True)

    def test_C01_pinned_before_has_origin_candidate(self):
        result = self.run_version(0)
        self.assertTrue(any(o.kind == 'candidate' for o in result.observations))
        self.assertEqual(result.file_outcome, 'partial')

    def test_C02_pinned_fix_has_no_rule_candidate(self):
        result = self.run_version(1)
        self.assertTrue(any(o.kind == 'matched' for o in result.observations))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))
        self.assertEqual(result.file_outcome, 'partial')


if __name__ == '__main__':
    unittest.main()
