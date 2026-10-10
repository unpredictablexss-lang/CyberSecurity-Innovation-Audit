import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.component import git_oid, tree_oid, verify_snapshot, file_group
from src.benchmark.historical import load_sample
from src.benchmark.report_inputs import load_report_runs
from src.benchmark.tool_result import ToolRunResult


class ComponentSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.records = []
        for file in ('base/src/a.cpp', 'base/test/unit.cpp', 'README.md'):
            data = b'int safe() { return 0; }\n'
            target = self.root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.records.append(dict(path=file, mode='100644', blob=git_oid('blob', data),
                                     sha256=hashlib.sha256(data).hexdigest(),
                                     language_scope='other' if file.endswith('.md') else 'cpp'))
        tree = tree_oid(self.records)
        commit = ('tree ' + tree + '\nauthor Tester <t@example.com> 0 +0000\n'
                  'committer Tester <t@example.com> 0 +0000\n\nfixture\n').encode()
        self.manifest = dict(experiment_kind='current_component', files=self.records,
                             repository='openharmony/commonlibrary_c_utils',
                             tree=tree, commit=git_oid('commit', commit),
                             commit_object_b64=base64.b64encode(commit).decode())

    def test_valid_snapshot_and_test_group(self):
        verify_snapshot(self.manifest, self.root)
        self.assertEqual(file_group('base/test/unit.cpp'), 'tests')
        self.assertEqual(file_group('base/src/a.cpp'), 'production')

    def test_working_copy_drift_is_rejected(self):
        (self.root / 'base/src/a.cpp').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'content changed'):
            verify_snapshot(self.manifest, self.root)

    def test_commit_relabeling_is_rejected(self):
        self.manifest['commit'] = 'a' * 40
        with self.assertRaisesRegex(ValueError, 'Commit object'):
            verify_snapshot(self.manifest, self.root)

    def test_repository_mixing_is_rejected(self):
        self.manifest['repository'] = 'openharmony/kernel_liteos_a'
        with self.assertRaisesRegex(ValueError, 'repository binding'):
            verify_snapshot(self.manifest, self.root)

    def test_extra_file_is_not_silently_scanned(self):
        (self.root / 'extra.cpp').write_text('int extra;')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            verify_snapshot(self.manifest, self.root)

    def test_omitted_tracked_file_is_rejected(self):
        self.manifest['files'] = self.records[:-1]
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            verify_snapshot(self.manifest, self.root)

    def test_cpp_scope_cannot_be_relabelled_as_other(self):
        self.records[0]['language_scope'] = 'other'
        with self.assertRaisesRegex(ValueError, 'language scope'):
            verify_snapshot(self.manifest, self.root)

    def test_historical_input_is_rejected(self):
        self.manifest['experiment_kind'] = 'historical'
        with self.assertRaisesRegex(ValueError, 'historical inputs are separate'):
            verify_snapshot(self.manifest, self.root)

    def test_current_component_report_cannot_enter_historical_matrix(self):
        project = Path(__file__).resolve().parents[1]
        sample = load_sample(project / 'benchmarks/historical/c_utils_singleton_uaf.json')
        result = ToolRunResult(schema_version=1, run_id='current-run', tool='own_text', tool_version='text-v1',
                               target_id='current-component:openharmony/commonlibrary_c_utils',
                               commit=sample.vulnerable_commit, scope_files=1, scope_loc=1,
                               status='completed', elapsed_seconds=0)
        (self.root / 'report.json').write_text(json.dumps(result.to_dict()))
        manifest = dict(schema_version=1, runs=[dict(sample_id=sample.sample_id, revision='vulnerable',
                        report='report.json', analyzed_files=sample.affected_files)])
        path = self.root / 'inputs.json'
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'target_id'):
            load_report_runs(path, [sample])

    def test_tree_binds_paths_and_modes(self):
        altered = copy.deepcopy(self.records)
        altered[0]['mode'] = '100755'
        self.assertNotEqual(tree_oid(altered), self.manifest['tree'])

    def test_traversal_is_rejected(self):
        self.records[0]['path'] = '../escape.cpp'
        with self.assertRaisesRegex(ValueError, 'Unsafe snapshot path'):
            verify_snapshot(self.manifest, self.root)
