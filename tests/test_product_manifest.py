import tempfile
import unittest
import os
import sys
from pathlib import Path

from src.benchmark.product_manifest import read_manifest, select_projects, bind_resolution
from scripts.probe_product_configuration import missing_prebuilt_gate, isolated_command
from scripts.run_graph_tool_experiments import execute


class ProductManifestTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'private mount test requires Linux root')
    def test_private_namespace_prevents_writes_and_preserves_host_file(self):
        with tempfile.TemporaryDirectory(prefix='product probe ') as directory:
            root = Path(directory)
            file = root / 'sentinel.txt'
            file.write_text('original')
            command = isolated_command([sys.executable, '-c',
                'import sys; from pathlib import Path; Path(sys.argv[1]).write_text("changed")', str(file)], [str(root)])
            result = execute(command, root, os.environ.copy(), 10)
            if 'Operation not permitted' in result['stderr'] and 'unshare' in result['stderr']:
                self.skipTest('Private mount namespace unavailable')
            self.assertNotEqual(result['exit_code'], 0)
            self.assertIn('Read-only file system', result['stderr'])
            self.assertEqual(file.read_text(), 'original')

    def test_missing_tools_are_blocked_and_other_failures_are_not_misclassified(self):
        self.assertTrue(missing_prebuilt_gate(dict(exit_code=1, stdout='Node.js version mismatch. Expected 14.21.1', stderr='')))
        self.assertFalse(missing_prebuilt_gate(dict(exit_code=0, stdout='Node.js version mismatch. Expected 14.21.1', stderr='')))
        self.assertFalse(missing_prebuilt_gate(dict(exit_code=1, stdout='', stderr='Unknown target')))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, file, text):
        path = self.root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_includes_defaults_and_root_links_are_recorded(self):
        self.write('default.xml', '<manifest><remote name="official" fetch="https://example.com/oh"/>'
                   '<default remote="official" revision="master"/><include name="parts/base.xml"/></manifest>')
        self.write('parts/base.xml', '<manifest><project name="build" path="build">'
                   '<linkfile src="build_scripts/build.sh" dest="build.sh"/></project></manifest>')
        result = read_manifest(self.root)
        project = select_projects(result, ['build'])[0]
        self.assertEqual(project['fetch_url'], 'https://example.com/oh/build.git')
        self.assertEqual(project['file_operations'][0]['dest'], 'build.sh')
        self.assertEqual(len(result['documents']), 2)

    def test_include_cycle_and_traversal_are_rejected(self):
        for name in ('default.xml', '../outside.xml'):
            self.write('default.xml', '<manifest><include name="' + name + '"/></manifest>')
            with self.assertRaises(ValueError):
                read_manifest(self.root)

    def test_xml_entity_declaration_is_rejected(self):
        self.write('default.xml', '<!DOCTYPE manifest [<!ENTITY x "value">]><manifest/>')
        with self.assertRaisesRegex(ValueError, 'entity declarations'):
            read_manifest(self.root)

    def test_duplicate_paths_and_unsupported_extension_are_rejected(self):
        for children in ('<project name="a" path="same"/><project name="b" path="same"/>',
                         '<extend-project name="a" revision="other"/>'):
            self.write('default.xml', '<manifest>' + children + '</manifest>')
            with self.assertRaises(ValueError):
                read_manifest(self.root)

    def test_mirror_sha_cannot_be_claimed_as_official_resolution(self):
        project = dict(fetch_url='https://gitcode.com/openharmony/build.git', revision='master')
        resolution = dict(fetch_url='https://github.com/openharmony/build.git', revision='master',
                          resolved_ref='refs/heads/master', commit='a' * 40)
        with self.assertRaisesRegex(ValueError, 'different manifest remote'):
            bind_resolution(project, resolution)
        resolution['fetch_url'] = project['fetch_url']
        self.assertEqual(bind_resolution(project, resolution)['resolved_commit'], 'a' * 40)

    def test_revision_and_ref_mismatch_are_rejected(self):
        project = dict(fetch_url='https://example.com/build.git', revision='master')
        for ref, revision in (('HEAD', 'master'), ('refs/heads/release', 'release')):
            with self.assertRaises(ValueError):
                bind_resolution(project, dict(fetch_url=project['fetch_url'], revision=revision,
                                               resolved_ref=ref, commit='a' * 40))
