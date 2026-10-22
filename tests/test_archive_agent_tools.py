import copy
import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.ohscanner.git_source import load_git_sources
from src.workbench import agent, service
from src.workbench.agent_sources import FixedSourceReader
from src.workbench.settings import Settings


class ArchiveAgentToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'test')
        self.git('config', 'user.email', 'test@example.invalid')
        files = {'project/callee.c': 'int helper(int value) {\n return value + 1;\n}\n',
                 'project/caller.c': 'int helper(int value);\nint entry(void) {\n return helper(2);\n}\n',
                 'project/partial.c': 'int partial(void) {\n BROKEN ???;\n return other_function(1);\n}\n',
                 'project/header.h': '#define SOME_VALUE 3\n'}
        with tarfile.open(self.repo / 'sources.tgz', 'w:gz') as archive:
            for name, text in files.items():
                raw = text.encode()
                info = tarfile.TarInfo(name); info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        (self.repo / 'ordinary.c').write_text('int ordinary(void) { return 0; }\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixed source')
        commit = self.git('rev-parse', 'HEAD').strip()
        _, tree, sources, _ = load_git_sources(self.repo, commit, ('.',))
        self.report = {'repository': 'any/repository', 'commit': commit, 'git_tree': tree,
            '_workbench': {'source_inventory': [{'file': item.path, 'blob': item.oid,
                'sha256': hashlib.sha256(item.data).hexdigest(), **({'archive_binding': item.archive_binding} if item.archive_binding else {})} for item in sources]}}
        self.job = {'id': 'job', 'repository_id': 'repo', 'spec': {'commit': commit, 'git_tree': tree, 'include_paths': ['.']}}
        self.settings = Settings(self.root / 'data', (self.root,))
        class Store:
            def repository(inner, key): return {'id': 'repo', 'path': str(self.repo)}
        self.store = Store()
        self.reader = FixedSourceReader(self.settings, self.store, self.job, self.report)
        self.file = 'sources.tgz.members/project/callee.c'
        self.candidate = {'id': 'candidate', 'file': self.file, 'line': 2,
                          'source_sha256': self.reader.read(self.file)['sha256'], 'evidence': {'obligations': []}}

    def tearDown(self): self.tmp.cleanup()
    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL).decode()
    def tools(self):
        source = self.reader.read(self.candidate['file'])
        return agent._tool_specs(self.settings, self.store, self.job, self.report,
                                self.candidate, source, source['text'], (1, 3))

    def test_full_function_range_symbol_and_cross_file_caller_without_extraction(self):
        before = copy.deepcopy(self.report)
        tools = self.tools()
        function = tools['read_candidate_enclosing_function']({})
        self.assertEqual(function['status'], 'complete_function_context')
        self.assertEqual((function['function_start_line'], function['function_end_line']), (1, 3))
        self.assertIn('return value + 1', function['text'])
        ranged = tools['read_fixed_source_range']({'file': self.file, 'start_line': 2, 'line_count': 2})
        self.assertIn('2:  return', ranged['text'])
        lookup = tools['lookup_symbol_in_fixed_commit']({'symbol': 'helper'})
        self.assertEqual(len({item['file'] for item in lookup['matches']}), 2)
        traced = tools['trace_fixed_caller_sites']({'symbol': 'helper'})
        self.assertEqual(len(traced['matches']), 1)
        self.assertTrue(traced['matches'][0]['file'].endswith('caller.c'))
        calls = tools['find_callsite_candidates']({'identifier': 'helper'})
        self.assertEqual(calls['callsite_count'], 1)
        self.assertNotIn('archive_members_not_supported_by_this_tool', calls['truncation_reasons'])
        self.assertEqual(calls['callee_binding'], 'unknown')
        self.assertEqual(self.report, before)
        self.assertFalse((self.repo / 'project').exists())
        self.assertFalse((self.repo / 'sources.tgz.members').exists())

    def test_archive_is_loaded_once_per_reader(self):
        with patch('src.workbench.agent_sources.load_git_sources', wraps=load_git_sources) as load:
            reader = FixedSourceReader(self.settings, self.store, self.job, self.report)
            reader.read(self.file)
            reader.read('sources.tgz.members/project/caller.c')
            self.assertEqual(load.call_count, 1)

    def test_hash_binding_tree_mismatch_and_out_of_scope_paths_are_rejected(self):
        for mode in ('hash', 'archive_binding', 'tree'):
            report = copy.deepcopy(self.report)
            job = copy.deepcopy(self.job)
            entry = next(item for item in report['_workbench']['source_inventory'] if item['file'] == self.file)
            if mode == 'hash': entry['sha256'] = '0' * 64
            if mode == 'archive_binding': entry['archive_binding']['archive_sha256'] = '0' * 64
            if mode == 'tree': job['spec']['git_tree'] = '0' * 40
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                FixedSourceReader(self.settings, self.store, job, report).read(self.file)
        for path in ('../secret.c', '/etc/passwd', 'sources.tgz.members/project/unscanned.c'):
            with self.subTest(path=path), self.assertRaises(ValueError): self.reader.read(path)

    def test_dirty_archive_on_disk_does_not_replace_fixed_git_content(self):
        (self.repo / 'sources.tgz').write_bytes(b'corrupted working copy')
        reader = FixedSourceReader(self.settings, self.store, self.job, self.report)
        self.assertIn('return value + 1', reader.read(self.file)['text'])

    def test_member_ranges_are_valid_source_citations(self):
        result = self.tools()['read_fixed_source_range']({'file': self.file, 'start_line': 1, 'line_count': 3})
        lines = agent._source_evidence_lines('read_fixed_source_range', result)
        self.assertEqual(lines[self.file][2], ' return value + 1;')
        self.assertEqual(result['source_sha256'], self.candidate['source_sha256'])

    def test_partial_member_function_can_be_read_but_not_claimed_fully_parsed(self):
        self.candidate['file'] = 'sources.tgz.members/project/partial.c'
        self.candidate['line'] = 3
        tools = self.tools()
        result = tools['read_candidate_enclosing_function']({})
        self.assertEqual(result['status'], 'function_context_partial_parse')
        self.assertEqual(result['parse_status'], 'partial')
        self.assertEqual((result['function_start_line'], result['function_end_line']), (1, 4))
        self.assertIn('BROKEN ???', result['text'])
        self.assertTrue(result['text'].endswith('4: }'))
        traced = tools['trace_fixed_caller_sites']({'symbol': 'other_function'})
        self.assertEqual(len(traced['matches']), 1)
        self.assertEqual(traced['matches'][0]['parse_status'], 'partial')
        self.assertTrue(traced['truncated'])
        self.assertEqual(traced['dispatch_resolution'], 'unresolved')
    def test_header_location_is_not_invented_into_a_function(self):
        self.candidate['file'] = 'sources.tgz.members/project/header.h'
        self.candidate['line'] = 1
        result = self.tools()['read_candidate_enclosing_function']({})
        self.assertEqual(result['status'], 'no_unique_enclosing_function')
        self.assertEqual(result['text'], '')

    def test_ordinary_source_range_still_uses_fixed_inventory(self):
        with patch.object(service, 'read_report', return_value=self.report):
            result = self.tools()['read_fixed_source_range']({'file': 'ordinary.c', 'start_line': 1, 'line_count': 1})
        self.assertIn('ordinary', result['text'])

if __name__ == '__main__': unittest.main()