import os
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.run_graph_tool_experiments import execute, has_parse_errors, codeql_coverage_issues, joern_coverage_issues


class GraphExecutionTests(unittest.TestCase):
    def test_joern_requires_logged_file_and_cpg_coverage(self):
        metadata = {'steps': [{'stdout': '', 'stderr': '| 1 | src/a.cpp | 20 | yes | yes | 5 ms |'}]}
        self.assertEqual(joern_coverage_issues(metadata, ['src/a.cpp']), [])
        self.assertTrue(joern_coverage_issues(metadata, ['src/b.cpp']))
        metadata['steps'][0]['stderr'] += '\nFailed to parse method'
        self.assertTrue(joern_coverage_issues(metadata, ['src/a.cpp']))

    def test_successful_exit_does_not_prove_extraction_coverage(self):
        self.assertTrue(codeql_coverage_issues({'runs': []}, ['a.cpp']))
        payload = {'runs': [{'invocations': [{'toolExecutionNotifications': [
            {'descriptor': {'id': 'cpp/diagnostics/successfully-extracted-files'},
             'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'a.cpp'}}}]}]}]}]}
        self.assertEqual(codeql_coverage_issues(payload, ['a.cpp']), [])
        payload['runs'][0]['properties'] = {'metricResults': [
            {'ruleId': 'cpp/telemetry/failed-includes', 'value': 1, 'message': {'text': 'missing.h'}}]}
        self.assertIn('Missing include: missing.h', codeql_coverage_issues(payload, ['a.cpp']))

    def test_parser_problem_is_incomplete(self):
        self.assertTrue(has_parse_errors('WARN: Failed to parse syscall.c'))
        self.assertTrue(has_parse_errors('4 parse problems'))
        self.assertFalse(has_parse_errors('0 parse problems\n0 syntax errors'))
        self.assertFalse(has_parse_errors('Extraction finished'))

    @unittest.skipUnless(os.name == 'posix', 'runner executes in WSL')
    def test_timeout_retains_output_and_kills_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            result = execute([sys.executable, '-u', '-c',
                              'import time; print("started"); time.sleep(10)'],
                             Path(directory), os.environ.copy(), 0.1)
        self.assertTrue(result['timeout'])
        self.assertEqual(result['exit_code'], -1)
        self.assertIn('started', result['stdout'])

    @unittest.skipUnless(os.name == 'posix', 'runner executes in WSL')
    def test_failed_command_keeps_native_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            result = execute([sys.executable, '-c',
                              'import sys; print("extraction failed", file=sys.stderr); sys.exit(2)'],
                             Path(directory), os.environ.copy(), 2)
        self.assertEqual(result['exit_code'], 2)
        self.assertIn('extraction failed', result['stderr'])
