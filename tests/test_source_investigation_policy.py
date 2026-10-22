"""Readable source is investigable across repositories; product facts stay pending."""
import copy
import json
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from src.workbench.api import create_app
from src.workbench.settings import Settings
import unittest
from unittest.mock import patch
from src.workbench import agent


class SourceInvestigationPolicyTests(unittest.TestCase):
    def test_all_repository_and_file_kinds_keep_original_human_obligations(self):
        for repo, file in [('openharmony/example', 'src/main.cpp'), ('libpng', 'libpng.tgz.members/libpng/png.h'), ('other/project', 'src/app.ts')]:
            with self.subTest(repository=repo):
                obligations = [{'kind': 'security_impact', 'status': 'unknown'}, {'kind': 'product_build_context', 'status': 'unknown'}]
                before = copy.deepcopy(obligations)
                result = agent._source_trace_obligations({'repository': repo}, {'file': file}, obligations, 'int main() {}')
                self.assertEqual(obligations, before)
                self.assertEqual(result[:2], before)
                self.assertEqual(result[-1]['kind'], 'source_trace_review')
                route = agent._candidate_evidence_routing({}, {}, result)
                self.assertEqual(route['agent_source_review_indices'], [2])
                self.assertEqual(route['human_or_runtime_review_indices'], [0, 1])
                self.assertEqual(route['validated_vulnerability'], 0)
                self.assertEqual(agent._source_trace_obligations({}, {}, result, 'int main() {}'), result)

    def test_batch_three_source_candidates_can_be_queued_without_closing_human_items(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = create_app(Settings(root / "data", (root,)))
            repo = app.state.store.add_repository("arbitrary/repository", str(root))
            job = {"id": "job-source", "repository_id": repo["id"], "status": "completed", "report_sha256": "b" * 64}
            report = {"repository": "arbitrary/repository", "commit": "c" * 40}
            ids = ["source-candidate-" + str(i) for i in range(3)]
            def finding(report, key):
                return {"id": key, "file": "archive.tgz.members/project/source.c", "line": 1,
                    "source_sha256": "a" * 64, "evidence": {"obligations": [{"kind": "impact", "status": "unknown"}]}}
            source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "void check() {}"}
            headers = {"x-ohscanner-client": "workbench-v1"}
            with TestClient(app) as client, patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "fake-test-key"}), patch.object(app.state.store, "job", return_value=job), patch.object(agent.service, "read_report", return_value=report), patch.object(agent.service, "finding", side_effect=finding), patch.object(agent.service, "source", return_value=source):
                for mode in ("tool_agent", "single_shot"):
                    payload = {"job_id": job["id"], "candidate_ids": ids, "mode": mode}
                    response = client.post("/api/v1/operations/agent-investigations/batch/preview", headers=headers, json=payload)
                    self.assertEqual(response.status_code, 200, response.text)
                    preview = response.json()
                    self.assertEqual(preview["blocked_candidate_ids"], [])
                    self.assertTrue(all(row["preview"]["agent_execution"]["eligible"] for row in preview["candidates"]))
                    queued = client.post("/api/v1/operations/agent-investigations/batch", headers=headers, json={**payload,
                        "source_submission_approved": True, "consent_sha256": preview["consent_sha256"], "consent_nonce": preview["consent_nonce"]})
                    self.assertEqual(queued.status_code, 201, queued.text)
                self.assertEqual(len(client.get("/api/v1/operations").json()), 6)

    def test_no_source_does_not_invent_source_evidence(self):
        for text in ['', '   \n']:
            self.assertEqual(agent._source_trace_obligations({}, {}, [], text), [])

    def test_empty_closed_or_unclassified_obligations_can_be_investigated(self):
        for items in [[], [{'kind': 'future_kind', 'status': 'unknown'}], [{'kind': 'bounds_proof', 'status': 'satisfied'}]]:
            result = agent._source_trace_obligations({}, {}, items, 'source text')
            self.assertEqual(result[:-1], items)
            self.assertEqual(result[-1]['status'], 'unknown')

    def test_existing_source_question_is_preserved(self):
        items = [{'kind': 'bounds_proof', 'status': 'unknown'}, {'kind': 'impact', 'status': 'unknown'}]
        self.assertEqual(agent._source_trace_obligations({}, {}, items, 'source text'), items)

    def test_missing_and_partial_tools_have_visible_specific_reasons(self):
        result = agent._source_tool_limitations([
            {'tool': 'read_fixed_source_range', 'status': 'rejected', 'result': {'error_code': 'fixed_evidence_unavailable', 'message': 'Requested file absent from the fixed scan inventory.'}},
            {'tool': 'trace_fixed_caller_sites', 'status': 'completed', 'result': {'status': 'partial', 'truncation_reasons': ['archive_members_not_supported', 'parse_incomplete']}},
        ])
        self.assertIn('Requested file absent', result[0])
        self.assertIn('archive_members_not_supported', result[1])
        self.assertIn('parse_incomplete', result[1])
        self.assertTrue(all('待验证' in item for item in result))

    def test_exploratory_source_review_never_becomes_automatic_confirmation(self):
        for status in ['confirmed', 'false_positive', 'needs_more_evidence', 'unknown']:
            before = {'status': status, 'product_status': 'unknown', 'confidence': 'high'}
            result = agent._exploratory_source_verdict(before)
            self.assertNotIn(result['status'], ['confirmed', 'false_positive'])
            self.assertEqual(before['status'], status)
            self.assertEqual(result['product_status'], 'unknown')

    def test_human_runtime_obligation_cannot_be_closed_with_source_quote(self):
        obligations = agent._source_trace_obligations({}, {}, [{'kind': 'security_impact', 'status': 'unknown'}], 'void check() {}')
        value = {'summary': 'Review', 'assessment': 'needs_more_evidence',
            'supported_claims': [], 'unsupported_claims': [], 'unknowns': ['Runtime not tested'], 'next_steps': ['Human review'],
            'obligation_reviews': [{'obligation_index': 0, 'disposition': 'evidence_found', 'citations': [{'evidence_id': 'ev-source', 'quote': 'void check() {}'}]}, {'obligation_index': 1, 'disposition': 'unresolved', 'citations': []}]}
        with self.assertRaises(ValueError):
            agent._validate_final(json.dumps(value), {'ev-source': ['void check() {}']}, obligations, source_review_indices=[1])

if __name__ == '__main__':
    unittest.main()