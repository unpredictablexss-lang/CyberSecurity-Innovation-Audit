import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.workbench import agent
from src.workbench.agent_knowledge import PACKAGE_RELATIVE, retrieve_knowledge, tokenize


class AgentKnowledgeRetrievalTests(unittest.TestCase):
    def test_bm25_matches_cve_cwe_component_and_chinese_and_bounds_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / PACKAGE_RELATIVE
            cve_dir = package / "04_D线" / "CVE回放与PoC"
            cve_dir.mkdir(parents=True)
            report_path = cve_dir / "CVE-2025-57052-CJSON.md"
            content = "# CVE-2025-57052 cJSON\n" + "background context with sufficient padding\n" * 60
            content += "CVE-2025-57052 CWE-125 cJSON JSON Pointer 数组越界读取。\n"
            content += "[复核指引](../references/guide.txt)\n"
            report_path.write_text(content, encoding="utf-8")
            reference_path = package / "04_D线" / "references" / "guide.txt"
            reference_path.parent.mkdir(parents=True)
            reference_path.write_text("修复时检查组件边界和输入长度。\n", encoding="utf-8")
            (cve_dir / "ignored.log").write_text("CVE-2025-57052 log", encoding="utf-8")
            (cve_dir / "ignored.zip").write_bytes(b"archive")
            (package / "outside.exe").write_bytes(b"binary")
            outside = root / "outside" / "CVE-2025-57052.md"
            outside.parent.mkdir()
            outside.write_text("CVE-2025-57052 CWE-125 cJSON", encoding="utf-8")

            result = retrieve_knowledge(root, {
                "cve": "CVE-2025-57052", "cwe": "CWE-125", "file": "third_party/cJSON",
                "symbol": "cJSON_GetArrayItem", "rule_id": "cjson.pointer.bounds",
                "evidence_obligations": [{"kind": "bounds_proof",
                    "description": "确认输入边界并排除数组越界读取"}],
            })

            self.assertEqual(result["status"], "matched")
            self.assertGreaterEqual(result["indexed_files"], 2)
            self.assertLessEqual(len(result["references"]), 4)
            self.assertIn("cve-2025-57052", tokenize("CVE-2025-57052"))
            self.assertIn("cwe-125", tokenize("CWE-125"))
            self.assertIn("数组", tokenize("数组越界读取"))
            report_reference = next(item for item in result["references"]
                                    if item["path"] == "04_D线/CVE回放与PoC/CVE-2025-57052-CJSON.md")
            raw = report_path.read_bytes()
            self.assertEqual(report_reference["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertGreater(report_reference["start_line"], 1)
            self.assertLessEqual(len(report_reference["excerpt"]), 1200)
            self.assertIn("CWE-125", report_reference["excerpt"])
            self.assertNotIn("outside", " ".join(item["path"] for item in result["references"]))
            self.assertNotIn("ignored.log", " ".join(item["path"] for item in result["references"]))
            self.assertNotIn("ignored.zip", " ".join(item["path"] for item in result["references"]))

    def test_empty_and_no_match_states_are_non_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / PACKAGE_RELATIVE).mkdir(parents=True)
            empty = retrieve_knowledge(root, {"rule_id": "not-present"})
            self.assertEqual(empty["status"], "empty")
            (root / PACKAGE_RELATIVE / "CVE-index.md").write_text("ordinary notes", encoding="utf-8")
            no_match = retrieve_knowledge(root, {"rule_id": "unknown-special-token"})
            self.assertEqual(no_match["status"], "no_match")
            self.assertEqual(no_match["references"], [])

    def test_corpus_change_invalidates_authorization_before_provider_call(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed",
                        "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}

        class Ops:
            def get(self, key):
                return {"cancel_requested": False}
            def event(self, *args):
                pass

        class NeverCall:
            def create(self, payload):
                raise AssertionError("stale knowledge consent must fail before the Provider call")

        report = {"repository": "openharmony/sample", "commit": "c" * 40,
            "status": "complete", "detector_coverage": {"detectors": {"test.rule": {"status": "complete"}}}}
        candidate = {"id": "candidate-knowledge", "file": "src/sample.cpp", "line": 1,
            "source_sha256": "a" * 64, "detector_id": "test.rule", "rule_id": "sample.bounds",
            "evidence": {"analysis_status": "complete", "obligations": [
                {"kind": "guard_dominance", "description": "Check the fixed-source guard.", "status": "unknown"}]}}
        source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "void check() { return; }"}
        provider = agent.ProviderConfig("https://api.openai.com/v1", "test-model", "test-key")
        knowledge_before = {"status": "matched", "algorithm": "bm25-k1.5-b0.75-v1",
            "corpus_sha256": "1" * 64, "indexed_files": 1, "disclaimer": "untrusted",
            "references": [{"path": "CVE/example.md", "start_line": 1, "end_line": 1,
                "sha256": "2" * 64, "summary": "analogy", "score": 1.0, "excerpt": "old corpus snippet"}]}
        knowledge_after = {**knowledge_before, "corpus_sha256": "3" * 64,
            "references": [{**knowledge_before["references"][0], "excerpt": "changed corpus snippet"}]}
        spec = {"job_id": "job", "candidate_id": candidate["id"], "mode": "single_shot",
            "knowledge_retrieval_enabled": True, "max_steps": 2, "max_output_tokens": 500,
            "max_total_input_tokens": 24000, "max_total_output_tokens": 1000,
            "timeout_seconds": 90, "report_sha256": "b" * 64,
            "source_submission_approved": True, "provider_fingerprint": provider.fingerprint,
            "prompt_version": agent.PROMPT_VERSION, "tool_policy_version": agent.TOOL_POLICY_VERSION,
            "consent_preview_version": agent.CONSENT_PREVIEW_VERSION,
            "redaction_policy_version": agent.REDACTION_POLICY_VERSION}
        job = Store().job("job")
        with patch.object(agent.service, "source", return_value=source), \
             patch.object(agent.service, "read_report", return_value=report), \
             patch.object(agent.service, "finding", return_value=candidate), \
             patch.object(agent, "retrieve_knowledge", side_effect=[knowledge_before, knowledge_after]):
            preview = agent.consent_preview(None, Store(), job, report, candidate, spec, provider)
            spec["source_consent_sha256"] = preview["consent_sha256"]
            with patch.object(agent.ProviderConfig, "from_env", return_value=provider):
                with self.assertRaisesRegex(ValueError, "source consent preview no longer matches"):
                    agent.execute_agent(None, Store(), Ops(), {"id": "task", "spec": spec}, client=NeverCall())


if __name__ == "__main__":
    unittest.main()
