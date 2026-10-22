import json
import unittest

from src.workbench import agent
from src.workbench.operations_api import _case_enum_label, _case_html_narrative, _case_md_narrative


class ChineseReportLanguageTests(unittest.TestCase):
    def test_agent_prompts_require_simplified_chinese_narratives(self):
        self.assertIn("自然语言内容必须使用简体中文", agent._INSTRUCTIONS)
        self.assertIn("自然语言说明必须使用简体中文", agent._SKEPTIC_INSTRUCTIONS)
        self.assertIn("PoC 的标题", agent._ARTIFACT_INSTRUCTIONS)
        self.assertEqual(agent.PROMPT_VERSION, "ohscanner-agent-investigation-0.13.0-zh")

    def test_artifact_validator_rejects_english_report_prose(self):
        value = {
            "vulnerability_report": {
                "title": "Candidate report", "summary": "Needs review.",
                "root_cause": "Unknown.", "impact": "Unknown.",
                "preconditions": [], "attack_path": [], "remediation": "Review it.",
                "citations": [],
            },
            "poc_draft": {
                "title": "Test draft", "language": "C++", "code": "",
                "prerequisites": [], "run_steps": [], "expected_observation": "",
                "negative_control": "", "citations": [],
            },
        }
        with self.assertRaisesRegex(ValueError, "artifact narrative must be Chinese: report.title"):
            agent._validate_artifact_drafts(json.dumps(value), {},
                {"assessment": "needs_more_evidence", "supported_claims": []}, [], ["."])

    def test_report_status_codes_never_leak_unknown_english_values(self):
        self.assertEqual(_case_enum_label("completed_with_limitations"), "已完成（存在限制）")
        self.assertEqual(_case_enum_label("unknown_future_state"), "其他状态（待核对）")
        self.assertEqual(_case_enum_label("产品入口尚未核验"), "产品入口尚未核验")

    def test_chinese_report_prose_passes_and_english_fields_fold_in_exports(self):
        self.assertEqual(_case_md_narrative("该路径需要人工复核。"), "该路径需要人工复核。")
        mixed = _case_md_narrative("该调用会读取 index and may write past the buffer unless checked.")
        self.assertIn("该说明主要为英文", mixed)
        self.assertIn("该说明主要为英文，已折叠原文", _case_md_narrative("该调用 may return null when the guard is missing."))
        self.assertIn("<details>", mixed)
        md = _case_md_narrative("The old report is unverified.")
        self.assertIn("该说明主要为英文，已折叠原文", md)
        self.assertIn("<details>", md)
        self.assertIn("The old report is unverified.", md)
        html = _case_html_narrative("<script>alert(1)</script>")
        self.assertIn("查看原文（历史记录）", html)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
