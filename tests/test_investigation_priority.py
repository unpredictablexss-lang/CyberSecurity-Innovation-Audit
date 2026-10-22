import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.workbench.investigation_priority import investigation_priority
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.operations_store import Operations

class InvestigationPriorityTests(unittest.TestCase):
    def setUp(self):
        self.report = {"repository":"sample/repo", "commit":"c"*40, "snapshot_sha256":"d"*64,
            "detector_runs":[], "detector_coverage":{"detectors":{}}}
        self.candidates = [dict(id=str(i),file="a.cpp",line=i+1,rule_id="RULE",detector_id="det",
            detector_version="1",source_sha256="e"*64,symbol="run",severity="high",
            evidence={"obligations":[{},{}]}) for i in range(6)]
        self.operations = []
        self.results = {}

    def add(self, candidate, assessment="needs_more_evidence", validation="accepted", mode="single_shot", status="completed"):
        op_id = "op-"+str(len(self.operations))
        self.operations.append({"id":op_id,"candidate_id":candidate,"mode":mode,"status":status,"result_sha256":"f"*64})
        self.results[op_id] = {"binding":{"job_id":"job", "candidate_id":candidate,"report_sha256":"b"*64},
            "structured_answer_validation":validation,"structured_answer_validation_error_code":"invalid_schema" if validation!="accepted" else None,
            "agent_assessment":{"assessment":assessment,"supported_claims":[{"obligation_indices":[0],"citations":[{}]}],
                "obligation_reviews":[{"obligation_index":0,"disposition":"evidence_found"},{"obligation_index":1,"disposition":"unresolved"}]}}
        return op_id

    def run_priority(self, source_indices=None):
        with patch("src.workbench.investigation_priority.service.findings", return_value=self.candidates), \
             patch("src.workbench.service.findings", return_value=self.candidates), \
             patch("src.workbench.investigation_priority._candidate_evidence_routing", return_value={"agent_source_review_indices":[0,1] if source_indices is None else source_indices}):
            return investigation_priority(self.report,"job","b"*64,self.operations,self.results.__getitem__)

    def test_similar_candidates_group_once_and_keep_every_member(self):
        self.add("0");self.add("1",validation="rejected_without_repair")
        value=self.run_priority()
        self.assertEqual(value["counts"]["candidates"],6)
        self.assertEqual(value["counts"]["groups"],1)
        self.assertEqual(value["counts"]["incomplete"],1)
        group=value["groups"][0]
        self.assertEqual(group["member_count"],6)
        self.assertEqual(group["representative"]["candidate_id"],"0")
        self.assertEqual(group["priority"],"investigate")
        self.assertEqual(group["root_cause_conclusion"],"not_inferred")

    def test_distinct_symbols_rules_sources_and_missing_symbols_not_merged(self):
        self.candidates[1]["symbol"]="other"
        self.candidates[2]["source_sha256"]="x"*64
        self.candidates[3]["rule_id"]="OTHER"
        self.candidates[4]["symbol"]=""
        self.candidates[5]["symbol"]=""
        self.assertEqual(self.run_priority()["counts"]["groups"],6)

    def test_failed_response_not_ranked_as_low_risk(self):
        self.add("0",assessment="likely_false_positive",validation="rejected_without_repair")
        group=self.run_priority()["groups"][0]
        self.assertEqual(group["priority"],"incomplete")
        self.assertIsNone(group["rank"])
        self.assertFalse(group["auto_select"])
        self.assertIsNone(group["representative"]["assessment"])

    def test_latest_pending_initial_does_not_reuse_old_success_or_deep_verdict(self):
        self.add("0",assessment="likely_true_positive")
        self.add("0",status="running")
        self.add("0",assessment="likely_false_positive",mode="tool_agent")
        group=self.run_priority()["groups"][0]
        self.assertEqual(group["priority"],"pending")
        self.assertFalse(group["auto_select"])

    def test_binding_mismatch_is_not_ranked(self):
        op=self.add("0");self.results[op]["binding"]["report_sha256"]="wrong"
        self.assertEqual(self.run_priority()["groups"][0]["priority"],"incomplete")

    def test_human_only_obligations_and_refutation_are_not_auto_selected(self):
        self.add("0")
        group=self.run_priority([])["groups"][0]
        self.assertEqual(group["priority"],"human_review")
        self.assertFalse(group["auto_select"])
        self.assertFalse(group["representative"]["eligible"])
        self.operations=[];self.add("0",assessment="likely_false_positive")
        group=self.run_priority()["groups"][0]
        self.assertEqual(group["priority"],"defer")
        self.assertFalse(group["auto_select"])

    def test_group_with_existing_deep_investigation_is_not_auto_selected(self):
        self.add("0");self.add("1");self.add("1",mode="tool_agent",status="running")
        group=self.run_priority()["groups"][0]
        self.assertFalse(group["auto_select"])
        self.assertEqual(len(group["members"]),6)

    def test_priority_precedes_static_severity_and_has_repeatable_order(self):
        for i,c in enumerate(self.candidates):c["symbol"]="f"+str(i)
        self.candidates[0]["severity"]="low"
        self.candidates[1]["severity"]="critical"
        self.add("0");self.add("1",assessment="likely_false_positive")
        first=self.run_priority();second=self.run_priority()
        self.assertEqual(first,second)
        self.assertEqual(first["groups"][0]["representative"]["candidate_id"],"0")
        self.assertEqual(first["groups"][0]["rank"],1)

    def test_api_uses_only_operations_bound_to_current_report_and_does_not_enqueue(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);app=create_app(Settings(root/"data",(root,)))
            repo=app.state.store.add_repository("sample/repo",str(root))
            job=app.state.store.create_job(repo["id"],{"commit":"c"*40})
            with app.state.store.connect() as db:db.execute("UPDATE jobs SET status='completed',report_sha256=? WHERE id=?",("b"*64,job["id"]))
            ops=Operations(app.state.store)
            ops.create("agent_investigation",{"job_id":job["id"],"report_sha256":"stale","candidate_id":"0","mode":"single_shot"})
            with patch("src.workbench.operations_api.service.read_report",return_value=self.report), \
                 patch("src.workbench.investigation_priority.service.findings",return_value=self.candidates), \
                 TestClient(app) as client:
                before=len(ops.list())
                response=client.get("/api/v1/scans/"+job["id"]+"/investigation-priority")
                self.assertEqual(response.status_code,200,response.text)
                self.assertEqual(response.json()["counts"]["analyzed"],0)
                self.assertEqual(len(ops.list()),before)
