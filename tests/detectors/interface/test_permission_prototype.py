import copy
import json
from pathlib import Path
import unittest

from src.ohscanner.detectors.interface.permission_prototype import analyze


def fixture():
    return {"research_schema": "interface-graph-fixture-v0", "case_id": "synthetic-guard",
        "repository": "synthetic/interface", "commit": "a" * 40,
        "profile": "authored-model-only", "file": "fixtures/demo.cpp", "entry": "entry",
        "synthetic": True, "parse_status": "complete", "graph_complete": True,
        "nodes": [
            {"id": "entry", "kind": "entry", "edges": [{"to": "guard"}]},
            {"id": "guard", "kind": "guard", "subject": "ipc_caller",
             "permission": "demo.permission", "resource": "demo.resource",
             "edges": [{"to": "sink", "granted": True}, {"to": "return", "granted": False}]},
            {"id": "sink", "kind": "sink", "subject": "ipc_caller",
             "permission": "demo.permission", "resource": "demo.resource", "edges": []},
            {"id": "return", "kind": "return", "edges": []}]}


class PermissionPrototypeTests(unittest.TestCase):
    def test_guarded_fixture(self):
        self.assertEqual(analyze(fixture())["candidates"], [])

    def test_unguarded_fixture_has_witness(self):
        case = fixture()
        case["nodes"][0]["edges"] = [{"to": "sink"}]
        result = analyze(case)
        self.assertEqual(result["candidates"][0]["trace"], ["entry", "sink"])
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["confidence"], "unassessed")

    def test_wrong_identity(self):
        case = fixture()
        case["nodes"][1]["subject"] = "parcel_uid"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_wrong_permission(self):
        case = fixture()
        case["nodes"][1]["permission"] = "unrelated.permission"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_wrong_resource(self):
        case = fixture()
        case["nodes"][1]["resource"] = "other.resource"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_denial_fallthrough(self):
        case = fixture()
        case["nodes"][1]["edges"][1]["to"] = "sink"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_one_unprotected_branch(self):
        case = fixture()
        case["nodes"][0]["edges"].append({"to": "sink"})
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_unreachable_sink(self):
        case = fixture()
        case["nodes"][0]["edges"] = [{"to": "return"}]
        self.assertEqual(analyze(case)["candidates"], [])

    def test_guard_after_sink(self):
        case = fixture()
        case["nodes"][0]["edges"] = [{"to": "sink"}]
        case["nodes"][2]["edges"] = [{"to": "guard"}]
        case["nodes"][1]["edges"][0]["to"] = "return"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_identity_change_invalidates_grants(self):
        case = fixture()
        case["nodes"].append({"id": "change", "kind": "identity_change", "edges": [{"to": "sink"}]})
        case["nodes"][1]["edges"][0]["to"] = "change"
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_cycles_terminate(self):
        case = fixture()
        case["nodes"][2]["edges"] = [{"to": "entry"}]
        self.assertEqual(analyze(case)["status"], "completed")

    def test_incomplete_parse_blocks(self):
        for status in ("partial", "failed", "not_run"):
            with self.subTest(status=status):
                case = fixture()
                case["parse_status"] = status
                self.assertEqual(analyze(case)["assessment"], "unknown")

    def test_incomplete_graph_blocks(self):
        case = fixture()
        case["graph_complete"] = False
        self.assertEqual(analyze(case)["coverage"], "unknown")

    def test_real_source_cannot_be_promoted_from_authored_graph(self):
        case = fixture()
        case["synthetic"] = False
        self.assertEqual(analyze(case)["status"], "blocked")

    def test_budget_discards_partial_findings(self):
        case = fixture()
        case["nodes"][0]["edges"] = [{"to": "sink"}]
        case["nodes"][2]["edges"] = [{"to": "guard"}]
        result = analyze(case, max_states=2)
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["candidates"], [])

    def test_bad_budget(self):
        for value in (0, -1, True, 10001):
            with self.assertRaises(ValueError):
                analyze(fixture(), max_states=value)

    def test_invalid_commit_and_edge_types(self):
        for commit in (None, 123, "short"):
            case = fixture()
            case["commit"] = commit
            with self.assertRaises(ValueError):
                analyze(case)
        case = fixture()
        case["nodes"][0]["edges"][0]["to"] = []
        with self.assertRaises(ValueError):
            analyze(case)

    def test_path_validation(self):
        for value in ("../secret.cpp", "/tmp/demo.cpp", "C:/demo.cpp", "a\\b.cpp", ".", "a//b.cpp"):
            case = fixture()
            case["file"] = value
            with self.assertRaises(ValueError):
                analyze(case)

    def test_duplicate_node(self):
        case = fixture()
        case["nodes"].append(copy.deepcopy(case["nodes"][0]))
        with self.assertRaises(ValueError):
            analyze(case)

    def test_unknown_edge(self):
        case = fixture()
        case["nodes"][0]["edges"][0]["to"] = "unknown"
        with self.assertRaises(ValueError):
            analyze(case)

    def test_missing_guard_branch(self):
        case = fixture()
        case["nodes"][1]["edges"].pop()
        with self.assertRaises(ValueError):
            analyze(case)

    def test_invalid_edge(self):
        case = fixture()
        case["nodes"][1]["edges"] = ["bad"]
        with self.assertRaises(ValueError):
            analyze(case)

    def test_denial_revokes_earlier_grant(self):
        case = fixture()
        again = copy.deepcopy(case["nodes"][1])
        again["id"] = "guard2"
        again["edges"][1]["to"] = "sink"
        case["nodes"][1]["edges"][0]["to"] = "guard2"
        case["nodes"].append(again)
        self.assertEqual(analyze(case)["assessment"], "candidate")

    def test_no_input_mutation_and_deterministic_output(self):
        case = fixture()
        before = copy.deepcopy(case)
        self.assertEqual(analyze(case), analyze(case))
        self.assertEqual(case, before)

    def test_provenance_is_not_shared_across_runs(self):
        a, b = fixture(), fixture()
        b["repository"], b["commit"], b["profile"] = "other/component", "b" * 40, "other-profile"
        self.assertNotEqual(analyze(a)["commit"], analyze(b)["commit"])
        self.assertNotEqual(analyze(a)["repository"], analyze(b)["repository"])

    def test_committed_fixture_files(self):
        root = Path(__file__).resolve().parents[3]
        paths = sorted((root / "research/corpus/interface/fixtures").glob("*.json"))
        self.assertEqual(len(paths), 7)
        for path in paths:
            with self.subTest(path=path.name):
                case = json.loads(path.read_text(encoding="utf-8"))
                result = analyze(case)
                self.assertEqual(result["assessment"], case["expected_assessment"])


if __name__ == "__main__":
    unittest.main()
