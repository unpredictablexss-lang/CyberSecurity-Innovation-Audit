from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import holdout_pipeline as hp
ROOT = HERE.parents[2]
PRODUCT_GATE = ROOT / "research/deliveries/product_closure_20261019/C13_candidate_product_gate_audit.json"
LEDGER = HERE / "development_leakage_ledger.local-development-20261019.json"
PROTOCOL = HERE / "real_holdout_input_protocol.v1.json"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class HoldoutContractTests(unittest.TestCase):
    def test_protocol_hash_and_semantics(self):
        recorded = (HERE / "real_holdout_input_protocol.v1.sha256").read_text(encoding="utf-8").split()[0]
        self.assertEqual(recorded, hp.file_sha256(PROTOCOL))
        self.assertEqual([], hp.validate_protocol(load(PROTOCOL)))

    def test_schemas_are_json_and_declare_required_contract(self):
        expected = {
            "development_leakage_ledger.schema.json": "ohscanner.ark-holdout-development-leakage-ledger/v1",
            "real_holdout_intake.schema.json": "ohscanner.ark-holdout-intake/v2",
            "real_holdout_truth.schema.json": "ohscanner.ark-holdout-truth/v2",
        }
        for name, schema_id in expected.items():
            schema = load(HERE / name)
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
            self.assertEqual(schema_id, schema["$id"])
            self.assertTrue(schema["required"])

    def test_real_intake_schema_binds_ledger_file_and_payload(self):
        schema = load(HERE / "real_holdout_intake.schema.json")
        self.assertIn("development_leakage_ledger_sha256", schema["required"])
        self.assertIn("development_leakage_ledger_payload_sha256", schema["required"])

    def test_development_ledger_binds_local_development_artifacts(self):
        ledger = load(LEDGER)
        self.assertEqual("COMPLETE_LOCAL_DEVELOPMENT_ARTIFACTS", ledger["status"])
        self.assertGreaterEqual(len(ledger["excluded_case_ids"]), 28)
        self.assertGreaterEqual(len(ledger["excluded_sources"]), 100)
        self.assertEqual(
            sorted({row["sha256"] for row in ledger["excluded_sources"]}),
            ledger["excluded_source_sha256"],
        )
        errors = hp.validate_development_leakage_ledger(
            ledger, hp.file_sha256(LEDGER), {
                "development_leakage_ledger_sha256": hp.file_sha256(LEDGER),
                "development_leakage_ledger_payload_sha256": ledger["payload_sha256"],
                "cases": [],
            },
            hp.file_sha256(PROTOCOL),
        )
        self.assertEqual([], errors)

    def test_development_overlap_is_rejected(self):
        ledger = load(LEDGER)
        intake = {
            "development_leakage_ledger_sha256": hp.file_sha256(LEDGER),
            "development_leakage_ledger_payload_sha256": ledger["payload_sha256"],
            "cases": [{
                "case_id": ledger["excluded_case_ids"][0],
                "source_sha256": "f" * 64,
                "sampling_frame_sha256": ledger["selection_frame_sha256"],
            }],
        }
        errors = hp.validate_development_leakage_ledger(
            ledger, hp.file_sha256(LEDGER), intake, hp.file_sha256(PROTOCOL)
        )
        self.assertIn("development_case_id_overlap", errors)

    def test_pipeline_selftest_preserves_unknown_and_disagreement(self):
        work = HERE / "selftest-unittest-20261019"
        self.assertEqual(0, hp.self_test(argparse_namespace(work)))
        result = load(work / "selftest-validation.json")
        self.assertEqual("PASS", result["status"])
        self.assertFalse(result["metrics_computed"])
        adjudication = load(work / "frozen/adjudication_packet.json")
        self.assertEqual(1, len(adjudication["disagreements"]))
        final = load(work / "frozen/final_labels.json")
        final_labels = {row["case_pseudonym"]: row["label"] for row in final["labels"]}
        self.assertIn("unknown", set(final_labels.values()))
        for row in adjudication["disagreements"]:
            if "unknown" in {row["reviewer_1_label"], row["reviewer_2_label"]}:
                self.assertEqual("unknown", final_labels[row["case_pseudonym"]])

    def test_product_gate_never_promotes_incomplete_candidates(self):
        gate = load(PRODUCT_GATE)
        self.assertEqual("BLOCKED", gate["status"])
        self.assertEqual("NOT_ADMITTED", gate["decision"])
        self.assertEqual(28, gate["scanner_coverage_status"]["reviewed_dispositions"])
        self.assertEqual(16, gate["scanner_coverage_status"]["ark_parent_fix_product_candidates"])
        for row in gate["ark_product_candidates"]:
            self.assertIn(row["product_build_and_version"], {"unknown", "partial"})
            for field in (
                "real_entry_point", "permission_or_trust_boundary", "trigger_conditions",
                "reachable_sensitive_operation", "concrete_cia_impact",
            ):
                self.assertIn(row[field], {"unknown", "partial"})
            self.assertEqual("not_run", row["authorized_isolated_poc"])
            self.assertEqual("not_run", row["fixed_product_revalidation"])
            self.assertEqual("candidate/unassessed", row["evidence_classification"])
            self.assertEqual("NOT_ADMITTED", row["admission"])
        self.assertEqual([], gate["promotion_policy"]["promoted_to_confirmed_reportable"])
        self.assertEqual("candidate/unassessed", gate["promotion_policy"]["default"])
        for row in gate["reviewed_case_dispositions"]:
            self.assertIn(row["evidence_classification"], {"candidate/unassessed", "not-applicable"})
            self.assertIn(row["product_gate"]["admission"], {"NOT_ADMITTED", "NOT_APPLICABLE"})
        serialized = json.dumps(gate, ensure_ascii=False).lower()
        self.assertNotIn('"confirmed/reportable"', serialized)


def argparse_namespace(work: Path):
    import argparse
    return argparse.Namespace(work_dir=work)


if __name__ == "__main__":
    unittest.main()
