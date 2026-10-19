from __future__ import annotations

import copy
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from research.evaluation.ark_runtime_holdout_20261019 import holdout_pipeline as hp


def make_intake(root: Path) -> tuple[dict, dict, Path]:
    source_root = root / "sources"
    source_root.mkdir(parents=True, exist_ok=True)
    source_path = "sample.cpp"
    source = b"int synthetic_sample(int x) { return x + 1; }\n"
    (source_root / source_path).write_bytes(source)
    digest = hp.sha256_bytes(source)
    case_id = "SYNTHETIC-CASE-1"
    identity = {
        "repository": "https://example.invalid/synthetic/repo",
        "commit": "1" * 40,
        "tree": "2" * 40,
        "path": source_path,
        "blob": hp.git_blob_oid(source),
        "source_sha256": digest,
    }
    profile = {
        "detector_rule_version": "synthetic-rule-1",
        "scope": "synthetic-scope",
        "profile": "synthetic-profile",
        "config_hash": hp.sha256_bytes(b"config"),
        "parser_identity": "synthetic-parser-1",
        "toolchain_identity": "synthetic-toolchain-1",
        "source_identity_sha256": hp.payload_hash(identity),
        "product_build_preprocess": {
            "status": "COMPLETE",
            "product_manifest": "synthetic-manifest",
            "exact_args_gn": "synthetic-args",
            "gn_target": "synthetic-target",
            "compile_commands_json": "synthetic-compile-commands",
            "actual_include_closure": "synthetic-include-closure",
            "compiler_identity": "synthetic-compiler",
            "linker_identity": "synthetic-linker",
            "sysroot_identity": "synthetic-sysroot",
            "preprocessed_translation_units": ["synthetic-tu"],
            "macro_expansion_log": "synthetic-macro-log",
        },
    }
    verification = hp.seal_artifact(hp.SOURCE_VERIFICATION_SCHEMA, {
        "verification_status": "verified",
        "verifier": "synthetic-test-only",
        "evidence_sha256": hp.sha256_bytes(b"synthetic evidence"),
        "identity": copy.deepcopy(identity),
    })
    case = {
        "case_id": case_id,
        "source_path": source_path,
        "source_sha256": digest,
        "selection_rule_id": "synthetic-selection",
        "sampling_frame_sha256": hp.sha256_bytes(b"synthetic-frame"),
        "development_overlap": False,
        "root_cause_family": "synthetic-family-1",
        "source_identity": identity,
        "source_verification": verification,
        "profile": profile,
    }
    prereg = hp.seal_artifact(hp.PREREGISTRATION_SCHEMA, {"protocol": {
        "target_population": "synthetic only",
        "analysis_unit": "one synthetic source file",
        "family_rule": "synthetic family key",
        "sample_size": 1,
        "inclusion": "generated fixture",
        "exclusion": "none",
        "unknown_rule": "preserve unknown",
        "disagreement_rule": "adjudicate disagreement",
        "estimate": "none",
        "freeze_procedure": "synthetic test",
    }})
    ledger = hp.seal_artifact(hp.LEAKAGE_LEDGER_SCHEMA, {"ledger": {
        "development_source_sha256": [],
        "history_review_source_sha256": [],
        "development_family_keys": [],
        "history_review_family_keys": [],
        "cases": {case_id: {
            "status": "no_overlap",
            "evidence_ref": "synthetic-test-only",
            "source_sha256": digest,
            "root_cause_family": case["root_cause_family"],
        }},
    }})
    intake = {
        "schema": hp.INTAKE_SCHEMA,
        "preregistration": prereg,
        "preregistration_sha256": prereg["payload_sha256"],
        "development_leakage_ledger": ledger,
        "development_leakage_ledger_sha256": ledger["payload_sha256"],
        "cases": [case],
    }
    truth = {"schema": hp.TRUTH_SCHEMA, "truth_status": "pipeline_self_test_not_reliable", "model_generated": False, "labels": {
        case_id: {"label": "unknown", "model_generated": False, "root_cause_family": "synthetic-family-1"},
    }}
    return intake, truth, source_root


def make_freeze_and_packet() -> tuple[dict, dict]:
    packet = {"schema": hp.REVIEW_SCHEMA, "reviewer": "A", "cases": [{
        "case_pseudonym": "p1", "source_text": "int f() { return 1; }", "source_sha256": "a" * 64,
        "question": "classify shape", "forbidden_context": ["true label", "case id", "source path", "parent/fixed pairing", "scanner verdict"],
    }]}
    packet_b = {**packet, "reviewer": "B"}
    manifest = {
        "schema": hp.FREEZE_SCHEMA,
        "status": "FROZEN_PIPELINE_ONLY",
        "truth_commitment_sha256": "b" * 64,
        "preregistration_sha256": "c" * 64,
        "development_leakage_ledger_sha256": "d" * 64,
        "case_count": 1,
        "case_pseudonyms": ["p1"],
        "public_case_rows": [{"case_pseudonym": "p1", "source_sha256": "a" * 64, "source_identity_sha256": "b" * 64, "profile_identity_sha256": "c" * 64}],
        "packet_payload_sha256": {"A": hp.payload_hash(packet), "B": hp.payload_hash(packet_b)},
    }
    manifest["payload_sha256"] = hp.payload_hash(manifest)
    return manifest, packet


def make_review_submission(manifest: dict, packet: dict) -> dict:
    submission = {
        "schema": hp.REVIEW_SCHEMA,
        "packet_sha256": hp.payload_hash(packet),
        "reviewer_identity": "synthetic-reviewer-a",
        "reviewer_role": "reviewer_a",
        "signature": {"scheme": "synthetic-test-only", "key_id": "test-key-a", "value": "not-a-real-signature"},
        "labels": [{"case_pseudonym": "p1", "label": "unknown", "rationale": "synthetic"}],
    }
    submission["attestation_sha256"] = hp.payload_hash({
        "freeze_payload_sha256": manifest["payload_sha256"],
        "packet_sha256": hp.payload_hash(packet),
        "reviewer_identity": submission["reviewer_identity"],
        "reviewer_role": submission["reviewer_role"],
        "labels": submission["labels"],
    })
    return submission


def make_adjudication_submission(packet: dict, decisions: list[dict]) -> dict:
    submission = {
        "schema": hp.ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": packet["freeze_payload_sha256"],
        "adjudication_packet_sha256": packet["payload_sha256"],
        "adjudicator_identity": "synthetic-adjudicator",
        "adjudicator_role": "adjudicator",
        "adjudicator_signature": {"scheme": "synthetic-test-only", "key_id": "test-adjudicator", "value": "not-a-real-signature"},
        "decisions": decisions,
    }
    submission["attestation_sha256"] = hp.payload_hash({
        "freeze_payload_sha256": submission["freeze_payload_sha256"],
        "adjudication_packet_sha256": submission["adjudication_packet_sha256"],
        "adjudicator_identity": submission["adjudicator_identity"],
        "adjudicator_role": submission["adjudicator_role"],
        "decisions": submission["decisions"],
    })
    return submission


class FailClosedReviewTests(unittest.TestCase):
    def test_complete_synthetic_intake_is_structurally_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            self.assertEqual([], hp.validate_intake(intake, truth, source_root))

    def test_synthetic_fixture_cannot_bypass_real_truth_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["synthetic_fixture"] = True
            truth["truth_status"] = "reliable_independent_human_adjudicated"
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("synthetic_fixture_cannot_claim_reliable_truth", errors)

    def test_missing_source_identity_or_profile_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            del intake["cases"][0]["source_identity"]
            del intake["cases"][0]["profile"]
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("missing_source_identity:SYNTHETIC-CASE-1", errors)
            self.assertIn("missing_profile_identity:SYNTHETIC-CASE-1", errors)

    def test_source_tree_binding_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["cases"][0]["source_identity"]["tree"] = "3" * 40
            proof = intake["cases"][0]["source_verification"]
            proof["payload_sha256"] = hp.object_hash_without(proof, "payload_sha256")
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("source_verification_identity_mismatch:SYNTHETIC-CASE-1", errors)
            self.assertIn("profile_source_identity_mismatch:SYNTHETIC-CASE-1", errors)

    def test_blob_and_source_hash_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["cases"][0]["source_identity"]["blob"] = "4" * 40
            intake["cases"][0]["source_sha256"] = "5" * 64
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("source_identity_blob_mismatch:SYNTHETIC-CASE-1", errors)
            self.assertIn("source_sha256_mismatch:SYNTHETIC-CASE-1", errors)

    def test_product_profile_incomplete_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["cases"][0]["profile"]["product_build_preprocess"]["status"] = "BLOCKED"
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("product_build_profile_not_complete:SYNTHETIC-CASE-1", errors)

    def test_preregistration_hash_tamper_and_missing_fields_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["preregistration"]["protocol"].pop("sample_size")
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("preregistration_payload_hash_mismatch", errors)
            self.assertIn("preregistration_missing_sample_size", errors)

    def test_development_or_historical_family_overlap_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            ledger = intake["development_leakage_ledger"]
            ledger["ledger"]["history_review_family_keys"] = ["synthetic-family-1"]
            ledger["payload_sha256"] = hp.object_hash_without(ledger, "payload_sha256")
            intake["development_leakage_ledger_sha256"] = ledger["payload_sha256"]
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("development_or_history_family_overlap:SYNTHETIC-CASE-1", errors)

    def test_development_overlap_self_report_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            intake["cases"][0]["development_overlap"] = True
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("development_overlap_not_false:SYNTHETIC-CASE-1", errors)

    def test_leakage_ledger_case_identity_or_clearance_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            intake, truth, source_root = make_intake(Path(temp))
            row = intake["development_leakage_ledger"]["ledger"]["cases"]["SYNTHETIC-CASE-1"]
            row["status"] = "unknown"
            ledger = intake["development_leakage_ledger"]
            ledger["payload_sha256"] = hp.object_hash_without(ledger, "payload_sha256")
            intake["development_leakage_ledger_sha256"] = ledger["payload_sha256"]
            errors = hp.validate_intake(intake, truth, source_root)
            self.assertIn("leakage_case_not_cleared:SYNTHETIC-CASE-1", errors)

    def test_reviewer_identity_role_signature_and_attestation_are_required(self):
        manifest, packet = make_freeze_and_packet()
        submission = make_review_submission(manifest, packet)
        self.assertEqual([], hp.validate_submission(manifest, packet, submission))
        for field in ("reviewer_identity", "reviewer_role", "signature", "attestation_sha256"):
            bad = copy.deepcopy(submission)
            bad.pop(field)
            self.assertTrue(hp.validate_submission(manifest, packet, bad), field)

    def test_reviewer_pair_requires_distinct_ids_roles_and_same_case_set(self):
        freeze = "a" * 64
        truth = "b" * 64
        def lock(identity: str, role: str, pseudo: str = "p1") -> dict:
            labels = [{"case_pseudonym": pseudo, "label": "unknown", "rationale": "synthetic"}]
            reviewer_role = "A" if role == "reviewer_a" else "B"
            packet_digest = ("a" if reviewer_role == "A" else "b") * 64
            value = {
                "schema": hp.LOCK_SCHEMA, "freeze_payload_sha256": freeze, "truth_commitment_sha256": truth,
                "reviewer_identity": identity, "reviewer_role": role, "reviewer": reviewer_role,
                "packet_sha256": packet_digest,
                "signature": {"scheme": "synthetic", "key_id": identity, "value": "test-only"},
                "submission_payload_sha256": "d" * 64,
                "labels": labels,
            }
            value["attestation_sha256"] = hp.payload_hash({
                "freeze_payload_sha256": freeze, "packet_sha256": packet_digest,
                "reviewer_identity": identity, "reviewer_role": role, "labels": labels,
            })
            value["payload_sha256"] = hp.payload_hash(value)
            return value
        left = lock("reviewer-1", "reviewer_a")
        right = lock("reviewer-2", "reviewer_b")
        self.assertEqual([], hp.validate_reviewer_pair(left, right))
        self.assertIn("reviewer_identity_not_independent", hp.validate_reviewer_pair(left, lock("reviewer-1", "reviewer_b")))
        self.assertIn("reviewer_role_separation", hp.validate_reviewer_pair(left, lock("reviewer-2", "reviewer_a")))
        self.assertIn("review_pair_case_set_mismatch", hp.validate_reviewer_pair(left, lock("reviewer-2", "reviewer_b", "p2")))

    def test_blind_packets_reject_labels_or_context_leak(self):
        manifest, packet_a = make_freeze_and_packet()
        packet_b = {**packet_a, "reviewer": "B"}
        manifest["packet_payload_sha256"] = {"A": hp.payload_hash(packet_a), "B": hp.payload_hash(packet_b)}
        manifest["payload_sha256"] = hp.payload_hash({key: value for key, value in manifest.items() if key != "payload_sha256"})
        self.assertEqual([], hp.validate_blind_packets(manifest, packet_a, packet_b))
        leaked = copy.deepcopy(packet_a)
        leaked["cases"][0]["true_label"] = "unknown"
        self.assertIn("blind_packet_context_fields:A", hp.validate_blind_packets(manifest, leaked, packet_b))

    def test_adjudication_packet_checks_hash_and_full_case_set(self):
        packet = {
            "schema": hp.ADJUDICATION_SCHEMA, "freeze_payload_sha256": "a" * 64,
            "truth_commitment_sha256": "b" * 64, "status": "THIRD_REVIEW_REQUIRED",
            "case_pseudonyms": ["p1", "p2"], "agreements": [{"case_pseudonym": "p1", "label": "unknown", "route": "agreement"}],
            "disagreements": [{"case_pseudonym": "p2", "label_1": "unknown", "label_2": "unknown", "rationale_1": "x", "rationale_2": "y"}],
        }
        packet["payload_sha256"] = hp.payload_hash(packet)
        self.assertEqual([], hp.validate_adjudication_packet(packet))
        bad_set = copy.deepcopy(packet)
        bad_set["case_pseudonyms"] = ["p1"]
        bad_set["payload_sha256"] = hp.object_hash_without(bad_set, "payload_sha256")
        self.assertIn("adjudication_packet_full_case_set_mismatch", hp.validate_adjudication_packet(bad_set))

    def test_apply_adjudication_rejects_freeze_hash_and_extra_decisions(self):
        packet = {
            "schema": hp.ADJUDICATION_SCHEMA, "freeze_payload_sha256": "a" * 64,
            "truth_commitment_sha256": "b" * 64, "status": "THIRD_REVIEW_REQUIRED",
            "case_pseudonyms": ["p1"], "agreements": [],
            "disagreements": [{"case_pseudonym": "p1", "label_1": "unknown", "label_2": "vulnerable_shape", "rationale_1": "x", "rationale_2": "y"}],
        }
        packet["payload_sha256"] = hp.payload_hash(packet)
        bad_freeze = make_adjudication_submission(packet, [{"case_pseudonym": "p1", "decision": "unknown", "rationale": "test"}])
        bad_freeze["freeze_payload_sha256"] = "c" * 64
        extra_decisions = make_adjudication_submission(packet, [{"case_pseudonym": "p1", "decision": "unknown", "rationale": "test"}, {"case_pseudonym": "extra", "decision": "unknown", "rationale": "test"}])
        for submission in (bad_freeze, extra_decisions):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                hp.write_json(root / "packet.json", packet)
                hp.write_json(root / "submission.json", submission)
                with self.assertRaises(SystemExit):
                    hp.apply_adjudication(Namespace(adjudication_packet=root / "packet.json", adjudication_submission=root / "submission.json", output=root / "final.json"))

    def test_final_label_schema_hash_and_chain_are_required(self):
        final = {
            "schema": hp.FINAL_SCHEMA, "status": "FINAL_LABELS_AVAILABLE", "model_generated": False,
            "freeze_payload_sha256": "a" * 64, "truth_commitment_sha256": "b" * 64,
            "adjudication_packet_sha256": "c" * 64, "adjudication_submission_sha256": "d" * 64,
            "labels": [{"case_pseudonym": "p1", "label": "unknown", "route": "agreement"}],
        }
        final["payload_sha256"] = hp.payload_hash(final)
        self.assertEqual([], hp.validate_final_labels(final))
        wrong_schema = copy.deepcopy(final)
        wrong_schema["schema"] = "wrong"
        self.assertIn("final_labels_schema", hp.validate_final_labels(wrong_schema))
        wrong_hash = copy.deepcopy(final)
        wrong_hash["payload_sha256"] = "e" * 64
        self.assertIn("final_labels_payload_hash", hp.validate_final_labels(wrong_hash))
        missing_chain = copy.deepcopy(final)
        missing_chain.pop("adjudication_submission_sha256")
        missing_chain["payload_sha256"] = hp.object_hash_without(missing_chain, "payload_sha256")
        self.assertIn("final_labels_adjudication_submission_sha256", hp.validate_final_labels(missing_chain))

    def test_scoring_chain_must_reconcile_reviews_adjudication_and_final_labels(self):
        manifest, packet_a = make_freeze_and_packet()
        packet_b = {**packet_a, "reviewer": "B"}
        manifest["packet_payload_sha256"] = {"A": hp.payload_hash(packet_a), "B": hp.payload_hash(packet_b)}
        manifest["payload_sha256"] = hp.payload_hash({key: value for key, value in manifest.items() if key != "payload_sha256"})

        def make_lock(identity: str, role: str) -> dict:
            labels = [{"case_pseudonym": "p1", "label": "unknown", "rationale": "synthetic"}]
            packet_digest = manifest["packet_payload_sha256"]["A" if role == "reviewer_a" else "B"]
            lock = {
                "schema": hp.LOCK_SCHEMA,
                "freeze_payload_sha256": manifest["payload_sha256"],
                "truth_commitment_sha256": manifest["truth_commitment_sha256"],
                "reviewer_identity": identity,
                "reviewer_role": role,
                "reviewer": "A" if role == "reviewer_a" else "B",
                "packet_sha256": packet_digest,
                "signature": {"scheme": "synthetic-test-only", "key_id": identity, "value": "not-a-real-signature"},
                "submission_payload_sha256": "f" * 64,
                "labels": labels,
            }
            lock["attestation_sha256"] = hp.payload_hash({
                "freeze_payload_sha256": manifest["payload_sha256"],
                "packet_sha256": packet_digest,
                "reviewer_identity": identity,
                "reviewer_role": role,
                "labels": labels,
            })
            lock["payload_sha256"] = hp.payload_hash(lock)
            return lock

        review_a = make_lock("reviewer-a", "reviewer_a")
        review_b = make_lock("reviewer-b", "reviewer_b")
        packet = {
            "schema": hp.ADJUDICATION_SCHEMA,
            "freeze_payload_sha256": manifest["payload_sha256"],
            "truth_commitment_sha256": manifest["truth_commitment_sha256"],
            "case_pseudonyms": ["p1"],
            "status": "AGREEMENT_COMPLETE",
            "agreements": [{"case_pseudonym": "p1", "label": "unknown", "route": "agreement"}],
            "disagreements": [],
        }
        packet["payload_sha256"] = hp.payload_hash(packet)
        submission = make_adjudication_submission(packet, [])
        final = {
            "schema": hp.FINAL_SCHEMA,
            "status": "FINAL_LABELS_AVAILABLE",
            "model_generated": False,
            "freeze_payload_sha256": manifest["payload_sha256"],
            "truth_commitment_sha256": manifest["truth_commitment_sha256"],
            "adjudication_packet_sha256": packet["payload_sha256"],
            "adjudication_submission_sha256": hp.payload_hash(submission),
            "labels": [{"case_pseudonym": "p1", "label": "unknown", "route": "agreement"}],
        }
        final["payload_sha256"] = hp.payload_hash(final)
        self.assertEqual([], hp.validate_scoring_chain(manifest, packet, submission, review_a, review_b, final))
        tampered = copy.deepcopy(final)
        tampered["labels"][0]["label"] = "vulnerable_shape"
        tampered["payload_sha256"] = hp.object_hash_without(tampered, "payload_sha256")
        self.assertIn("chain_final_labels_not_derived", hp.validate_scoring_chain(manifest, packet, submission, review_a, review_b, tampered))

    def test_scoring_gate_keeps_synthetic_truth_not_run_and_rejects_bad_final(self):
        final = {
            "schema": hp.FINAL_SCHEMA, "status": "FINAL_LABELS_AVAILABLE", "model_generated": False,
            "freeze_payload_sha256": "a" * 64, "truth_commitment_sha256": "b" * 64,
            "adjudication_packet_sha256": "c" * 64, "adjudication_submission_sha256": "d" * 64,
            "labels": [{"case_pseudonym": "p1", "label": "unknown", "route": "agreement"}],
        }
        final["payload_sha256"] = hp.payload_hash(final)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            truth = {"schema": hp.TRUTH_SCHEMA, "truth_status": "pipeline_self_test_not_reliable", "model_generated": False, "labels": {"case1": {"label": "unknown", "model_generated": False}}}
            hp.write_json(root / "truth.json", truth)
            hp.write_json(root / "final.json", final)
            (root / "secret").write_text("synthetic-secret", encoding="utf-8")
            rc = hp.score(Namespace(truth=root / "truth.json", final_labels=root / "final.json", secret_file=root / "secret", output=root / "score.json"))
            self.assertEqual(3, rc)
            bad = copy.deepcopy(final)
            bad["schema"] = "wrong"
            bad["payload_sha256"] = hp.object_hash_without(bad, "payload_sha256")
            hp.write_json(root / "bad-final.json", bad)
            with self.assertRaises(SystemExit):
                hp.score(Namespace(truth=root / "truth.json", final_labels=root / "bad-final.json", secret_file=root / "secret", output=root / "score.json"))

    def test_self_test_never_reports_real_metrics(self):
        generated = Path(hp.__file__).resolve().parent / "selftest" / "fail-closed-review-20261020" / "generated"
        generated.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=generated) as temp:
            work = Path(temp) / "synthetic-work"
            rc = hp.self_test(Namespace(work_dir=work))
            self.assertEqual(0, rc)
            result = hp.load_json(work / "selftest-validation.json")
            self.assertEqual("PASS", result["status"])
            self.assertIs(result["metrics_computed"], False)
            self.assertIn("synthetic self-test truth is not reliable", result["reason"])


if __name__ == "__main__":
    unittest.main()
