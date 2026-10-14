import hashlib
import json
import unittest

from src.investigation.contracts import FactBundle
from src.investigation.drafts import (
    DraftValidationError,
    validate_investigation_draft,
)
from src.investigation.ipc_deterministic import (
    InvestigationIntegrityError,
    build_ipc_fact_bundle,
)


TEXT = "int Open(int code) {\n  return code;\n}\n"


def git_blob_id(data):
    framed = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(framed).hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(
    *,
    run_status="completed",
    analysis_status="analyzed",
    with_obligations=True,
    include_report_bytes=True,
    schema_version=2,
):
    data = TEXT.encode("utf-8")
    source_sha = sha(data)
    source_blob = git_blob_id(data)
    diagnostic = {
        "diagnostic_id": "",
        "provider": "ohscanner.interface.ipc",
        "evidence_type": "syntax",
        "file": "ipc.cpp",
        "line": 1,
        "column": 5,
        "rule_id": "ipc.auth.missing",
        "severity": "unassessed",
        "message": "AUTH-02 candidate: modeled effect lacks matched caller authorization; path=[]",
        "candidate_cwe": "CWE-862",
        "confidence": "unassessed",
        "symbol": "Open",
        "source_sha256": source_sha,
        "consequence_impact": "unauthorized_effect",
        "consequence_cwe": None,
    }
    if schema_version == 2:
        diagnostic["diagnostic_id"] = "ohscanner.interface.ipc:" + sha(
            "|".join((
                source_sha,
                diagnostic["file"],
                str(diagnostic["line"]),
                diagnostic["rule_id"],
                diagnostic["message"],
            )).encode("utf-8")
        )[:16]
    else:
        diagnostic["diagnostic_id"] = "legacy-tool:diagnostic-1"
    run = {
        "schema_version": schema_version,
        "run_id": "request:ohscanner.interface.ipc",
        "tool": "ohscanner.interface.ipc",
        "tool_version": "0.5.0",
        "target_id": "current-component:fixture/ipc",
        "commit": "a" * 40,
        "scope_files": 1,
        "scope_loc": 3,
        "status": run_status,
        "elapsed_seconds": 0.1,
        "diagnostics": [diagnostic],
        "limitations": ["No compiler CFG or full authorization proof."],
        "parsing": [{
            "file": "ipc.cpp",
            "status": "complete",
            "issues": [],
            "analysis_status": analysis_status,
            "analysis_reason": "" if analysis_status == "analyzed" else "partial_parse",
        }],
    }
    report = {
        "repository": "fixture/ipc",
        "commit": "a" * 40,
        "git_tree": "b" * 40,
        "snapshot_sha256": "c" * 64,
        "detector_runs": [run],
        "detector_coverage": {"detectors": {"ohscanner.interface.ipc": {}}},
    }
    candidate_id = sha(json.dumps([
        report["repository"],
        report["commit"],
        report["snapshot_sha256"],
        run["tool"],
        run["tool_version"],
        diagnostic["diagnostic_id"],
    ]).encode("utf-8"))
    obligations = [
        {
            "kind": "entry_reachability",
            "description": "Verify actual caller reachability.",
            "status": "unknown",
        },
        {
            "kind": "callee_and_policy",
            "description": "Verify receiver binding and required permission.",
            "status": "unknown",
        },
        {
            "kind": "security_impact",
            "description": "Independently establish concrete impact.",
            "status": "unknown",
        },
    ] if with_obligations else None
    evidence = {
        "diagnostic_id": diagnostic["diagnostic_id"],
        "file": diagnostic["file"],
        "source_sha256": source_sha,
        "analysis_status": analysis_status,
        "source_binding": {
            "repository": report["repository"],
            "commit": report["commit"],
            "snapshot_sha256": report["snapshot_sha256"],
            "profile_id": "light-ast",
            "detector_id": run["tool"],
            "detector_version": run["tool_version"],
            "rule_id": diagnostic["rule_id"],
            "file": diagnostic["file"],
            "source_sha256": source_sha,
        },
        "consequence_impact": diagnostic["consequence_impact"],
        "consequence_cwe": diagnostic["consequence_cwe"],
        "model_version": "oh-ipc-2026.10-v3",
    }
    if obligations is not None:
        evidence["obligations"] = obligations
    candidate = {**diagnostic, "evidence": evidence}
    report_bytes = json.dumps(report, ensure_ascii=False).encode("utf-8") if include_report_bytes else None
    report_sha = sha(json.dumps(report, ensure_ascii=False).encode("utf-8"))
    source = {
        "file": "ipc.cpp",
        "commit": report["commit"],
        "blob": source_blob,
        "sha256": source_sha,
        "text": TEXT,
    }
    return {
        "report": report,
        "candidate_id": candidate_id,
        "candidate": candidate,
        "report_bytes": report_bytes,
        "report_sha": report_sha,
        "source": source,
    }


def source_evidence_record(data, record_id="evidence-1", text=None):
    source = data["source"]
    text = TEXT if text is None else text
    return {
        "id": record_id,
        "job_id": "job-1",
        "candidate_id": data["candidate_id"],
        "kind": "source_excerpt",
        "interpretation": "human_selected_context_not_path_or_runtime_proof",
        "repository": data["report"]["repository"],
        "commit": data["report"]["commit"],
        "git_tree": data["report"]["git_tree"],
        "snapshot_sha256": data["report"]["snapshot_sha256"],
        "report_sha256": data["report_sha"],
        "file": source["file"],
        "blob": source["blob"],
        "source_sha256": source["sha256"],
        "start_line": 1,
        "end_line": 1,
        "text": text.splitlines(keepends=True)[0],
        "excerpt_sha256": sha(text.splitlines(keepends=True)[0].encode("utf-8")),
        "note": "candidate line",
    }


def valid_draft(data, fact_id):
    return {
        "schema_version": "ohscanner.investigation-draft-v1",
        "draft_id": "draft-1",
        "candidate_id": data["candidate_id"],
        "producer": {"kind": "human"},
        "input_context": {
            "fact_bundle_sha256": "",
            "report_sha256": data["report_sha"],
            "tool_call_ids": [],
            "tool_result_evidence_ids": [],
            "budget": {
                "input_tokens": 0,
                "output_tokens": 0,
                "tool_calls": 0,
                "wall_clock_seconds": 0,
            },
            "model_parameters": {},
        },
        "claims": [{
            "claim_id": "claim-1",
            "kind": "hypothesis",
            "text": "The recorded authorization obligation remains unresolved.",
            "evidence_refs": [fact_id],
            "status": "draft",
        }],
        "assumptions": ["The fixed source object is the only source considered."],
        "missing_evidence": [],
        "recommended_probes": [],
        "limitations": ["No runtime or product-entry evidence is included."],
        "review_recommendations": ["Review the caller permission boundary."],
        "status": "draft_only",
        "can_promote": False,
    }


class DeterministicFactBundleTests(unittest.TestCase):
    def build(self, data=None, **kwargs):
        data = data or fixture(**kwargs)
        bundle = build_ipc_fact_bundle(
            report=data["report"],
            candidate_id=data["candidate_id"],
            candidate_record=data["candidate"],
            source=data["source"],
            report_sha256=data["report_sha"],
            report_bytes=data["report_bytes"],
        )
        return data, bundle

    def test_source_bound_bundle_is_stable_and_mechanical(self):
        data, first = self.build()
        _, second = self.build(data)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.fact_bundle_sha256, second.fact_bundle_sha256)
        self.assertEqual(first.analysis_status, "complete")
        gates = {item.name: item.status for item in first.gate_checks}
        self.assertEqual(gates["report_integrity"], "met")
        self.assertEqual(gates["source_integrity"], "met")
        self.assertEqual(gates["candidate_identity"], "met")
        for name in (
            "entry_reachability", "callee_and_policy", "guard_dominance",
            "attacker_control", "cia_impact", "security_impact",
        ):
            self.assertEqual(gates[name], "unknown", name)

    def test_report_object_must_match_verified_report_bytes(self):
        data = fixture()
        changed = dict(data["report"])
        changed["repository"] = "fixture/changed"
        data["report"] = changed
        with self.assertRaisesRegex(
            InvestigationIntegrityError, "differs from verified report bytes"
        ):
            self.build(data)

    def test_legacy_partial_binding_is_unknown_not_verified(self):
        data, bundle = self.build(fixture(schema_version=1))
        gates = {item.name: item.status for item in bundle.gate_checks}
        self.assertEqual(gates["candidate_identity"], "unknown")
        self.assertEqual(gates["source_binding"], "partial")
        self.assertEqual(gates["source_integrity"], "met")
        self.assertEqual(
            bundle.facts[0].value["identity_recomputed"], False
        )

    def test_source_hash_mismatch_fails_closed(self):
        data = fixture()
        data["source"] = {**data["source"], "sha256": "f" * 64}
        with self.assertRaisesRegex(InvestigationIntegrityError, "source SHA-256"):
            self.build(data)

    def test_blob_mismatch_fails_closed(self):
        data = fixture()
        data["source"] = {**data["source"], "blob": "0" * 40}
        with self.assertRaisesRegex(InvestigationIntegrityError, "blob ID"):
            self.build(data)

    def test_report_hash_mismatch_fails_closed(self):
        data = fixture()
        data["report_sha"] = "e" * 64
        with self.assertRaisesRegex(InvestigationIntegrityError, "report bytes"):
            self.build(data)

    def test_unknown_candidate_id_is_rejected(self):
        data = fixture()
        data["candidate_id"] = "d" * 64
        with self.assertRaisesRegex(InvestigationIntegrityError, "candidate not found"):
            self.build(data)

    def test_missing_obligations_remain_unknown_not_empty_proof(self):
        data, bundle = self.build(fixture(with_obligations=False, analysis_status="partial"))
        self.assertEqual(bundle.obligation_inventory, "unknown")
        self.assertEqual(bundle.obligations, ())
        self.assertEqual(bundle.analysis_status, "partial")
        self.assertTrue(any("empty list" in item for item in bundle.limitations))
        gates = {item.name: item.status for item in bundle.gate_checks}
        self.assertEqual(gates["entry_reachability"], "unknown")
        self.assertEqual(gates["security_impact"], "unknown")

    def test_valid_supplemental_excerpt_is_fact_only(self):
        data = fixture()
        record = source_evidence_record(data)
        bundle = build_ipc_fact_bundle(
            report=data["report"],
            candidate_id=data["candidate_id"],
            candidate_record=data["candidate"],
            source=data["source"],
            report_sha256=data["report_sha"],
            report_bytes=data["report_bytes"],
            source_evidence=[record],
        )
        excerpts = [item for item in bundle.facts if item.kind == "source_excerpt"]
        self.assertEqual(len(excerpts), 1)
        self.assertEqual(excerpts[0].authority, "human")
        gates = {item.name: item.status for item in bundle.gate_checks}
        self.assertEqual(gates["entry_reachability"], "unknown")

    def test_tampered_supplemental_excerpt_is_rejected(self):
        data = fixture()
        record = source_evidence_record(data)
        record["text"] = "int Open(int changed) {\n"
        with self.assertRaisesRegex(InvestigationIntegrityError, "excerpt hash"):
            build_ipc_fact_bundle(
                report=data["report"],
                candidate_id=data["candidate_id"],
                candidate_record=data["candidate"],
                source=data["source"],
                report_sha256=data["report_sha"],
                report_bytes=data["report_bytes"],
                source_evidence=[record],
            )

    def test_bundle_without_raw_report_bytes_keeps_report_gate_unknown(self):
        _, bundle = self.build(fixture(include_report_bytes=False))
        gates = {item.name: item.status for item in bundle.gate_checks}
        self.assertEqual(gates["report_integrity"], "unknown")
        self.assertEqual(gates["source_integrity"], "met")


class DraftValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.bundle = build_ipc_fact_bundle(
            report=self.data["report"],
            candidate_id=self.data["candidate_id"],
            candidate_record=self.data["candidate"],
            source=self.data["source"],
            report_sha256=self.data["report_sha"],
            report_bytes=self.data["report_bytes"],
        )
        self.fact_id = self.bundle.facts[0].fact_id

    def draft(self):
        payload = valid_draft(self.data, self.fact_id)
        payload["input_context"]["fact_bundle_sha256"] = self.bundle.fact_bundle_sha256
        return payload

    def test_valid_human_draft_stays_draft_only(self):
        draft = validate_investigation_draft(self.draft(), self.bundle)
        self.assertEqual(draft.status, "draft_only")
        self.assertFalse(draft.can_promote)
        self.assertEqual(draft.claims[0]["status"], "draft")

    def test_unknown_claim_reference_is_rejected(self):
        payload = self.draft()
        payload["claims"][0]["evidence_refs"] = ["model-self"]
        with self.assertRaisesRegex(DraftValidationError, "unknown evidence"):
            validate_investigation_draft(payload, self.bundle)

    def test_model_producer_requires_complete_provenance(self):
        payload = self.draft()
        payload["producer"] = {"kind": "llm", "provider": "local"}
        with self.assertRaisesRegex(DraftValidationError, "requires"):
            validate_investigation_draft(payload, self.bundle)

    def test_model_provenance_is_complete_and_never_self_evidence(self):
        payload = self.draft()
        payload["producer"] = {
            "kind": "agent",
            "provider": "fixture-provider",
            "model": "fixture-model",
            "model_version": "v1",
            "prompt_sha256": "a" * 64,
            "tool_versions": {"source": "v1"},
            "parameters": {"temperature": 0},
            "failures": [],
            "retries": 0,
        }
        payload["claims"][0]["evidence_refs"] = [payload["draft_id"]]
        with self.assertRaisesRegex(DraftValidationError, "unknown evidence"):
            validate_investigation_draft(payload, self.bundle)

    def test_status_mutation_fields_are_rejected(self):
        payload = self.draft()
        payload["candidate_status"] = "confirmed"
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            validate_investigation_draft(payload, self.bundle)

    def test_promotion_flag_is_rejected(self):
        payload = self.draft()
        payload["can_promote"] = True
        with self.assertRaisesRegex(DraftValidationError, "promotion"):
            validate_investigation_draft(payload, self.bundle)

    def test_tool_budget_must_match_recorded_calls(self):
        payload = self.draft()
        payload["input_context"]["tool_call_ids"] = ["call-1"]
        with self.assertRaisesRegex(DraftValidationError, "tool-call budget"):
            validate_investigation_draft(payload, self.bundle)

    def test_append_only_identity_cannot_be_replaced(self):
        payload = self.draft()
        with self.assertRaisesRegex(DraftValidationError, "draft_id"):
            validate_investigation_draft(
                payload, self.bundle, draft_id="draft-2"
            )


if __name__ == "__main__":
    unittest.main()