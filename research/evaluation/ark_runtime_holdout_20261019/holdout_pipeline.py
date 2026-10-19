#!/usr/bin/env python3
"""Independent holdout freeze, double-blind review and adjudication pipeline.

The pipeline separates source intake, truth custody, reviewer packets and
adjudication. It refuses Precision/Recall unless the truth packet explicitly
declares reliable independent human labels and is not model-generated.

Governance hashes bind the contents of supplied artifacts; this module does
not authenticate external signatures, reviewer identities, custody, or Git
object-store claims. Those remain external prerequisites, never self-test proof.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

FREEZE_SCHEMA = "ohscanner.ark-holdout-freeze/v1"
INTAKE_SCHEMA = "ohscanner.ark-holdout-intake/v1"
TRUTH_SCHEMA = "ohscanner.ark-holdout-truth/v1"
REVIEW_SCHEMA = "ohscanner.ark-holdout-review/v1"
LOCK_SCHEMA = "ohscanner.ark-holdout-review-lock/v1"
ADJUDICATION_SCHEMA = "ohscanner.ark-holdout-adjudication/v2"
FINAL_SCHEMA = "ohscanner.ark-holdout-final-labels/v1"
PREREGISTRATION_SCHEMA = "ohscanner.ark-holdout-preregistration/v1"
LEAKAGE_LEDGER_SCHEMA = "ohscanner.ark-holdout-leakage-ledger/v1"
SOURCE_VERIFICATION_SCHEMA = "ohscanner.ark-holdout-source-verification/v1"
ALLOWED_LABELS = {"vulnerable_shape", "not_vulnerable_shape", "unknown"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^[0-9a-f]{40}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def object_hash_without(value: dict[str, Any], field: str) -> str:
    return payload_hash({key: item for key, item in value.items() if key != field})


def seal_artifact(schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    artifact = {"schema": schema, **payload}
    artifact["payload_sha256"] = payload_hash(artifact)
    return artifact


def has_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def normalized_identity(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return " ".join(value.casefold().split())


def normalized_family(value: Any) -> str | None:
    """Normalize only presentation differences; semantic family mapping is external."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().casefold()


def validate_sealed_artifact(value: Any, schema: str, name: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{name}_missing_or_invalid"]
    errors: list[str] = []
    if value.get("schema") != schema:
        errors.append(f"{name}_schema")
    digest = value.get("payload_sha256")
    if not has_sha256(digest):
        errors.append(f"{name}_payload_sha256")
    elif digest != object_hash_without(value, "payload_sha256"):
        errors.append(f"{name}_payload_hash_mismatch")
    return errors


def validate_freeze_manifest(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        return ["freeze_manifest_invalid"]
    errors: list[str] = []
    if manifest.get("schema") != FREEZE_SCHEMA:
        errors.append("freeze_manifest_schema")
    if manifest.get("status") != "FROZEN_PIPELINE_ONLY":
        errors.append("freeze_manifest_status")
    if not has_sha256(manifest.get("payload_sha256")) or manifest.get("payload_sha256") != object_hash_without(manifest, "payload_sha256"):
        errors.append("freeze_manifest_payload_hash")
    if not has_sha256(manifest.get("truth_commitment_sha256")):
        errors.append("freeze_manifest_truth_commitment")
    if not has_sha256(manifest.get("preregistration_sha256")) or not has_sha256(manifest.get("development_leakage_ledger_sha256")):
        errors.append("freeze_manifest_governance_hash")
    cases = manifest.get("case_pseudonyms")
    rows = manifest.get("public_case_rows")
    if not isinstance(cases, list) or not cases or any(not isinstance(item, str) or not item for item in cases):
        errors.append("freeze_manifest_case_set")
    elif len(set(cases)) != len(cases) or manifest.get("case_count") != len(cases):
        errors.append("freeze_manifest_case_set")
    if isinstance(cases, list) and isinstance(rows, list):
        row_ids = [row.get("case_pseudonym") for row in rows if isinstance(row, dict)]
        valid_row_ids = [item for item in row_ids if isinstance(item, str) and item]
        if len(valid_row_ids) != len(rows) or set(valid_row_ids) != set(cases) or len(rows) != len(cases):
            errors.append("freeze_manifest_public_case_rows")
        for row in rows:
            if not isinstance(row, dict):
                continue
            if not has_sha256(row.get("source_sha256")) or not has_sha256(row.get("source_identity_sha256")) or not has_sha256(row.get("profile_identity_sha256")):
                errors.append("freeze_manifest_case_identity_hash")
        packets = manifest.get("packet_payload_sha256")
        if not isinstance(packets, dict) or not has_sha256(packets.get("A")) or not has_sha256(packets.get("B")):
            errors.append("freeze_manifest_packet_hashes")
    else:
        errors.append("freeze_manifest_public_case_rows")
    return errors


def validate_blind_packets(manifest: dict[str, Any], packet_a: Any, packet_b: Any) -> list[str]:
    errors = validate_freeze_manifest(manifest)
    if not isinstance(packet_a, dict) or not isinstance(packet_b, dict):
        return errors + ["blind_packet_invalid"]
    allowed_fields = {"case_pseudonym", "source_text", "source_sha256", "question", "forbidden_context"}
    by_role = {"A": packet_a, "B": packet_b}
    case_ids = manifest.get("case_pseudonyms", [])
    expected_ids = set(case_ids) if isinstance(case_ids, list) and all(isinstance(item, str) for item in case_ids) else set()
    case_content: dict[str, dict[str, str]] = {}
    for role, packet in by_role.items():
        if packet.get("schema") != REVIEW_SCHEMA or packet.get("reviewer") != role:
            errors.append(f"blind_packet_role_or_schema:{role}")
        if payload_hash(packet) != manifest.get("packet_payload_sha256", {}).get(role):
            errors.append(f"blind_packet_hash_mismatch:{role}")
        rows = packet.get("cases")
        if not isinstance(rows, list):
            errors.append(f"blind_packet_cases_invalid:{role}")
            continue
        ids: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                errors.append(f"blind_packet_case_invalid:{role}")
                continue
            pseudo = row.get("case_pseudonym")
            ids.append(pseudo)
            if set(row) != allowed_fields:
                errors.append(f"blind_packet_context_fields:{role}")
            if not isinstance(row.get("source_text"), str) or not has_sha256(row.get("source_sha256")):
                errors.append(f"blind_packet_source_invalid:{role}")
            forbidden = row.get("forbidden_context")
            if not isinstance(forbidden, list) or any(not isinstance(item, str) for item in forbidden) or not {"true label", "case id", "source path", "parent/fixed pairing", "scanner verdict"}.issubset(set(forbidden)):
                errors.append(f"blind_packet_forbidden_context_missing:{role}")
            if isinstance(pseudo, str) and pseudo:
                case_content.setdefault(pseudo, {})[role] = payload_hash(row)
        valid_ids = [item for item in ids if isinstance(item, str) and item]
        if len(valid_ids) != len(ids) or len(valid_ids) != len(set(valid_ids)) or set(valid_ids) != expected_ids:
            errors.append(f"blind_packet_case_set:{role}")
    if any(set(roles) != {"A", "B"} or roles["A"] != roles["B"] for roles in case_content.values()):
        errors.append("blind_packets_content_mismatch")
    return errors


def validate_review_lock(lock: Any) -> list[str]:
    if not isinstance(lock, dict):
        return ["review_lock_invalid"]
    errors: list[str] = []
    if lock.get("schema") != LOCK_SCHEMA:
        errors.append("review_lock_schema")
    if not has_sha256(lock.get("payload_sha256")) or lock.get("payload_sha256") != object_hash_without(lock, "payload_sha256"):
        errors.append("review_lock_payload_hash")
    if not has_sha256(lock.get("freeze_payload_sha256")):
        errors.append("review_lock_freeze_hash")
    if not isinstance(lock.get("reviewer_identity"), str) or not lock["reviewer_identity"].strip():
        errors.append("review_lock_reviewer_identity")
    if lock.get("reviewer_role") not in {"reviewer_a", "reviewer_b"}:
        errors.append("review_lock_reviewer_role")
    expected_packet_role = {"reviewer_a": "A", "reviewer_b": "B"}.get(lock.get("reviewer_role"))
    if lock.get("reviewer") != expected_packet_role:
        errors.append("review_lock_packet_role")
    signature = lock.get("signature")
    if not isinstance(signature, dict) or not signature.get("scheme") or not signature.get("key_id") or not signature.get("value"):
        errors.append("review_lock_signature")
    if not has_sha256(lock.get("packet_sha256")) or not has_sha256(lock.get("attestation_sha256")) or not has_sha256(lock.get("submission_payload_sha256")):
        errors.append("review_lock_attestation")
    labels = lock.get("labels")
    if not isinstance(labels, list) or not labels:
        errors.append("review_lock_labels")
    else:
        ids: list[str] = []
        for row in labels:
            if not isinstance(row, dict):
                errors.append("review_lock_label_row")
                continue
            pseudo = row.get("case_pseudonym")
            ids.append(pseudo)
            if row.get("label") not in ALLOWED_LABELS or not row.get("rationale"):
                errors.append("review_lock_label_content")
        valid_ids = [item for item in ids if isinstance(item, str) and item]
        if len(valid_ids) != len(ids) or len(set(valid_ids)) != len(ids):
            errors.append("review_lock_case_set")
        if all(isinstance(row, dict) for row in labels):
            expected_attestation = payload_hash({
                "freeze_payload_sha256": lock.get("freeze_payload_sha256"),
                "packet_sha256": lock.get("packet_sha256"),
                "reviewer_identity": lock.get("reviewer_identity"),
                "reviewer_role": lock.get("reviewer_role"),
                "labels": labels,
            })
            if lock.get("attestation_sha256") != expected_attestation:
                errors.append("review_lock_attestation_mismatch")
    if not has_sha256(lock.get("truth_commitment_sha256")):
        errors.append("review_lock_truth_commitment")
    return errors


def validate_reviewer_pair(a: Any, b: Any) -> list[str]:
    errors = validate_review_lock(a) + validate_review_lock(b)
    if errors:
        return errors
    if a.get("freeze_payload_sha256") != b.get("freeze_payload_sha256"):
        errors.append("review_freeze_mismatch")
    if a.get("truth_commitment_sha256") != b.get("truth_commitment_sha256"):
        errors.append("review_truth_commitment_mismatch")
    if normalized_identity(a.get("reviewer_identity")) == normalized_identity(b.get("reviewer_identity")):
        errors.append("reviewer_identity_not_independent")
    if {a.get("reviewer_role"), b.get("reviewer_role")} != {"reviewer_a", "reviewer_b"}:
        errors.append("reviewer_role_separation")
    a_ids = [row.get("case_pseudonym") for row in a.get("labels", []) if isinstance(row, dict)]
    b_ids = [row.get("case_pseudonym") for row in b.get("labels", []) if isinstance(row, dict)]
    a_valid = [item for item in a_ids if isinstance(item, str) and item]
    b_valid = [item for item in b_ids if isinstance(item, str) and item]
    if len(a_valid) != len(a.get("labels", [])) or len(b_valid) != len(b.get("labels", [])) or set(a_valid) != set(b_valid):
        errors.append("review_pair_case_set_mismatch")
    return errors


def validate_adjudication_packet(packet: Any) -> list[str]:
    if not isinstance(packet, dict):
        return ["adjudication_packet_invalid"]
    errors: list[str] = []
    if packet.get("schema") != ADJUDICATION_SCHEMA:
        errors.append("adjudication_packet_schema")
    if not has_sha256(packet.get("freeze_payload_sha256")) or not has_sha256(packet.get("truth_commitment_sha256")):
        errors.append("adjudication_packet_freeze_binding")
    if not has_sha256(packet.get("payload_sha256")) or packet.get("payload_sha256") != object_hash_without(packet, "payload_sha256"):
        errors.append("adjudication_packet_payload_hash")
    agreements, disagreements = packet.get("agreements"), packet.get("disagreements")
    if not isinstance(agreements, list) or not isinstance(disagreements, list):
        errors.append("adjudication_packet_case_sets")
        return errors
    agree_ids = [row.get("case_pseudonym") for row in agreements if isinstance(row, dict)]
    disagree_ids = [row.get("case_pseudonym") for row in disagreements if isinstance(row, dict)]
    if len(agree_ids) != len(agreements) or len(disagree_ids) != len(disagreements):
        errors.append("adjudication_packet_case_rows")
    if not all(isinstance(item, str) and item for item in agree_ids + disagree_ids):
        errors.append("adjudication_packet_case_ids")
    valid_agree_ids = [item for item in agree_ids if isinstance(item, str) and item]
    valid_disagree_ids = [item for item in disagree_ids if isinstance(item, str) and item]
    if len(valid_agree_ids) != len(agree_ids) or len(valid_disagree_ids) != len(disagree_ids):
        errors.append("adjudication_packet_case_ids")
    if len(set(valid_agree_ids)) != len(agree_ids) or len(set(valid_disagree_ids)) != len(disagree_ids) or set(valid_agree_ids) & set(valid_disagree_ids):
        errors.append("adjudication_packet_case_sets")
    expected_ids = packet.get("case_pseudonyms")
    if not isinstance(expected_ids, list) or any(not isinstance(item, str) or not item for item in expected_ids):
        errors.append("adjudication_packet_expected_case_set")
    elif len(set(expected_ids)) != len(expected_ids) or set(expected_ids) != set(valid_agree_ids) | set(valid_disagree_ids):
        errors.append("adjudication_packet_full_case_set_mismatch")
    for row in agreements:
        if isinstance(row, dict) and (set(row) != {"case_pseudonym", "label", "route"}
                                      or row.get("label") not in ALLOWED_LABELS or row.get("route") != "agreement"):
            errors.append("adjudication_packet_agreement_schema")
    for row in disagreements:
        if not isinstance(row, dict):
            continue
        if set(row) != {"case_pseudonym", "opinions"}:
            errors.append("adjudication_packet_disagreement_schema")
            continue
        opinions = row.get("opinions")
        if (not isinstance(opinions, list) or len(opinions) != 2
                or any(not isinstance(opinion, dict) or set(opinion) != {"label", "rationale"}
                       or opinion.get("label") not in ALLOWED_LABELS
                       or not isinstance(opinion.get("rationale"), str) or not opinion["rationale"].strip()
                       for opinion in opinions)):
            errors.append("adjudication_packet_opinions_invalid")
        elif opinions != sorted(opinions, key=canonical_json_bytes):
            errors.append("adjudication_packet_opinion_order_not_anonymous")
    expected_status = "THIRD_REVIEW_REQUIRED" if disagreements else "AGREEMENT_COMPLETE"
    if packet.get("status") != expected_status:
        errors.append("adjudication_packet_status")
    return errors


def validate_final_labels(final: Any) -> list[str]:
    if not isinstance(final, dict):
        return ["final_labels_invalid"]
    errors: list[str] = []
    if final.get("schema") != FINAL_SCHEMA:
        errors.append("final_labels_schema")
    if final.get("status") != "FINAL_LABELS_AVAILABLE" or final.get("model_generated") is not False:
        errors.append("final_labels_status")
    if not has_sha256(final.get("payload_sha256")) or final.get("payload_sha256") != object_hash_without(final, "payload_sha256"):
        errors.append("final_labels_payload_hash")
    for field in ("freeze_payload_sha256", "truth_commitment_sha256", "adjudication_packet_sha256", "adjudication_submission_sha256"):
        if not has_sha256(final.get(field)):
            errors.append(f"final_labels_{field}")
    rows = final.get("labels")
    if not isinstance(rows, list) or not rows:
        errors.append("final_labels_case_set")
        return errors
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            errors.append("final_labels_row")
            continue
        pseudo = row.get("case_pseudonym")
        if not isinstance(pseudo, str) or not pseudo or pseudo in seen:
            errors.append("final_labels_duplicate_or_invalid_case")
        else:
            seen.add(pseudo)
        if row.get("label") not in ALLOWED_LABELS:
            errors.append("final_labels_invalid_label")
        if row.get("route") not in {"agreement", "third_review_adjudication"}:
            errors.append("final_labels_invalid_route")
    return errors


def git_blob_oid(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def validate_case_identity(case: dict[str, Any], data: bytes | None, synthetic: bool) -> list[str]:
    errors: list[str] = []
    identity = case.get("source_identity")
    profile = case.get("profile")
    case_id = case.get("case_id", "unknown")
    required_identity = ("repository", "commit", "tree", "path", "blob", "source_sha256")
    if not isinstance(identity, dict):
        errors.append(f"missing_source_identity:{case_id}")
    else:
        for field in required_identity:
            if not identity.get(field):
                errors.append(f"missing_source_identity_{field}:{case_id}")
        for field in ("commit", "tree", "blob"):
            value = identity.get(field)
            if not isinstance(value, str) or GIT_OID_RE.fullmatch(value) is None:
                errors.append(f"invalid_source_identity_{field}:{case_id}")
        if not has_sha256(identity.get("source_sha256")):
            errors.append(f"invalid_source_identity_source_sha256:{case_id}")
        if identity.get("path") != case.get("source_path"):
            errors.append(f"source_identity_path_mismatch:{case_id}")
        if data is not None:
            if identity.get("source_sha256") != sha256_bytes(data):
                errors.append(f"source_identity_sha256_mismatch:{case_id}")
            if identity.get("blob") != git_blob_oid(data):
                errors.append(f"source_identity_blob_mismatch:{case_id}")

    if not isinstance(profile, dict):
        errors.append(f"missing_profile_identity:{case_id}")
        return errors
    required_profile = ("detector_rule_version", "scope", "profile", "config_hash", "parser_identity", "toolchain_identity")
    for field in required_profile:
        if not profile.get(field):
            errors.append(f"missing_profile_{field}:{case_id}")
    if profile.get("config_hash") and not has_sha256(profile.get("config_hash")):
        errors.append(f"invalid_profile_config_hash:{case_id}")
    if isinstance(identity, dict) and not synthetic:
        if profile.get("source_identity_sha256") != payload_hash(identity):
            errors.append(f"profile_source_identity_mismatch:{case_id}")
        verification = case.get("source_verification")
        errors.extend(validate_sealed_artifact(verification, SOURCE_VERIFICATION_SCHEMA, f"source_verification:{case_id}"))
        if isinstance(verification, dict):
            if verification.get("verification_status") != "verified":
                errors.append(f"source_identity_not_verified:{case_id}")
            if verification.get("identity") != identity:
                errors.append(f"source_verification_identity_mismatch:{case_id}")
            if not verification.get("verifier") or not has_sha256(verification.get("evidence_sha256")):
                errors.append(f"source_verification_evidence_missing:{case_id}")
    if not synthetic:
        build = profile.get("product_build_preprocess")
        required_build = (
            "product_manifest", "exact_args_gn", "gn_target", "compile_commands_json",
            "actual_include_closure", "compiler_identity", "linker_identity", "sysroot_identity",
            "preprocessed_translation_units", "macro_expansion_log",
        )
        if not isinstance(build, dict) or build.get("status") != "COMPLETE":
            errors.append(f"product_build_profile_not_complete:{case_id}")
        else:
            for field in required_build:
                if not build.get(field):
                    errors.append(f"missing_product_profile_{field}:{case_id}")
    return errors


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def safe_relative(value: str) -> bool:
    if not isinstance(value, str):
        return False
    p = PurePosixPath(value)
    return (bool(value) and value not in {".", ".."} and not p.is_absolute()
            and ".." not in p.parts and "\\" not in value and ":" not in value
            and "\x00" not in value)


def read_evidence_bytes(evidence_root: Path | None, evidence_ref: Any, case_id: str) -> tuple[bytes | None, list[str]]:
    if evidence_root is None:
        return None, [f"leakage_evidence_root_missing:{case_id}"]
    if not isinstance(evidence_ref, str) or not safe_relative(evidence_ref):
        return None, [f"leakage_evidence_ref_unsafe:{case_id}"]
    root = evidence_root.resolve()
    candidate = root.joinpath(*PurePosixPath(evidence_ref).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, [f"leakage_evidence_missing:{case_id}"]
    if not resolved.is_relative_to(root):
        return None, [f"leakage_evidence_outside_root:{case_id}"]
    try:
        if not resolved.is_file():
            return None, [f"leakage_evidence_not_file:{case_id}"]
        return resolved.read_bytes(), []
    except OSError:
        return None, [f"leakage_evidence_unreadable:{case_id}"]


def source_leak_errors(data: bytes, case_id: str, source_path: str) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    errors: list[str] = []
    forbidden = {
        "case_id_in_source": case_id in text,
        "source_path_in_source": source_path in text,
        "url_in_source": bool(re.search(r"https?://", text, re.IGNORECASE)),
        "cve_identifier_in_source": bool(re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)),
        "issue_or_pull_reference_in_source": bool(re.search(r"(issues?/\d+|pulls?/\d+|![0-9]{3,})", text, re.IGNORECASE)),
    }
    errors.extend("source_metadata_leak:" + key for key, present in forbidden.items() if present)
    return errors

def pseudonym(secret: bytes, case_id: str) -> str:
    return hmac.new(secret, case_id.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def validate_intake(intake: dict[str, Any], truth: dict[str, Any], source_root: Path, evidence_root: Path | None = None) -> list[str]:
    if not isinstance(intake, dict) or not isinstance(truth, dict):
        return ["intake_or_truth_invalid"]
    errors: list[str] = []
    if intake.get("schema") != INTAKE_SCHEMA:
        errors.append("intake_schema")
    if truth.get("schema") != TRUTH_SCHEMA:
        errors.append("truth_schema")
    synthetic = intake.get("synthetic_fixture") is True
    if synthetic and truth.get("truth_status") != "pipeline_self_test_not_reliable":
        errors.append("synthetic_fixture_cannot_claim_reliable_truth")
    preregistration = intake.get("preregistration")
    ledger = intake.get("development_leakage_ledger")
    errors.extend(validate_sealed_artifact(preregistration, PREREGISTRATION_SCHEMA, "preregistration"))
    errors.extend(validate_sealed_artifact(ledger, LEAKAGE_LEDGER_SCHEMA, "development_leakage_ledger"))
    preregistration_obj = preregistration if isinstance(preregistration, dict) else {}
    ledger_obj = ledger if isinstance(ledger, dict) else {}
    if intake.get("preregistration_sha256") != preregistration_obj.get("payload_sha256"):
        errors.append("preregistration_sha256_mismatch")
    if intake.get("development_leakage_ledger_sha256") != ledger_obj.get("payload_sha256"):
        errors.append("development_leakage_ledger_sha256_mismatch")
    prereg = preregistration_obj.get("protocol", {})
    if not isinstance(prereg, dict):
        prereg = {}
        errors.append("preregistration_protocol_invalid")
    text_protocol_fields = ("target_population", "analysis_unit", "family_rule", "inclusion", "exclusion", "unknown_rule", "disagreement_rule", "estimate", "freeze_procedure")
    for field in text_protocol_fields:
        if not isinstance(prereg.get(field), str) or not prereg[field].strip():
            errors.append(f"preregistration_missing_{field}")
    if "sample_size" not in prereg:
        errors.append("preregistration_missing_sample_size")
    elif isinstance(prereg.get("sample_size"), bool) or not isinstance(prereg.get("sample_size"), int) or prereg.get("sample_size", 0) <= 0:
        errors.append("preregistration_sample_size_invalid")
    ledger_payload = ledger_obj.get("ledger", {})
    if not isinstance(ledger_payload, dict):
        ledger_payload = {}
        errors.append("development_leakage_ledger_payload_invalid")
    required_ledger_fields = (
        "development_source_sha256", "history_review_source_sha256",
        "development_family_keys", "history_review_family_keys", "cases",
    )
    for field in required_ledger_fields:
        if field not in ledger_payload:
            errors.append(f"leakage_ledger_missing_{field}")
    def string_set(value: Any, error_code: str) -> set[str]:
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            errors.append(error_code)
            return set()
        return set(value)

    forbidden_hashes = string_set(ledger_payload.get("development_source_sha256"), "leakage_development_hashes_invalid") | string_set(ledger_payload.get("history_review_source_sha256"), "leakage_history_hashes_invalid")
    if any(not has_sha256(item) for item in forbidden_hashes):
        errors.append("leakage_source_hash_invalid")
    dev_hashes = ledger_payload.get("development_source_sha256")
    history_hashes = ledger_payload.get("history_review_source_sha256")
    if (isinstance(dev_hashes, list) and isinstance(history_hashes, list)
            and len(forbidden_hashes) != len(dev_hashes) + len(history_hashes)):
        errors.append("leakage_source_hash_duplicate")
    forbidden_families_raw = string_set(ledger_payload.get("development_family_keys"), "leakage_development_families_invalid") | string_set(ledger_payload.get("history_review_family_keys"), "leakage_history_families_invalid")
    forbidden_families = {normalized_family(item) for item in forbidden_families_raw}
    if None in forbidden_families or any(not item.strip() for item in forbidden_families_raw):
        errors.append("leakage_family_key_invalid")
    cases = intake.get("cases", [])
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        return errors + ["intake_cases_invalid"]
    sample_size = prereg.get("sample_size")
    if isinstance(sample_size, bool) or not isinstance(sample_size, int) or sample_size != len(cases):
        errors.append("preregistration_sample_size_mismatch")
    labels = truth.get("labels", {})
    ids = [case.get("case_id") for case in cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in ids):
        errors.append("empty_case_id")
    valid_ids = [case_id for case_id in ids if isinstance(case_id, str) and case_id]
    if not cases:
        errors.append("empty_case_set")
    if not isinstance(labels, dict):
        errors.append("truth_labels_invalid")
        labels = {}
    if len(valid_ids) != len(set(valid_ids)):
        errors.append("duplicate_case_id")
    if set(valid_ids) != set(labels):
        errors.append("truth_case_set_mismatch")
    for case in cases:
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("empty_case_id")
            continue
        synthetic = intake.get("synthetic_fixture") is True
        if not synthetic and case.get("development_overlap") is not False:
            errors.append(f"development_overlap_not_false:{case_id}")
        if not case.get("selection_rule_id") or not has_sha256(case.get("sampling_frame_sha256")):
            errors.append(f"missing_selection_binding:{case_id}")
        source_path = case.get("source_path", "")
        if not safe_relative(source_path):
            errors.append(f"unsafe_source_path:{case_id}")
            continue
        resolved_root = source_root.resolve()
        path = source_root.joinpath(*PurePosixPath(source_path).parts)
        try:
            resolved_path = path.resolve(strict=True)
            if not resolved_path.is_relative_to(resolved_root):
                errors.append(f"source_path_outside_root:{case_id}")
                continue
            data = resolved_path.read_bytes()
        except OSError:
            errors.append(f"missing_source:{case_id}")
            continue
        digest = sha256_bytes(data)
        errors.extend(source_leak_errors(data, case_id, source_path))
        expected = case.get("source_sha256")
        if not has_sha256(expected):
            errors.append(f"missing_or_invalid_source_sha256:{case_id}")
        elif expected != digest:
            errors.append(f"source_sha256_mismatch:{case_id}")
        errors.extend(validate_case_identity(case, data, synthetic))
        family = case.get("root_cause_family")
        if not isinstance(family, str) or not family:
            errors.append(f"missing_root_cause_family:{case_id}")
        elif normalized_family(family) in forbidden_families:
            errors.append(f"development_or_history_family_overlap:{case_id}")
        if digest in forbidden_hashes:
            errors.append(f"development_or_history_source_overlap:{case_id}")
        if not synthetic:
            ledger_cases = ledger_payload.get("cases", {})
            ledger_row = ledger_cases.get(case_id, {}) if isinstance(ledger_cases, dict) else {}
            if not isinstance(ledger_row, dict):
                errors.append(f"leakage_case_not_cleared:{case_id}")
            else:
                if ledger_row.get("status") != "no_overlap":
                    errors.append(f"leakage_case_not_cleared:{case_id}")
                if (not isinstance(ledger_row.get("evidence_ref"), str) or not ledger_row["evidence_ref"].strip()
                        or not has_sha256(ledger_row.get("evidence_sha256"))):
                    errors.append(f"leakage_case_evidence_invalid:{case_id}")
                else:
                    evidence_bytes, evidence_errors = read_evidence_bytes(evidence_root, ledger_row.get("evidence_ref"), case_id)
                    errors.extend(evidence_errors)
                    if evidence_bytes is not None and sha256_bytes(evidence_bytes) != ledger_row.get("evidence_sha256"):
                        errors.append(f"leakage_case_evidence_sha256_mismatch:{case_id}")
                if (ledger_row.get("source_sha256") != digest
                        or normalized_family(ledger_row.get("root_cause_family")) != normalized_family(family)):
                    errors.append(f"leakage_case_identity_mismatch:{case_id}")
                if normalized_family(family) in forbidden_families or digest in forbidden_hashes:
                    errors.append(f"development_or_history_case_overlap:{case_id}")
        entry = labels.get(case_id, {})
        if not isinstance(entry, dict):
            errors.append(f"truth_label_row_invalid:{case_id}")
            continue
        if entry.get("label") not in ALLOWED_LABELS:
            errors.append(f"invalid_truth_label:{case_id}")
        if entry.get("model_generated") is not False:
            errors.append(f"truth_model_generated:{case_id}")
        if entry.get("root_cause_family") != family:
            errors.append(f"truth_family_mismatch:{case_id}")
    if not synthetic:
        ledger_cases = ledger_payload.get("cases", {})
        if not isinstance(ledger_cases, dict) or set(ledger_cases) != set(valid_ids):
            errors.append("leakage_ledger_case_set_mismatch")
    return errors


def freeze(args: argparse.Namespace) -> int:
    intake = load_json(args.cases)
    truth = load_json(args.truth)
    source_root = args.source_root.resolve()
    evidence_root = args.evidence_root.resolve() if getattr(args, "evidence_root", None) else None
    errors = validate_intake(intake, truth, source_root, evidence_root=evidence_root)
    if errors:
        raise SystemExit("freeze rejected: " + ", ".join(errors))
    secret = args.secret_file.read_bytes().strip()
    if not secret:
        raise SystemExit("empty custodian secret")
    cases = intake["cases"]
    rows = []
    packets = {}
    for case in cases:
        case_id = case["case_id"]
        data = source_root.joinpath(*PurePosixPath(case["source_path"]).parts).read_bytes()
        pseudo = pseudonym(secret, case_id)
        row = {
            "case_pseudonym": pseudo,
            "source_sha256": sha256_bytes(data),
            "source_bytes": len(data),
            "selection_rule_id": case["selection_rule_id"],
            "sampling_frame_sha256": case["sampling_frame_sha256"],
            "development_overlap": False,
            "source_identity_sha256": payload_hash(case["source_identity"]),
            "profile_identity_sha256": payload_hash(case["profile"]),
        }
        rows.append(row)
        packets[pseudo] = {
            "case_pseudonym": pseudo,
            "source_text": data.decode("utf-8", errors="replace"),
            "source_sha256": row["source_sha256"],
            "question": "Classify only the source shape. Use vulnerable_shape, not_vulnerable_shape, or unknown. Do not infer product exploitability.",
            "forbidden_context": ["true label", "case id", "source path", "parent/fixed pairing", "scanner verdict"],
        }
    rows.sort(key=lambda item: item["case_pseudonym"])
    public_packet = {"schema": REVIEW_SCHEMA, "reviewer": "A", "cases": [packets[row["case_pseudonym"]] for row in rows]}
    packet_b = {"schema": REVIEW_SCHEMA, "reviewer": "B", "cases": [packets[row["case_pseudonym"]] for row in reversed(rows)]}
    truth_commitment = payload_hash({"schema": truth["schema"], "labels": truth["labels"], "truth_status": truth.get("truth_status")})
    manifest = {
        "schema": FREEZE_SCHEMA,
        "status": "FROZEN_PIPELINE_ONLY",
        "truth_status": truth.get("truth_status"),
        "truth_commitment_sha256": truth_commitment,
        "preregistration_sha256": intake["preregistration_sha256"],
        "development_leakage_ledger_sha256": intake["development_leakage_ledger_sha256"],
        "case_count": len(rows),
        "case_pseudonyms": [row["case_pseudonym"] for row in rows],
        "public_case_rows": rows,
        "review_protocol": {
            "reviewers": 2,
            "reviewer_independence_required": True,
            "labels": sorted(ALLOWED_LABELS),
            "adjudicator": 1,
            "agreement_rule": "matching labels are accepted; disagreements require a third blind adjudication decision",
            "model_generated_truth_forbidden": True,
            "metrics_rule": "Precision/Recall is refused unless truth_status == reliable_independent_human_adjudicated",
        },
        "packet_payload_sha256": {
            "A": payload_hash(public_packet),
            "B": payload_hash(packet_b),
        },
    }
    manifest["payload_sha256"] = payload_hash(manifest)
    errors = validate_blind_packets(manifest, public_packet, packet_b)
    if errors:
        raise SystemExit("blind packet rejected: " + ", ".join(errors))
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "freeze_manifest.json", manifest)
    write_json(out / "reviewer_packet_A.json", public_packet)
    write_json(out / "reviewer_packet_B.json", packet_b)
    write_json(out / "truth_commitment.json", {"schema": "ohscanner.ark-holdout-truth-commitment/v1", "sha256": truth_commitment})
    write_json(out / "adjudication_template.json", {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": manifest["payload_sha256"],
        "adjudication_packet_sha256": "<packet payload SHA-256>",
        "adjudicator_identity": "<independent adjudicator identity>",
        "adjudicator_role": "adjudicator",
        "adjudicator_signature": {"scheme": "<externally verified scheme>", "key_id": "<key id>", "value": "<signature>"},
        "attestation_sha256": "<attestation payload SHA-256>",
        "decisions": [],
        "required_fields": [
            "freeze_payload_sha256", "adjudication_packet_sha256", "adjudicator_identity",
            "adjudicator_role", "adjudicator_signature", "attestation_sha256", "decisions",
            "case_pseudonym", "decision", "rationale",
        ],
    })
    print(json.dumps({"status": manifest["status"], "case_count": len(rows), "truth_status": manifest["truth_status"]}, indent=2))
    return 0


def validate_submission(freeze_manifest: dict[str, Any], packet: dict[str, Any], submission: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_freeze_manifest(freeze_manifest))
    if not isinstance(freeze_manifest, dict) or not isinstance(packet, dict) or not isinstance(submission, dict):
        return errors + ["review_packet_or_submission_invalid"]
    if errors:
        return errors
    if submission.get("schema") != REVIEW_SCHEMA:
        errors.append("submission_schema")
    if submission.get("packet_sha256") != payload_hash(packet):
        errors.append("packet_hash_mismatch")
    expected_packet_hashes = freeze_manifest.get("packet_payload_sha256", {})
    role_key = packet.get("reviewer")
    if role_key not in {"A", "B"} or expected_packet_hashes.get(role_key) != payload_hash(packet):
        errors.append("freeze_packet_hash_mismatch")
    reviewer = submission.get("reviewer_identity")
    role = submission.get("reviewer_role")
    expected_role = {"A": "reviewer_a", "B": "reviewer_b"}.get(packet.get("reviewer"))
    if not isinstance(reviewer, str) or not reviewer.strip():
        errors.append("reviewer_identity_missing")
    if role != expected_role:
        errors.append("reviewer_role_mismatch")
    signature = submission.get("signature")
    # Structural signature fields are a gate only; no PKI verifier or trusted
    # reviewer-key registry is implemented in this pipeline.
    if not isinstance(signature, dict) or not signature.get("scheme") or not signature.get("key_id") or not signature.get("value"):
        errors.append("reviewer_signature_missing_or_invalid")
    attestation = {
        "freeze_payload_sha256": freeze_manifest.get("payload_sha256"),
        "packet_sha256": payload_hash(packet),
        "reviewer_identity": reviewer,
        "reviewer_role": role,
        "labels": submission.get("labels", []),
    }
    if submission.get("attestation_sha256") != payload_hash(attestation):
        errors.append("reviewer_attestation_mismatch")
    expected = set(freeze_manifest["case_pseudonyms"])
    rows = submission.get("labels", [])
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            errors.append("review_label_row_invalid")
            continue
        pseudo = row.get("case_pseudonym")
        if not isinstance(pseudo, str) or pseudo not in expected or pseudo in seen:
            errors.append(f"bad_or_duplicate_case:{pseudo}")
            continue
        seen.add(pseudo)
        if row.get("label") not in ALLOWED_LABELS:
            errors.append(f"bad_label:{pseudo}")
        if not row.get("rationale"):
            errors.append(f"missing_rationale:{pseudo}")
    if seen != expected:
        errors.append("submission_case_set_mismatch")
    return errors


def lock_review(args: argparse.Namespace) -> int:
    freeze_manifest = load_json(args.freeze_manifest)
    packet = load_json(args.packet)
    submission = load_json(args.submission)
    errors = validate_submission(freeze_manifest, packet, submission)
    if errors:
        raise SystemExit("review rejected: " + ", ".join(errors))
    lock = {
        "schema": LOCK_SCHEMA,
        "freeze_payload_sha256": freeze_manifest["payload_sha256"],
        "reviewer": packet.get("reviewer"),
        "reviewer_identity": submission["reviewer_identity"],
        "reviewer_role": submission["reviewer_role"],
        "packet_sha256": payload_hash(packet),
        "signature": submission["signature"],
        "attestation_sha256": submission["attestation_sha256"],
        "truth_commitment_sha256": freeze_manifest["truth_commitment_sha256"],
        "submission_payload_sha256": payload_hash(submission),
        "labels": submission["labels"],
    }
    lock["payload_sha256"] = payload_hash(lock)
    write_json(args.output, lock)
    print(json.dumps({"status": "LOCKED", "reviewer": lock["reviewer"], "payload_sha256": lock["payload_sha256"]}, indent=2))
    return 0


def adjudicate(args: argparse.Namespace) -> int:
    a = load_json(args.review_a)
    b = load_json(args.review_b)
    errors = validate_reviewer_pair(a, b)
    if errors:
        raise SystemExit("review lock rejected: " + ", ".join(errors))
    a_rows = {row["case_pseudonym"]: row for row in a["labels"]}
    b_rows = {row["case_pseudonym"]: row for row in b["labels"]}
    if set(a_rows) != set(b_rows):
        raise SystemExit("review case set mismatch")
    agreements = []
    disagreements = []
    for pseudo in sorted(a_rows):
        left, right = a_rows[pseudo], b_rows[pseudo]
        if left["label"] == right["label"]:
            agreements.append({"case_pseudonym": pseudo, "label": left["label"], "route": "agreement"})
        else:
            opinions = [
                {"label": left["label"], "rationale": left["rationale"]},
                {"label": right["label"], "rationale": right["rationale"]},
            ]
            opinions.sort(key=canonical_json_bytes)
            disagreements.append({"case_pseudonym": pseudo, "opinions": opinions})
    out = {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": a["freeze_payload_sha256"],
        "truth_commitment_sha256": a.get("truth_commitment_sha256"),
        "case_pseudonyms": sorted(a_rows),
        "status": "THIRD_REVIEW_REQUIRED" if disagreements else "AGREEMENT_COMPLETE",
        "agreements": agreements,
        "disagreements": disagreements,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "agreements": len(agreements), "disagreements": len(disagreements)}, indent=2))
    return 0


def apply_adjudication(args: argparse.Namespace) -> int:
    packet = load_json(args.adjudication_packet)
    submission = load_json(args.adjudication_submission)
    packet_errors = validate_adjudication_packet(packet)
    if packet_errors:
        raise SystemExit("adjudication packet rejected: " + ", ".join(packet_errors))
    if not isinstance(submission, dict):
        raise SystemExit("adjudication submission invalid")
    if submission.get("schema") != ADJUDICATION_SCHEMA:
        raise SystemExit("adjudication submission schema rejected")
    if submission.get("freeze_payload_sha256") != packet.get("freeze_payload_sha256"):
        raise SystemExit("adjudication submission freeze mismatch")
    if submission.get("adjudication_packet_sha256") != packet.get("payload_sha256"):
        raise SystemExit("adjudication submission packet hash mismatch")
    adjudicator = submission.get("adjudicator_identity")
    signature = submission.get("adjudicator_signature")
    if not isinstance(adjudicator, str) or not adjudicator.strip() or submission.get("adjudicator_role") != "adjudicator":
        raise SystemExit("adjudicator identity or role rejected")
    if not isinstance(signature, dict) or not signature.get("scheme") or not signature.get("key_id") or not signature.get("value"):
        raise SystemExit("adjudicator signature missing or invalid")
    attestation = {
        "freeze_payload_sha256": packet["freeze_payload_sha256"],
        "adjudication_packet_sha256": packet["payload_sha256"],
        "adjudicator_identity": adjudicator,
        "adjudicator_role": "adjudicator",
        "decisions": submission.get("decisions", []),
    }
    if submission.get("attestation_sha256") != payload_hash(attestation):
        raise SystemExit("adjudicator attestation mismatch")
    decision_rows = submission.get("decisions", [])
    decisions: dict[str, dict[str, Any]] = {}
    for row in decision_rows:
        if not isinstance(row, dict):
            raise SystemExit("invalid adjudication decision row")
        pseudo = row.get("case_pseudonym")
        if not isinstance(pseudo, str) or pseudo in decisions:
            raise SystemExit("duplicate or invalid adjudication decision case")
        decisions[pseudo] = row
    expected_disagreements = {row["case_pseudonym"] for row in packet["disagreements"]}
    if set(decisions) != expected_disagreements:
        raise SystemExit("adjudication decision case set mismatch")
    final_rows = []
    for row in packet.get("agreements", []):
        final_rows.append({"case_pseudonym": row["case_pseudonym"], "label": row["label"], "route": "agreement"})
    for row in packet.get("disagreements", []):
        pseudo = row["case_pseudonym"]
        decision = decisions.get(pseudo)
        if not decision or decision.get("decision") not in ALLOWED_LABELS or not decision.get("rationale"):
            raise SystemExit(f"missing adjudication decision for {pseudo}")
        final_rows.append({"case_pseudonym": pseudo, "label": decision["decision"], "route": "third_review_adjudication"})
    out = {
        "schema": FINAL_SCHEMA,
        "freeze_payload_sha256": packet.get("freeze_payload_sha256"),
        "truth_commitment_sha256": packet.get("truth_commitment_sha256"),
        "adjudication_packet_sha256": packet.get("payload_sha256"),
        "adjudication_submission_sha256": payload_hash(submission),
        "status": "FINAL_LABELS_AVAILABLE",
        "labels": sorted(final_rows, key=lambda item: item["case_pseudonym"]),
        "model_generated": False,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "label_count": len(final_rows)}, indent=2))
    return 0


def validate_scoring_chain(freeze_manifest: Any, packet: Any, submission: Any, review_a: Any, review_b: Any, final: Any) -> list[str]:
    errors = validate_freeze_manifest(freeze_manifest) + validate_adjudication_packet(packet)
    errors.extend(validate_reviewer_pair(review_a, review_b))
    errors.extend(validate_final_labels(final))
    if errors:
        return errors
    if packet.get("freeze_payload_sha256") != freeze_manifest.get("payload_sha256"):
        errors.append("chain_adjudication_freeze_mismatch")
    if packet.get("truth_commitment_sha256") != freeze_manifest.get("truth_commitment_sha256"):
        errors.append("chain_adjudication_truth_mismatch")
    expected_cases = set(freeze_manifest["case_pseudonyms"])
    expected_packet_hashes = freeze_manifest.get("packet_payload_sha256", {})
    if review_a.get("reviewer_role") != "reviewer_a" or review_a.get("packet_sha256") != expected_packet_hashes.get("A"):
        errors.append("chain_reviewer_a_packet_mismatch")
    if review_b.get("reviewer_role") != "reviewer_b" or review_b.get("packet_sha256") != expected_packet_hashes.get("B"):
        errors.append("chain_reviewer_b_packet_mismatch")
    if set(packet.get("case_pseudonyms", [])) != expected_cases:
        errors.append("chain_adjudication_case_set_mismatch")
    if not isinstance(submission, dict) or submission.get("schema") != ADJUDICATION_SCHEMA:
        errors.append("chain_submission_schema")
        return errors
    if submission.get("freeze_payload_sha256") != freeze_manifest.get("payload_sha256"):
        errors.append("chain_submission_freeze_mismatch")
    if submission.get("adjudication_packet_sha256") != packet.get("payload_sha256"):
        errors.append("chain_submission_packet_mismatch")
    if final.get("freeze_payload_sha256") != freeze_manifest.get("payload_sha256"):
        errors.append("chain_final_freeze_mismatch")
    if final.get("truth_commitment_sha256") != freeze_manifest.get("truth_commitment_sha256"):
        errors.append("chain_final_truth_mismatch")
    if final.get("adjudication_packet_sha256") != packet.get("payload_sha256"):
        errors.append("chain_final_packet_mismatch")
    if final.get("adjudication_submission_sha256") != payload_hash(submission):
        errors.append("chain_final_submission_mismatch")
    adjudicator = submission.get("adjudicator_identity")
    if submission.get("adjudicator_role") != "adjudicator" or not isinstance(adjudicator, str) or not adjudicator.strip():
        errors.append("chain_adjudicator_identity_or_role")
    if not isinstance(submission.get("adjudicator_signature"), dict) or not all(submission["adjudicator_signature"].get(field) for field in ("scheme", "key_id", "value")):
        errors.append("chain_adjudicator_signature")
    expected_attestation = payload_hash({
        "freeze_payload_sha256": packet.get("freeze_payload_sha256"),
        "adjudication_packet_sha256": packet.get("payload_sha256"),
        "adjudicator_identity": adjudicator,
        "adjudicator_role": submission.get("adjudicator_role"),
        "decisions": submission.get("decisions", []),
    })
    if submission.get("attestation_sha256") != expected_attestation:
        errors.append("chain_adjudicator_attestation")

    def rows_by_id(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {row["case_pseudonym"]: row for row in lock["labels"]}

    a_rows, b_rows = rows_by_id(review_a), rows_by_id(review_b)
    if isinstance(adjudicator, str) and normalized_identity(adjudicator) in {
        normalized_identity(review_a.get("reviewer_identity")), normalized_identity(review_b.get("reviewer_identity"))
    }:
        errors.append("chain_adjudicator_not_independent")
    if set(a_rows) != expected_cases or set(b_rows) != expected_cases:
        errors.append("chain_review_case_set_mismatch")
        return errors
    expected_agreements = []
    expected_disagreements = []
    for pseudo in sorted(expected_cases):
        left, right = a_rows[pseudo], b_rows[pseudo]
        if left["label"] == right["label"]:
            expected_agreements.append({"case_pseudonym": pseudo, "label": left["label"], "route": "agreement"})
        else:
            opinions = [
                {"label": left["label"], "rationale": left["rationale"]},
                {"label": right["label"], "rationale": right["rationale"]},
            ]
            opinions.sort(key=canonical_json_bytes)
            expected_disagreements.append({"case_pseudonym": pseudo, "opinions": opinions})
    if packet.get("agreements") != expected_agreements or packet.get("disagreements") != expected_disagreements:
        errors.append("chain_adjudication_not_derived_from_reviews")

    decisions = submission.get("decisions")
    if not isinstance(decisions, list):
        errors.append("chain_adjudication_decisions_invalid")
        return errors
    decision_map: dict[str, dict[str, Any]] = {}
    for row in decisions:
        if not isinstance(row, dict):
            errors.append("chain_adjudication_decision_row")
            continue
        pseudo = row.get("case_pseudonym")
        if not isinstance(pseudo, str) or not pseudo or pseudo in decision_map:
            errors.append("chain_adjudication_decision_duplicate")
            continue
        decision_map[pseudo] = row
        if row.get("decision") not in ALLOWED_LABELS or not row.get("rationale"):
            errors.append("chain_adjudication_decision_content")
    disagreement_ids = {row["case_pseudonym"] for row in expected_disagreements}
    if set(decision_map) != disagreement_ids:
        errors.append("chain_adjudication_decision_case_set")
    expected_final: dict[str, tuple[str, str]] = {
        row["case_pseudonym"]: (row["label"], "agreement") for row in expected_agreements
    }
    for pseudo in disagreement_ids:
        row = decision_map.get(pseudo)
        if row and row.get("decision") in ALLOWED_LABELS:
            expected_final[pseudo] = (row["decision"], "third_review_adjudication")
    final_rows = final.get("labels", [])
    observed_final = {
        row["case_pseudonym"]: (row.get("label"), row.get("route"))
        for row in final_rows if isinstance(row, dict) and isinstance(row.get("case_pseudonym"), str)
    }
    if observed_final != expected_final or set(observed_final) != expected_cases:
        errors.append("chain_final_labels_not_derived")
    return errors


def score(args: argparse.Namespace) -> int:
    truth = load_json(args.truth)
    final = load_json(args.final_labels)
    final_errors = validate_final_labels(final)
    if final_errors:
        raise SystemExit("final labels rejected: " + ", ".join(final_errors))
    if not isinstance(truth, dict):
        raise SystemExit("truth packet invalid")
    if truth.get("truth_status") != "reliable_independent_human_adjudicated" or truth.get("model_generated") is not False:
        print(json.dumps({"status": "NOT_RUN", "reason": "truth is not reliable independent human adjudicated"}, indent=2))
        return 3
    chain_paths = ("freeze_manifest", "adjudication_packet", "adjudication_submission", "review_a_lock", "review_b_lock")
    if any(not getattr(args, field, None) for field in chain_paths):
        print(json.dumps({"status": "NOT_RUN", "reason": "complete freeze/review/adjudication chain is required"}, indent=2))
        return 3
    chain = [load_json(getattr(args, field)) for field in chain_paths]
    chain_errors = validate_scoring_chain(chain[0], chain[1], chain[2], chain[3], chain[4], final)
    if chain_errors:
        raise SystemExit("scoring chain rejected: " + ", ".join(chain_errors))
    if truth.get("schema") != TRUTH_SCHEMA or not isinstance(truth.get("labels"), dict) or not truth["labels"]:
        raise SystemExit("truth packet schema or labels rejected")
    truth_commitment = payload_hash({"schema": truth["schema"], "labels": truth["labels"], "truth_status": truth.get("truth_status")})
    if final.get("truth_commitment_sha256") != truth_commitment:
        raise SystemExit("truth commitment mismatch")
    for case_id, row in truth["labels"].items():
        if not isinstance(case_id, str) or not isinstance(row, dict) or row.get("label") not in ALLOWED_LABELS or row.get("model_generated") is not False:
            raise SystemExit("truth label schema rejected")
    secret = args.secret_file.read_bytes().strip()
    if not secret:
        raise SystemExit("empty truth pseudonym secret")
    labels = {pseudonym(secret, case_id): row for case_id, row in truth["labels"].items()}
    predicted = {row["case_pseudonym"]: row["label"] for row in final["labels"]}
    if set(predicted) != set(labels):
        raise SystemExit("final label case set does not match truth")
    matrix = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "unknown": 0}
    for pseudo, truth_row in labels.items():
        pred = predicted.get(pseudo, "unknown")
        true = truth_row["label"]
        if pred == "unknown" or true == "unknown":
            matrix["unknown"] += 1
        elif true == "vulnerable_shape" and pred == "vulnerable_shape":
            matrix["TP"] += 1
        elif true == "not_vulnerable_shape" and pred == "vulnerable_shape":
            matrix["FP"] += 1
        elif true == "vulnerable_shape" and pred == "not_vulnerable_shape":
            matrix["FN"] += 1
        else:
            matrix["TN"] += 1
    out = {"schema": "ohscanner.ark-holdout-score/v1", "status": "COMPLETE", "confusion_matrix": matrix}
    write_json(args.output, out)
    print(json.dumps(out, indent=2))
    return 0


def self_test(args: argparse.Namespace) -> int:
    work = args.work_dir.resolve()
    evaluation_root = Path(__file__).resolve().parent
    if work == evaluation_root or not work.is_relative_to(evaluation_root):
        raise SystemExit("self-test work-dir must be a child of the evaluation directory")
    if work.exists():
        shutil.rmtree(work)
    source_root = work / "sources"
    out = work / "frozen"
    source_root.mkdir(parents=True)
    cases = []
    labels = {}
    for index, label in enumerate(("vulnerable_shape", "not_vulnerable_shape", "unknown"), start=1):
        case_id = f"SELFTEST-{index}"
        source_path = f"case_{index}.cpp"
        source_bytes = f"// self-test source {index}\nint f_{index}(int x) {{ return x; }}\n".encode("utf-8")
        (source_root / source_path).write_bytes(source_bytes)
        source_digest = sha256_bytes(source_bytes)
        cases.append({
            "case_id": case_id,
            "source_path": source_path,
            "source_sha256": source_digest,
            "selection_rule_id": "selftest-synthetic",
            "sampling_frame_sha256": "0" * 64,
            "development_overlap": False,
            "root_cause_family": "synthetic",
            "source_identity": {
                "repository": "synthetic://selftest",
                "commit": f"{index:040x}",
                "tree": f"{index + 10:040x}",
                "path": source_path,
                "blob": git_blob_oid(source_bytes),
                "source_sha256": source_digest,
            },
            "profile": {
                "detector_rule_version": "synthetic-1",
                "scope": "synthetic",
                "profile": "synthetic-selftest",
                "config_hash": sha256_bytes(b"synthetic-config"),
                "parser_identity": "synthetic-parser",
                "toolchain_identity": "synthetic-toolchain",
                "source_identity_sha256": "synthetic-only",
            },
        })
        labels[case_id] = {"label": label, "model_generated": False, "root_cause_family": "synthetic"}
    preregistration = seal_artifact(PREREGISTRATION_SCHEMA, {"protocol": {
        "target_population": "synthetic-only", "analysis_unit": "synthetic-source-file", "family_rule": "one synthetic family",
        "sample_size": len(cases), "inclusion": "generated fixture", "exclusion": "none",
        "unknown_rule": "retain unknown", "disagreement_rule": "third synthetic review",
        "estimate": "none", "freeze_procedure": "pipeline self-test only",
    }})
    leakage_ledger = seal_artifact(LEAKAGE_LEDGER_SCHEMA, {"ledger": {
        "development_source_sha256": [], "history_review_source_sha256": [],
        "development_family_keys": [], "history_review_family_keys": [], "cases": {},
    }})
    intake = {
        "schema": INTAKE_SCHEMA, "synthetic_fixture": True,
        "preregistration": preregistration, "preregistration_sha256": preregistration["payload_sha256"],
        "development_leakage_ledger": leakage_ledger,
        "development_leakage_ledger_sha256": leakage_ledger["payload_sha256"], "cases": cases,
    }
    truth = {"schema": TRUTH_SCHEMA, "truth_status": "pipeline_self_test_not_reliable", "model_generated": False, "labels": labels}
    secret_file = work / "selftest-secret.txt"
    secret_file.write_text("self-test-secret-not-for-real-holdout\n", encoding="utf-8")
    write_json(work / "intake.json", intake)
    write_json(work / "truth.json", truth)
    freeze_ns = argparse.Namespace(cases=work / "intake.json", truth=work / "truth.json", source_root=source_root, output_dir=out, secret_file=secret_file)
    freeze(freeze_ns)
    manifest = load_json(out / "freeze_manifest.json")
    packet_a = load_json(out / "reviewer_packet_A.json")
    packet_b = load_json(out / "reviewer_packet_B.json")
    a_rows, b_rows = [], []
    for idx, pseudo in enumerate(manifest["case_pseudonyms"]):
        a_label = "vulnerable_shape" if idx == 0 else "not_vulnerable_shape"
        b_label = "unknown" if idx == 0 else a_label
        a_rows.append({"case_pseudonym": pseudo, "label": a_label, "rationale": "self-test reviewer A"})
        b_rows.append({"case_pseudonym": pseudo, "label": b_label, "rationale": "self-test reviewer B"})
    sub_a = {"schema": REVIEW_SCHEMA, "packet_sha256": payload_hash(packet_a), "reviewer_identity": "synthetic-reviewer-a", "reviewer_role": "reviewer_a", "signature": {"scheme": "synthetic-test-only", "key_id": "test-a", "value": "not-a-real-signature"}, "labels": a_rows}
    sub_b = {"schema": REVIEW_SCHEMA, "packet_sha256": payload_hash(packet_b), "reviewer_identity": "synthetic-reviewer-b", "reviewer_role": "reviewer_b", "signature": {"scheme": "synthetic-test-only", "key_id": "test-b", "value": "not-a-real-signature"}, "labels": b_rows}
    for submission, packet, role_key in ((sub_a, packet_a, "A"), (sub_b, packet_b, "B")):
        submission["attestation_sha256"] = payload_hash({
            "freeze_payload_sha256": manifest["payload_sha256"],
            "packet_sha256": payload_hash(packet),
            "reviewer_identity": submission["reviewer_identity"],
            "reviewer_role": submission["reviewer_role"],
            "labels": submission["labels"],
        })
    write_json(work / "review_A.json", sub_a)
    write_json(work / "review_B.json", sub_b)
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_A.json", submission=work / "review_A.json", output=out / "review_A.lock.json"))
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_B.json", submission=work / "review_B.json", output=out / "review_B.lock.json"))
    adjudicate(argparse.Namespace(review_a=out / "review_A.lock.json", review_b=out / "review_B.lock.json", output=out / "adjudication_packet.json"))
    packet = load_json(out / "adjudication_packet.json")
    decisions = [{"case_pseudonym": row["case_pseudonym"], "decision": "vulnerable_shape", "rationale": "self-test adjudicator"} for row in packet["disagreements"]]
    adjudication_submission = {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": packet["freeze_payload_sha256"],
        "adjudication_packet_sha256": packet["payload_sha256"],
        "adjudicator_identity": "synthetic-adjudicator",
        "adjudicator_role": "adjudicator",
        "adjudicator_signature": {"scheme": "synthetic-test-only", "key_id": "test-adjudicator", "value": "not-a-real-signature"},
        "decisions": decisions,
    }
    adjudication_submission["attestation_sha256"] = payload_hash({
        "freeze_payload_sha256": adjudication_submission["freeze_payload_sha256"],
        "adjudication_packet_sha256": adjudication_submission["adjudication_packet_sha256"],
        "adjudicator_identity": adjudication_submission["adjudicator_identity"],
        "adjudicator_role": adjudication_submission["adjudicator_role"],
        "decisions": adjudication_submission["decisions"],
    })
    write_json(work / "adjudication_submission.json", adjudication_submission)
    apply_adjudication(argparse.Namespace(adjudication_packet=out / "adjudication_packet.json", adjudication_submission=work / "adjudication_submission.json", output=out / "final_labels.json"))
    result = {"schema": "ohscanner.ark-holdout-selftest/v1", "status": "PASS", "metrics_computed": False, "reason": "synthetic self-test truth is not reliable independent human truth"}
    write_json(work / "selftest-validation.json", result)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("freeze")
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--truth", type=Path, required=True)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--evidence-root", type=Path, help="Root containing readable leakage-evidence bytes referenced by ledger cases")
    p.add_argument("--secret-file", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.set_defaults(func=freeze)
    p = sub.add_parser("lock-review")
    p.add_argument("--freeze-manifest", type=Path, required=True)
    p.add_argument("--packet", type=Path, required=True)
    p.add_argument("--submission", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=lock_review)
    p = sub.add_parser("adjudicate")
    p.add_argument("--review-a", type=Path, required=True)
    p.add_argument("--review-b", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=adjudicate)
    p = sub.add_parser("apply-adjudication")
    p.add_argument("--adjudication-packet", type=Path, required=True)
    p.add_argument("--adjudication-submission", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=apply_adjudication)
    p = sub.add_parser("score")
    p.add_argument("--truth", type=Path, required=True)
    p.add_argument("--final-labels", type=Path, required=True)
    p.add_argument("--secret-file", type=Path, required=True)
    p.add_argument("--freeze-manifest", type=Path)
    p.add_argument("--adjudication-packet", type=Path)
    p.add_argument("--adjudication-submission", type=Path)
    p.add_argument("--review-a-lock", type=Path)
    p.add_argument("--review-b-lock", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=score)
    p = sub.add_parser("self-test")
    p.add_argument("--work-dir", type=Path, required=True)
    p.set_defaults(func=self_test)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
