#!/usr/bin/env python3
"""Fail-closed source-audit reconciliation scaffold.

Standard library only. This script never executes a scanner, never computes
precision/recall, and never turns missing/unknown evidence into a verdict.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[3]
INPUT_MANIFEST = BASE / "input-manifest.json"
SCHEMA = BASE / "audit-schema.json"
KNOWN = BASE / "known-source-findings.json"
REGRESSIONS = BASE / "expected-regressions.json"
RUN_MANIFEST = BASE / "run-manifest.json"
SELF_TEST_RESULT = BASE / "fail-closed-self-test.json"
MINIMAL_PATCH = BASE / "minimal-patch.diff"
EXPECTED_BASE = "7af25f5ced471e5d6acc8cf5efd4c696275ce940"
EXPECTED_BASE_TREE = "11f53fe00d79d477c383e7e9b49ad3b1adcae86c"

CONTROL_KINDS = {"positive", "fixed", "safe", "unrelated", "unknown"}
CLASSIFICATIONS = {"candidate", "unknown", "confirmed", "reportable"}
IDENTITY_STATUSES = {"verified_local", "recorded_external", "unknown", "missing_input"}
FACT_STATUSES = {"provisional_substitute_evidence", "source_fact", "unknown"}
DETECTOR_RULES = {
    "ohscanner.ark.runtime.type_safety": {
        "ark.runtime.typedarray-store-type-origin",
        "ark.runtime.typedarray-allocation-exception-guard",
    },
    "ohscanner.cpp.path_traversal": {
        "ohcpp-path-traversal-candidate-001",
    },
}
UNKNOWN = "unknown"

BLOCK_EXIT_CODES = {
    "input_missing": 10,
    "input_no_supported_entries": 11,
    "input_schema_invalid": 12,
    "input_hash_mismatch": 13,
    "input_manifest_unbound": 14,
    "configuration_invalid": 20,
    "worktree_identity_mismatch": 21,
}
BLOCK_STATUS = {
    "input_missing": "blocked_missing_input",
    "input_no_supported_entries": "blocked_no_entries",
    "input_schema_invalid": "blocked_schema_invalid",
    "input_hash_mismatch": "blocked_hash_mismatch",
    "input_manifest_unbound": "blocked_hash_unbound",
    "configuration_invalid": "blocked_configuration_invalid",
    "worktree_identity_mismatch": "blocked_worktree_identity",
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def normalized_git_blob_sha1(data: bytes) -> str:
    return git_blob_sha1(data.replace(b"\r\n", b"\n"))


def is_unknown(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() == UNKNOWN


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def hex_len(value: Any, length: int) -> bool:
    return nonempty_string(value) and len(value) == length and re.fullmatch(r"[0-9a-fA-F]+", value) is not None


def run_git(args: list[str], binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO,
        text=not binary,
        capture_output=True,
        check=False,
    )


def git_value(args: list[str]) -> str | None:
    try:
        proc = run_git(args)
    except (FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def git_object_bytes(git_object: str) -> bytes | None:
    if not nonempty_string(git_object) or ":" not in git_object:
        return None
    try:
        proc = run_git(["cat-file", "blob", git_object], binary=True)
    except (FileNotFoundError, OSError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def local_artifact(path_value: str) -> Path | None:
    p = Path(path_value)
    if p.is_absolute():
        return p
    return REPO / p


def verify_recorded_bytes(
    data: bytes,
    recorded_sha: Any,
    recorded_blob: Any,
    errors: list[str],
    label: str,
    location: str,
) -> None:
    actual_sha = sha256_bytes(data)
    actual_blobs = {git_blob_sha1(data), normalized_git_blob_sha1(data)}
    if is_unknown(recorded_sha):
        errors.append(f"{label}: {location} has no recorded SHA-256")
    elif not nonempty_string(recorded_sha) or recorded_sha.lower() != actual_sha:
        errors.append(f"{label}: SHA-256 mismatch for {location}")
    if is_unknown(recorded_blob):
        errors.append(f"{label}: {location} has no recorded Git blob")
    elif not nonempty_string(recorded_blob) or recorded_blob.lower() not in actual_blobs:
        errors.append(f"{label}: Git blob mismatch for {location}")

def verify_artifact(art: dict[str, Any], errors: list[str], label: str) -> None:
    for key in ("role", "path", "sha256", "git_blob"):
        if key not in art or not nonempty_string(art[key]):
            errors.append(f"{label}: artifact.{key} must be non-empty or explicit unknown")
    pinned_object = art.get("git_object")
    if nonempty_string(pinned_object):
        data = git_object_bytes(pinned_object)
        if data is None:
            errors.append(f"{label}: recorded Git object is unavailable: {pinned_object}")
            return
        verify_recorded_bytes(data, art.get("sha256"), art.get("git_blob"), errors, label, pinned_object)
        return

    path_value = art.get("path")
    if nonempty_string(path_value):
        p = local_artifact(path_value)
        if p is not None and p.exists():
            if not p.is_file():
                if not is_unknown(art.get("sha256")) or not is_unknown(art.get("git_blob")):
                    errors.append(f"{label}: directory artifact must carry explicit unknown SHA-256 and Git blob")
            else:
                verify_recorded_bytes(p.read_bytes(), art.get("sha256"), art.get("git_blob"), errors, label, str(path_value))
                return

    git_object = art.get("git_object")
    if nonempty_string(git_object):
        data = git_object_bytes(git_object)
        if data is None:
            errors.append(f"{label}: recorded Git object is unavailable: {git_object}")
            return
        verify_recorded_bytes(data, art.get("sha256"), art.get("git_blob"), errors, label, git_object)
        return

    if not is_unknown(art.get("sha256")) or not is_unknown(art.get("git_blob")):
        errors.append(f"{label}: missing artifact path must carry explicit unknown SHA-256 and Git blob unless git_object is bound")


def validate_source_identity(sid: Any, label: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(sid, dict):
        return [f"{label}: source identity must be object"]
    for key in ("repository", "path", "commit", "tree", "blob", "sha256", "identity_status"):
        if key not in sid or not nonempty_string(sid[key]):
            errors.append(f"{label}.{key} must be non-empty or explicit unknown")
    if sid.get("identity_status") not in IDENTITY_STATUSES:
        errors.append(f"{label}: invalid identity_status")
    for key, length in (("commit", 40), ("tree", 40), ("blob", 40)):
        value = sid.get(key)
        if not is_unknown(value) and not hex_len(value, length):
            errors.append(f"{label}.{key} must be 40-hex or unknown")
    if not is_unknown(sid.get("sha256")) and not hex_len(sid.get("sha256"), 64):
        errors.append(f"{label}.sha256 must be 64-hex or unknown")
    return errors


def validate_entry(entry: Any, controls: dict[str, dict[str, Any]], label: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(entry, dict):
        return [f"{label}: entry must be an object"]
    required = (
        "schema_version", "entry_id", "observation", "mapping",
        "controls", "evidence_gate", "artifacts", "claim_boundary",
    )
    for key in required:
        if key not in entry:
            errors.append(f"{label}: missing {key}")
    has_single = isinstance(entry.get("source_identity"), dict)
    has_multi = isinstance(entry.get("source_identities"), list) and bool(entry.get("source_identities"))
    if not has_single and not has_multi:
        errors.append(f"{label}: source_identity or non-empty source_identities is required")
    if errors:
        return errors
    if entry["schema_version"] != "ohscanner.source-audit-entry/v2":
        errors.append(f"{label}: schema_version must be source-bound v2")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,128}", str(entry["entry_id"])):
        errors.append(f"{label}: invalid entry_id")

    if has_single:
        errors.extend(validate_source_identity(entry["source_identity"], f"{label}.source_identity"))
    if has_multi:
        for i, sid in enumerate(entry["source_identities"]):
            errors.extend(validate_source_identity(sid, f"{label}.source_identities[{i}]"))
        identity_keys = [
            (sid.get("repository"), sid.get("path"), sid.get("commit"), sid.get("sha256"))
            for sid in entry["source_identities"]
            if isinstance(sid, dict)
        ]
        if len(identity_keys) != len(set(identity_keys)):
            errors.append(f"{label}: source_identities contains duplicate identity tuples")

    obs = entry["observation"]
    if not isinstance(obs, dict):
        errors.append(f"{label}: observation must be object")
    else:
        for key in ("summary", "scope"):
            if not nonempty_string(obs.get(key)):
                errors.append(f"{label}: observation.{key} must be non-empty")
        if obs.get("fact_status") not in FACT_STATUSES:
            errors.append(f"{label}: invalid observation.fact_status")
        if not isinstance(obs.get("limitations"), list) or not obs["limitations"] or not all(nonempty_string(x) for x in obs["limitations"]):
            errors.append(f"{label}: observation.limitations must be a non-empty string array")

    mapping = entry["mapping"]
    if not isinstance(mapping, dict):
        errors.append(f"{label}: mapping must be object")
    else:
        for key in ("detector_ids", "rule_ids", "control_ids"):
            values = mapping.get(key)
            if not isinstance(values, list) or not values or not all(nonempty_string(x) for x in values):
                errors.append(f"{label}: mapping.{key} must be a non-empty string array")
        detector_ids = mapping.get("detector_ids", [])
        rule_ids = mapping.get("rule_ids", [])
        for detector in detector_ids:
            if detector not in DETECTOR_RULES:
                errors.append(f"{label}: unknown detector_id {detector}")
        for rule in rule_ids:
            allowed_by = {d for d, rules in DETECTOR_RULES.items() if rule in rules}
            if not allowed_by:
                errors.append(f"{label}: unknown rule_id {rule}")
        if detector_ids and rule_ids and not any(rule in DETECTOR_RULES.get(detector, set()) for detector in detector_ids for rule in rule_ids):
            errors.append(f"{label}: mapping detector/rule pair is not registered in this reconciliation catalog")
        if mapping.get("mapping_status") not in {None, "mapped", "partial_mapping", "unknown"}:
            errors.append(f"{label}: invalid mapping.mapping_status")

    control_rows = entry["controls"]
    if not isinstance(control_rows, list) or not control_rows:
        errors.append(f"{label}: controls must be a non-empty array")
    else:
        seen: set[str] = set()
        for row in control_rows:
            if not isinstance(row, dict):
                errors.append(f"{label}: control row must be object")
                continue
            cid = row.get("control_id")
            if not nonempty_string(cid):
                errors.append(f"{label}: control_id must be non-empty")
                continue
            seen.add(cid)
            catalog = controls.get(cid)
            if catalog is None:
                errors.append(f"{label}: unmapped control_id {cid}")
            elif row.get("kind") != catalog.get("kind"):
                errors.append(f"{label}: control kind mismatch for {cid}")
            if row.get("kind") not in CONTROL_KINDS:
                errors.append(f"{label}: invalid control kind for {cid}")
            if not nonempty_string(row.get("expected")):
                errors.append(f"{label}: control.expected must be non-empty")
        mapped_controls = set(mapping.get("control_ids", [])) if isinstance(mapping, dict) else set()
        if mapped_controls != seen:
            errors.append(f"{label}: mapping.control_ids must exactly match controls rows")

    gate = entry["evidence_gate"]
    if not isinstance(gate, dict):
        errors.append(f"{label}: evidence_gate must be object")
    else:
        for key in ("entry_or_permission_boundary", "reachable_sensitive_operation", "trigger_condition", "cia_impact", "audit_evidence"):
            if not nonempty_string(gate.get(key)):
                errors.append(f"{label}: evidence_gate.{key} must be non-empty or explicit unknown")
        if not isinstance(gate.get("validated_vulnerability"), bool):
            errors.append(f"{label}: evidence_gate.validated_vulnerability must be boolean")

    arts = entry["artifacts"]
    if not isinstance(arts, list) or not arts:
        errors.append(f"{label}: artifacts must be a non-empty array")
    else:
        for i, art in enumerate(arts):
            if isinstance(art, dict):
                verify_artifact(art, errors, f"{label}.artifacts[{i}]")
            else:
                errors.append(f"{label}.artifacts[{i}] must be object")

    claim = entry["claim_boundary"]
    if not isinstance(claim, dict):
        errors.append(f"{label}: claim_boundary must be object")
    else:
        for key in ("product_vulnerability", "cia", "cve", "metrics"):
            if not isinstance(claim.get(key), bool):
                errors.append(f"{label}: claim_boundary.{key} must be boolean")
        if "cwe" in claim and not isinstance(claim.get("cwe"), bool):
            errors.append(f"{label}: claim_boundary.cwe must be boolean when present")
        if claim.get("classification") not in CLASSIFICATIONS:
            errors.append(f"{label}: invalid claim_boundary.classification")
        if claim.get("assessment_status") not in {"unassessed", "assessed"}:
            errors.append(f"{label}: invalid claim_boundary.assessment_status")
        if claim.get("metrics") is not False:
            errors.append(f"{label}: metrics claims are not permitted by this reconciliation scaffold")
        if claim.get("classification") in {"candidate", "unknown"}:
            for key in ("product_vulnerability", "cia", "cwe", "cve"):
                if key in claim and claim.get(key) is not False:
                    errors.append(f"{label}: candidate/unknown cannot assert product vulnerability, CIA, CWE or CVE")
        if obs.get("fact_status") == "provisional_substitute_evidence":
            if claim.get("classification") not in {"candidate", "unknown"}:
                errors.append(f"{label}: substitute evidence cannot be classified confirmed/reportable")
            if gate.get("validated_vulnerability") is not False:
                errors.append(f"{label}: substitute evidence cannot set validated_vulnerability=true")
        if gate.get("validated_vulnerability") is True:
            if claim.get("classification") not in {"confirmed", "reportable"}:
                errors.append(f"{label}: validated_vulnerability requires confirmed/reportable classification")
            for key in ("entry_or_permission_boundary", "reachable_sensitive_operation", "trigger_condition", "cia_impact"):
                if is_unknown(gate.get(key)):
                    errors.append(f"{label}: confirmed/reportable requires concrete {key}")
    return errors

def load_controls(known: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in known.get("mapping_catalog", {}).get("controls", []):
        if isinstance(row, dict) and nonempty_string(row.get("control_id")):
            result[row["control_id"]] = row
    return result


def validate_known(known: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    errors: list[str] = []
    controls = load_controls(known)
    if known.get("schema_version") != "c8.source-audit.known-source-findings/v1":
        errors.append("known-source-findings: schema_version mismatch")
    if not isinstance(known.get("findings"), list):
        errors.append("known-source-findings: findings must be array")
        return errors, controls
    policy = known.get("evidence_policy", {})
    for key in ("product_vulnerability_claim", "cia_claim", "cwe_claim", "cve_claim", "precision_recall_claim", "fp_fn_claim"):
        if policy.get(key) != "not_asserted":
            errors.append(f"known-source-findings: {key} must remain not_asserted")
    if policy.get("scanner_execution") is not False:
        errors.append("known-source-findings: scanner_execution must be false")
    ids: set[str] = set()
    for i, entry in enumerate(known["findings"]):
        label = f"known-source-findings.findings[{i}]"
        errors.extend(validate_entry(entry, controls, label))
        entry_id = entry.get("entry_id") if isinstance(entry, dict) else None
        if nonempty_string(entry_id):
            if entry_id in ids:
                errors.append(f"{label}: duplicate entry_id {entry_id}")
            ids.add(entry_id)
    return errors, controls


def validate_regressions(reg: dict[str, Any], known: dict[str, Any], controls: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if reg.get("schema_version") != "c8.source-audit.expected-regressions/v1":
        errors.append("expected-regressions: schema_version mismatch")
    if reg.get("scanner_execution") is not False or reg.get("metrics_allowed") is not False:
        errors.append("expected-regressions: scanner_execution/metrics_allowed must be false")
    required = set(reg.get("required_coverage", []))
    expected_required = {
        "type_origin_six_counterexamples", "guard_before", "guard_after", "guard_unknown",
        "partial_owner_fail_closed", "historical_object_missing",
        "a_path_source_to_sink_controls", "a_sample30_substitute_evidence",
    }
    if required != expected_required:
        errors.append("expected-regressions: required_coverage must be exactly the fail-closed suite")
    families = reg.get("families")
    if not isinstance(families, list):
        return errors + ["expected-regressions: families must be array"]
    family_ids = {f.get("family_id") for f in families if isinstance(f, dict)}
    for needed in expected_required:
        if needed in {"guard_before", "guard_after", "guard_unknown"}:
            if "exception_guard_order" not in family_ids:
                errors.append("expected-regressions: missing exception_guard_order family")
        elif needed not in family_ids and needed != "type_origin_six_counterexamples":
            errors.append(f"expected-regressions: missing family {needed}")
    if "type_origin_six_counterexamples" not in family_ids:
        errors.append("expected-regressions: missing type_origin_six_counterexamples family")
    known_ids = {x.get("entry_id") for x in known.get("findings", []) if isinstance(x, dict)}
    case_count = 0
    for family in families:
        if not isinstance(family, dict):
            errors.append("expected-regressions: family must be object")
            continue
        if not nonempty_string(family.get("family_id")) or not nonempty_string(family.get("rule_id")):
            errors.append("expected-regressions: family_id/rule_id must be non-empty")
        if family.get("rule_id") not in {rule for rules in DETECTOR_RULES.values() for rule in rules}:
            errors.append(f"expected-regressions: unknown family rule_id {family.get('rule_id')}")
        for case in family.get("cases", []):
            case_count += 1
            label = f"regression {family.get('family_id')}.{case.get('case_id')}"
            if not isinstance(case, dict):
                errors.append(f"{label}: case must be object")
                continue
            for key in ("case_id", "expected", "control_id"):
                if not nonempty_string(case.get(key)):
                    errors.append(f"{label}: missing {key}")
            if case.get("control_id") not in controls:
                errors.append(f"{label}: unknown control_id")
            if nonempty_string(case.get("source_sha256")) and not hex_len(case["source_sha256"], 64):
                errors.append(f"{label}: source_sha256 must be 64-hex")
            if nonempty_string(case.get("known_finding_id")) and case["known_finding_id"] not in known_ids:
                errors.append(f"{label}: known_finding_id is not present")
    if case_count < 12:
        errors.append("expected-regressions: expected at least 12 control cases")
    matrix = reg.get("control_matrix", {})
    if set(matrix) != CONTROL_KINDS:
        errors.append("expected-regressions: control_matrix must cover positive/fixed/safe/unrelated/unknown")
    else:
        cataloged = set(controls)
        listed = {cid for values in matrix.values() for cid in values}
        if listed - cataloged:
            errors.append(f"expected-regressions: unknown matrix controls {sorted(listed - cataloged)}")
    return errors


def git_probe(path: Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "commit": UNKNOWN,
        "tree": UNKNOWN,
        "blob": UNKNOWN,
        "status": "missing_input",
        "path_tracked": False,
    }
    commit = git_value(["rev-parse", "HEAD"])
    tree = git_value(["rev-parse", "HEAD^{tree}"])
    if path.exists():
        try:
            rel = path.relative_to(REPO).as_posix()
        except ValueError:
            rel = path.as_posix()
        stage = git_value(["ls-files", "--stage", "--", rel])
        if commit:
            out["commit"] = commit
        if tree:
            out["tree"] = tree
        if stage:
            parts = stage.split()
            if len(parts) >= 2:
                out["blob"] = parts[1]
                out["path_tracked"] = True
                out["status"] = "verified_local"
            else:
                out["status"] = "untracked_local"
        else:
            out["status"] = "untracked_local"
    return out


def refresh_input_manifest(path: Path, manifest: dict[str, Any], repo_identity: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    manifest["status"] = "present"
    manifest["execution_status"] = "hash_bound_pending_reconciliation"
    manifest["sha256"] = sha256_bytes(data)
    manifest["git_identity"] = git_probe(path)
    manifest["input_assertions"] = {
        "file_read": True,
        "entries_extracted": 0,
        "fabricated_entries": False,
        "missing_input_is_not_safe_or_miss": True,
        "hash_refresh_explicit": True,
    }
    manifest["last_refreshed_at"] = now_iso()
    manifest["checkout_identity"] = repo_identity
    manifest["next_obligation"] = "Rerun strict reconciliation; only explicit c8-audit-entries blocks are imported."
    return manifest


def extract_entries(path: Path) -> tuple[list[Any], list[str]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        return [], [f"input text decode failed: {exc}"]
    errors: list[str] = []
    entries: list[Any] = []
    blocks = re.findall(r"```c8-audit-entries\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if not blocks:
        return [], []
    for i, block in enumerate(blocks):
        try:
            payload = json.loads(block)
        except json.JSONDecodeError as exc:
            errors.append(f"c8-audit-entries block {i}: invalid JSON: {exc}")
            continue
        rows = payload.get("entries") if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            errors.append(f"c8-audit-entries block {i}: payload must be an array or object with entries array")
            continue
        entries.extend(rows)
    return entries, errors

def classify_input(
    input_path: Path,
    manifest: dict[str, Any],
    controls: dict[str, dict[str, Any]],
    refresh_hash: bool = False,
    repo_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    input_rel = manifest.get("input_path", "源码漏洞审查记录_20261018.md")
    failures: list[str] = []
    unknown_ledger: list[str] = []
    if not input_path.exists() or not input_path.is_file():
        reason = "input_missing"
        return {
            "input_status": "missing",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": [f"source-audit input missing: {input_rel}"],
            "unknown_ledger": ["source-audit input missing: no vulnerability entries imported"],
            "extracted": [],
            "entry_mappings": [],
            "actual_sha256": UNKNOWN,
            "recorded_sha256": manifest.get("sha256", UNKNOWN),
            "input_git_identity": git_probe(input_path),
        }

    data = input_path.read_bytes()
    actual_sha = sha256_bytes(data)
    recorded_sha = manifest.get("sha256")
    if refresh_hash:
        manifest = refresh_input_manifest(input_path, manifest, repo_identity or {})
        recorded_sha = manifest.get("sha256")
    if is_unknown(recorded_sha) or not nonempty_string(recorded_sha):
        reason = "input_manifest_unbound"
        failures.append("input-manifest: expected SHA-256 is unknown; use --refresh-input-manifest explicitly")
        unknown_ledger.append("present input is not hash-bound; content was not imported")
        return {
            "input_status": "present",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": failures,
            "unknown_ledger": unknown_ledger,
            "extracted": [],
            "entry_mappings": [],
            "actual_sha256": actual_sha,
            "recorded_sha256": recorded_sha or UNKNOWN,
            "input_git_identity": git_probe(input_path),
            "manifest": manifest,
        }
    if recorded_sha.lower() != actual_sha:
        reason = "input_hash_mismatch"
        failures.append(f"input-manifest: SHA-256 mismatch recorded={recorded_sha.lower()} actual={actual_sha}")
        unknown_ledger.append("hash mismatch rejected before entry extraction")
        return {
            "input_status": "present",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": failures,
            "unknown_ledger": unknown_ledger,
            "extracted": [],
            "entry_mappings": [],
            "actual_sha256": actual_sha,
            "recorded_sha256": recorded_sha.lower(),
            "input_git_identity": git_probe(input_path),
            "manifest": manifest,
        }

    extracted, extract_errors = extract_entries(input_path)
    if extract_errors:
        reason = "input_schema_invalid"
        failures.extend(extract_errors)
        unknown_ledger.append("invalid explicit entry block rejected")
        return {
            "input_status": "present",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": failures,
            "unknown_ledger": unknown_ledger,
            "extracted": extracted,
            "entry_mappings": [],
            "actual_sha256": actual_sha,
            "recorded_sha256": recorded_sha.lower(),
            "input_git_identity": git_probe(input_path),
            "manifest": manifest,
        }
    if not extracted:
        reason = "input_no_supported_entries"
        failures.append("input has no fenced c8-audit-entries JSON block; prose is never inferred")
        unknown_ledger.append("input exists but no supported explicit entries were extracted")
        return {
            "input_status": "present",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": failures,
            "unknown_ledger": unknown_ledger,
            "extracted": [],
            "entry_mappings": [],
            "actual_sha256": actual_sha,
            "recorded_sha256": recorded_sha.lower(),
            "input_git_identity": git_probe(input_path),
            "manifest": manifest,
        }

    for i, entry in enumerate(extracted):
        failures.extend(validate_entry(entry, controls, f"input.entries[{i}]"))
    if failures:
        reason = "input_schema_invalid"
        return {
            "input_status": "present",
            "blocked_status": BLOCK_STATUS[reason],
            "failure_codes": [reason],
            "failures": failures,
            "unknown_ledger": unknown_ledger,
            "extracted": extracted,
            "entry_mappings": [],
            "actual_sha256": actual_sha,
            "recorded_sha256": recorded_sha.lower(),
            "input_git_identity": git_probe(input_path),
            "manifest": manifest,
        }

    entry_mappings = []
    for entry in extracted:
        identities = entry.get("source_identities") or [entry.get("source_identity")]
        entry_mappings.append({
            "entry_id": entry.get("entry_id"),
            "finding_identity": entry.get("finding_identity", entry.get("entry_id")),
            "detector_ids": entry.get("mapping", {}).get("detector_ids", []),
            "rule_ids": entry.get("mapping", {}).get("rule_ids", []),
            "control_ids": entry.get("mapping", {}).get("control_ids", []),
            "source_identities": [
                {
                    "repository": sid.get("repository"),
                    "path": sid.get("path"),
                    "commit": sid.get("commit"),
                    "tree": sid.get("tree"),
                    "blob": sid.get("blob"),
                    "sha256": sid.get("sha256"),
                    "identity_status": sid.get("identity_status"),
                }
                for sid in identities
                if isinstance(sid, dict)
            ],
            "classification": entry.get("claim_boundary", {}).get("classification"),
            "validated_vulnerability": entry.get("evidence_gate", {}).get("validated_vulnerability"),
        })
    return {
        "input_status": "present",
        "blocked_status": "not_blocked",
        "failure_codes": [],
        "failures": [],
        "unknown_ledger": unknown_ledger,
        "extracted": extracted,
        "entry_mappings": entry_mappings,
        "actual_sha256": actual_sha,
        "recorded_sha256": recorded_sha.lower(),
        "input_git_identity": git_probe(input_path),
        "manifest": manifest,
    }


def make_valid_self_test_entry() -> dict[str, Any]:
    rows = [
        {"control_id": "A-PATH-POS-001", "kind": "positive", "expected": "candidate/unassessed"},
        {"control_id": "A-PATH-FIX-001", "kind": "fixed", "expected": "no candidate"},
    ]
    return {
        "schema_version": "ohscanner.source-audit-entry/v2",
        "entry_id": "SELFTEST-PATH-ENTRY-001",
        "source_identity": {
            "repository": "selftest",
            "path": "unknown",
            "commit": UNKNOWN,
            "tree": UNKNOWN,
            "blob": UNKNOWN,
            "sha256": UNKNOWN,
            "identity_status": "missing_input",
        },
        "observation": {
            "summary": "Synthetic importer self-test entry.",
            "scope": "reconcile fail-closed self-test only",
            "fact_status": "provisional_substitute_evidence",
            "limitations": ["Not product source evidence."],
        },
        "mapping": {
            "detector_ids": ["ohscanner.cpp.path_traversal"],
            "rule_ids": ["ohcpp-path-traversal-candidate-001"],
            "control_ids": [row["control_id"] for row in rows],
            "mapping_status": "mapped",
        },
        "controls": rows,
        "evidence_gate": {
            "entry_or_permission_boundary": UNKNOWN,
            "reachable_sensitive_operation": UNKNOWN,
            "trigger_condition": UNKNOWN,
            "cia_impact": UNKNOWN,
            "audit_evidence": "synthetic schema fixture",
            "validated_vulnerability": False,
        },
        "artifacts": [
            {"role": "selftest", "path": UNKNOWN, "sha256": UNKNOWN, "git_blob": UNKNOWN}
        ],
        "claim_boundary": {
            "classification": "candidate",
            "assessment_status": "unassessed",
            "product_vulnerability": False,
            "cia": False,
            "cwe": False,
            "cve": False,
            "metrics": False,
        },
    }


def run_fail_closed_self_test(known: dict[str, Any], output_path: Path) -> dict[str, Any]:
    controls = load_controls(known)
    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="c8-reconcile-selftest-", dir=BASE) as tmp:
        tmp_path = Path(tmp)

        def exercise(name: str, input_text: str | None, recorded_sha: Any) -> dict[str, Any]:
            input_path = tmp_path / f"{name}.md"
            if input_text is not None:
                input_path.write_bytes(input_text.encode("utf-8"))
            manifest = {"input_path": input_path.name, "sha256": recorded_sha}
            first = classify_input(input_path, manifest, controls)
            second = classify_input(input_path, manifest, controls)
            stable = (
                first["blocked_status"] == second["blocked_status"]
                and first["failure_codes"] == second["failure_codes"]
                and len(first["extracted"]) == len(second["extracted"])
            )
            return {
                "case": name,
                "first_status": first["blocked_status"],
                "rerun_status": second["blocked_status"],
                "failure_codes": second["failure_codes"],
                "entry_count": len(second["extracted"]),
                "mapped_entry_ids": [row.get("entry_id") for row in second["entry_mappings"]],
                "mapped_source_identity_count": sum(len(row.get("source_identities", [])) for row in second["entry_mappings"]),
                "rerunnable_stable": stable,
            }

        cases.append(exercise("missing", None, UNKNOWN))
        no_entries_text = "# review without explicit entries\n"
        cases.append(exercise("present_no_entries", no_entries_text, sha256_bytes(no_entries_text.encode("utf-8"))))
        schema_text = "```c8-audit-entries\n{\"entries\":[{}]}\n```\n"
        cases.append(exercise("schema_invalid", schema_text, sha256_bytes(schema_text.encode("utf-8"))))
        valid_text = "```c8-audit-entries\n" + json.dumps({"entries": [make_valid_self_test_entry()]}, ensure_ascii=False) + "\n```\n"
        cases.append(exercise("hash_mismatch", valid_text, "f" * 64))
        cases.append(exercise("valid_mapping", valid_text, sha256_bytes(valid_text.encode("utf-8"))))

    expected = {
        "missing": ("blocked_missing_input", ["input_missing"]),
        "present_no_entries": ("blocked_no_entries", ["input_no_supported_entries"]),
        "schema_invalid": ("blocked_schema_invalid", ["input_schema_invalid"]),
        "hash_mismatch": ("blocked_hash_mismatch", ["input_hash_mismatch"]),
        "valid_mapping": ("not_blocked", []),
    }
    for row in cases:
        wanted_status, wanted_codes = expected[row["case"]]
        row["expected_status"] = wanted_status
        row["expected_failure_codes"] = wanted_codes
        row["passed"] = (
            row["first_status"] == wanted_status
            and row["rerun_status"] == wanted_status
            and row["failure_codes"] == wanted_codes
            and row["rerunnable_stable"]
            and (row["case"] != "valid_mapping" or (row["entry_count"] == 1 and row["mapped_entry_ids"] == ["SELFTEST-PATH-ENTRY-001"] and row["mapped_source_identity_count"] == 1))
        )
    result = {
        "schema_version": "c8.source-audit.fail-closed-self-test/v1",
        "generated_at": now_iso(),
        "cwd": str(REPO),
        "exact_argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        "scanner_execution": False,
        "metrics_computed": False,
        "cases": cases,
        "status": "pass" if all(row["passed"] for row in cases) else "fail",
    }
    write_json(output_path, result)
    return result

def file_hashes(paths: list[Path]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        data = path.read_bytes()
        rel = path.relative_to(REPO).as_posix()
        result[rel] = {
            "sha256": sha256_bytes(data),
            "git_blob": git_blob_sha1(data),
            "size_bytes": len(data),
        }
    return result


def repo_identity() -> dict[str, Any]:
    return {
        "worktree": str(REPO),
        "head": git_value(["rev-parse", "HEAD"]) or UNKNOWN,
        "head_tree": git_value(["rev-parse", "HEAD^{tree}"]) or UNKNOWN,
        "base": EXPECTED_BASE,
        "base_tree": EXPECTED_BASE_TREE,
        "detached": git_value(["symbolic-ref", "--short", "HEAD"]) is None,
        "remote_origin": git_value(["remote", "get-url", "origin"]) or UNKNOWN,
    }


def validation_summary(failure_codes: list[str], blocked_status: str) -> dict[str, str]:
    if failure_codes == ["input_missing"]:
        return {
            "worktree_identity": "pass",
            "input_presence": "blocked",
            "input_hash": "not_evaluated",
            "entry_schema": "not_evaluated",
            "mapping": "not_evaluated",
            "known_substitute_evidence": "pass",
            "regression_scaffolding": "pass",
        }
    return {
        "worktree_identity": "pass" if "worktree_identity_mismatch" not in failure_codes else "fail",
        "input_presence": "pass" if "input_missing" not in failure_codes else "blocked",
        "input_hash": "pass" if not {"input_hash_mismatch", "input_manifest_unbound"} & set(failure_codes) else "fail",
        "entry_schema": "pass" if "input_schema_invalid" not in failure_codes else "fail",
        "mapping": "pass" if blocked_status == "not_blocked" else "not_evaluated",
        "known_substitute_evidence": "pass",
        "regression_scaffolding": "pass",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate C8 source-audit reconciliation without scanner execution")
    parser.add_argument("--strict-input", action="store_true", help="return non-zero when input/import is blocked")
    parser.add_argument("--write-run-manifest", action="store_true", help="write run-manifest.json in this scaffold directory")
    parser.add_argument("--refresh-input-manifest", action="store_true", help="explicitly bind the present input SHA-256 before reconciliation")
    parser.add_argument("--input", type=Path, help="override the input Markdown path for controlled replay")
    parser.add_argument("--input-manifest", type=Path, default=INPUT_MANIFEST, help="override input manifest path")
    parser.add_argument("--self-test-fail-closed", action="store_true", help="run deterministic missing/no-entry/schema/hash self-tests")
    args = parser.parse_args(argv)

    config_failures: list[str] = []
    try:
        schema = read_json(SCHEMA)
        manifest = read_json(args.input_manifest)
        known = read_json(KNOWN)
        regressions = read_json(REGRESSIONS)
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        schema, manifest, known, regressions = {}, {}, {}, {}
        config_failures.append(f"configuration load failed: {exc}")

    if schema.get("$id") != "ohscanner.source-audit-entry/v2":
        config_failures.append("audit-schema: $id mismatch")
    known_failures, controls = validate_known(known)
    config_failures.extend(known_failures)
    config_failures.extend(validate_regressions(regressions, known, controls))

    identity = repo_identity()
    if identity["head"] != EXPECTED_BASE or identity["head_tree"] != EXPECTED_BASE_TREE:
        config_failures.append(
            f"worktree identity mismatch: expected {EXPECTED_BASE}/{EXPECTED_BASE_TREE}, got {identity['head']}/{identity['head_tree']}"
        )

    if args.self_test_fail_closed:
        self_test = run_fail_closed_self_test(known, SELF_TEST_RESULT)
        print(json.dumps(self_test, ensure_ascii=False, indent=2))
        return 0 if self_test["status"] == "pass" and not config_failures else 20

    input_rel = manifest.get("input_path", "源码漏洞审查记录_20261018.md")
    input_path = args.input.resolve() if args.input else (REPO / input_rel)
    input_result = classify_input(
        input_path,
        manifest,
        controls,
        refresh_hash=args.refresh_input_manifest,
        repo_identity=identity,
    )
    manifest = input_result.pop("manifest", manifest)
    input_result["input_status"] = manifest.get("status", input_result["input_status"])
    input_result["input_provenance_status"] = manifest.get("git_identity", {}).get("status", UNKNOWN)
    if manifest.get("git_identity", {}).get("status") == "verified_local_pinned_object_after_explicit_fetch":
        input_result["input_git_identity"] = manifest["git_identity"]
    input_result["input_provenance_status"] = manifest.get("git_identity", {}).get("status", UNKNOWN)

    failure_codes = list(input_result["failure_codes"])
    failures = list(input_result["failures"])
    unknown_ledger = list(input_result["unknown_ledger"])
    if config_failures:
        if any(x.startswith("worktree identity mismatch") for x in config_failures):
            failure_codes.insert(0, "worktree_identity_mismatch")
        else:
            failure_codes.insert(0, "configuration_invalid")
        failures = config_failures + failures

    blocked_status = input_result["blocked_status"]
    if config_failures:
        blocked_status = (
            BLOCK_STATUS["worktree_identity_mismatch"]
            if failure_codes[0] == "worktree_identity_mismatch"
            else BLOCK_STATUS["configuration_invalid"]
        )
    exit_code = 0
    if failure_codes:
        exit_code = BLOCK_EXIT_CODES.get(failure_codes[0], 20)

    substitute_rows = []
    for entry in known.get("findings", []):
        if not isinstance(entry, dict):
            continue
        obs = entry.get("observation", {})
        if obs.get("fact_status") == "provisional_substitute_evidence":
            substitute_rows.append({
                "entry_id": entry.get("entry_id"),
                "source_report_finding_id": obs.get("source_report_finding_id"),
                "source_role": obs.get("source_role"),
                "classification": entry.get("claim_boundary", {}).get("classification"),
                "product_vulnerability": entry.get("claim_boundary", {}).get("product_vulnerability"),
            })

    self_test: dict[str, Any] = {"status": "not_run"}
    if SELF_TEST_RESULT.exists():
        try:
            self_test = read_json(SELF_TEST_RESULT)
        except (OSError, json.JSONDecodeError, UnicodeError) as exc:
            self_test = {"status": "unreadable", "error": str(exc)}

    patch_hashes = file_hashes([MINIMAL_PATCH])
    patch_meta: dict[str, Any] = {
        "path": MINIMAL_PATCH.relative_to(REPO).as_posix(),
        "generation_command": "git diff --binary -- research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019 ':(exclude)research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/run-manifest.json' > research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/minimal-patch.diff",
        "generated_output_excluded": [RUN_MANIFEST.relative_to(REPO).as_posix(), SELF_TEST_RESULT.relative_to(REPO).as_posix()],
    }
    patch_meta.update(patch_hashes.get(MINIMAL_PATCH.relative_to(REPO).as_posix(), {"sha256": UNKNOWN, "status": "missing"}))

    summary = {
        "schema_version": "c8.source-audit.run-manifest/v2",
        "run_id": "c8-source-audit-reconciliation-20261019",
        "generated_at": now_iso(),
        "exact_command": {
            "cwd": str(REPO),
            "executable": sys.executable,
            "argv": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
            "shell_rendering": " ".join([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]),
        },
        "checkout_identity": identity,
        "blocked": blocked_status != "not_blocked",
        "blocked_status": blocked_status,
        "expected_exit_code": exit_code,
        "exit_code": exit_code,
        "input": {
            "status": input_result["input_status"],
            "path": input_rel,
            "resolved_path": str(input_path),
            "recorded_sha256": input_result["recorded_sha256"],
            "actual_sha256": input_result["actual_sha256"],
            "git_identity": input_result["input_git_identity"],
            "provenance_status": input_result.get("input_provenance_status", UNKNOWN),
            "explicit_hash_refresh": bool(args.refresh_input_manifest),
        },
        "scanner_execution": False,
        "metrics_computed": False,
        "extracted_vulnerability_entries": len(input_result["extracted"]),
        "entry_mappings": input_result["entry_mappings"],
        "known_substitute_findings": substitute_rows,
        "validation": validation_summary(failure_codes, blocked_status),
        "failure_codes": failure_codes,
        "failures": failures,
        "unknown_ledger": unknown_ledger,
        "self_test": self_test,
        "hashes": file_hashes([
            BASE / "README.md",
            SCHEMA,
            args.input_manifest,
            KNOWN,
            REGRESSIONS,
            BASE / "reconcile.py",
            MINIMAL_PATCH,
            SELF_TEST_RESULT,
        ]),
        "minimal_patch": patch_meta,
        "limitations": [
            "The source-audit original is located as a remote pinned Git object and hash-bound through the c9 read-only copy; its prose was read with git show.",
            "The original contains prose rows, not an explicit c8-audit-entries JSON block; structured extraction therefore remains blocked_no_entries.",
            "No substitute evidence is promoted to product confirmed/reportable in this reconciliation.",
            "No scanner was executed by this script; expected regressions are mapping/acceptance scaffolding only.",
            "No Precision/Recall, FP/FN, CWE/CVE or product impact conclusion is computed or imported.",
            "ohscanner.cpp.path_traversal is research-only and not enabled in the product Runner/Catalog at the fixed base.",
        ],
        "next_slice": [
            "Preserve the remote pinned original identity and the c9 row-to-source/rule/control reconciliation; do not convert prose into product findings.",
            "If machine import is required, add explicit source-bound entry JSON with repo/commit/tree/blob/source SHA-256 and detector/rule/control identities.",
            "Keep multi-file, multi-commit and v1 read-only compatibility work in later auditable slices without rewriting historical IDs.",
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.write_run_manifest:
        write_json(RUN_MANIFEST, summary)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
