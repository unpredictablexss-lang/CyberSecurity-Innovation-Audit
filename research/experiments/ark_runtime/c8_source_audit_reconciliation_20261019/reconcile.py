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
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[3]
INPUT_MANIFEST = BASE / "input-manifest.json"
SCHEMA = BASE / "audit-schema.json"
KNOWN = BASE / "known-source-findings.json"
REGRESSIONS = BASE / "expected-regressions.json"
RUN_MANIFEST = BASE / "run-manifest.json"

CONTROL_KINDS = {"positive", "fixed", "safe", "unrelated", "unknown"}
CLASSIFICATIONS = {"candidate", "unknown", "confirmed", "reportable"}
IDENTITY_STATUSES = {"verified_local", "recorded_external", "unknown", "missing_input"}
FACT_STATUSES = {"provisional_substitute_evidence", "source_fact", "unknown"}
DETECTOR_IDS = {"ohscanner.ark.runtime.type_safety"}
RULE_IDS = {
    "ark.runtime.typedarray-store-type-origin",
    "ark.runtime.typedarray-allocation-exception-guard",
}
UNKNOWN = "unknown"


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


def is_unknown(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() == UNKNOWN


def nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def hex_len(value: Any, length: int) -> bool:
    return nonempty_string(value) and len(value) == length and re.fullmatch(r"[0-9a-fA-F]+", value) is not None


def local_artifact(path_value: str) -> Path | None:
    p = Path(path_value)
    if p.is_absolute():
        return p
    return REPO / p


def verify_artifact(art: dict[str, Any], errors: list[str], label: str) -> None:
    for key in ("role", "path", "sha256", "git_blob"):
        if key not in art or not nonempty_string(art[key]):
            errors.append(f"{label}: artifact.{key} must be non-empty or explicit unknown")
    path_value = art.get("path")
    if not nonempty_string(path_value):
        return
    p = local_artifact(path_value)
    if p is None or not p.exists():
        if not is_unknown(art.get("sha256")) or not is_unknown(art.get("git_blob")):
            errors.append(f"{label}: missing artifact path must carry explicit unknown SHA-256 and Git blob")
        return
    if not p.is_file():
        if not is_unknown(art.get("sha256")) or not is_unknown(art.get("git_blob")):
            errors.append(f"{label}: directory artifact must carry explicit unknown SHA-256 and Git blob")
        return
    data = p.read_bytes()
    actual_sha = sha256_bytes(data)
    actual_blob = git_blob_sha1(data)
    normalized_blob = git_blob_sha1(data.replace(b"\r\n", b"\n"))
    if is_unknown(art.get("sha256")):
        errors.append(f"{label}: existing artifact {path_value} has no recorded SHA-256")
    elif art["sha256"].lower() != actual_sha:
        errors.append(f"{label}: SHA-256 mismatch for {path_value}")
    if is_unknown(art.get("git_blob")):
        errors.append(f"{label}: existing artifact {path_value} has no recorded Git blob")
    elif art["git_blob"].lower() not in {actual_blob, normalized_blob}:
        errors.append(f"{label}: Git blob mismatch for {path_value}")


def validate_entry(entry: Any, controls: dict[str, dict[str, Any]], label: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(entry, dict):
        return [f"{label}: entry must be an object"]
    required = (
        "schema_version", "entry_id", "source_identity", "observation", "mapping",
        "controls", "evidence_gate", "artifacts", "claim_boundary",
    )
    for key in required:
        if key not in entry:
            errors.append(f"{label}: missing {key}")
    if errors:
        return errors
    if entry["schema_version"] != "ohscanner.source-audit-entry/v2":
        errors.append(f"{label}: schema_version must be source-bound v2")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,128}", str(entry["entry_id"])):
        errors.append(f"{label}: invalid entry_id")

    sid = entry["source_identity"]
    if not isinstance(sid, dict):
        errors.append(f"{label}: source_identity must be object")
    else:
        for key in ("repository", "path", "commit", "tree", "blob", "sha256", "identity_status"):
            if key not in sid or not nonempty_string(sid[key]):
                errors.append(f"{label}: source_identity.{key} must be non-empty or explicit unknown")
        if sid.get("identity_status") not in IDENTITY_STATUSES:
            errors.append(f"{label}: invalid source_identity.identity_status")
        for key, length in (("commit", 40), ("tree", 40), ("blob", 40)):
            value = sid.get(key)
            if not is_unknown(value) and not hex_len(value, length):
                errors.append(f"{label}: source_identity.{key} must be 40-hex or unknown")
        if not is_unknown(sid.get("sha256")) and not hex_len(sid.get("sha256"), 64):
            errors.append(f"{label}: source_identity.sha256 must be 64-hex or unknown")

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
        for detector in mapping.get("detector_ids", []):
            if detector not in DETECTOR_IDS:
                errors.append(f"{label}: unknown detector_id {detector}")
        for rule in mapping.get("rule_ids", []):
            if rule not in RULE_IDS:
                errors.append(f"{label}: unknown rule_id {rule}")

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
        if claim.get("classification") not in CLASSIFICATIONS:
            errors.append(f"{label}: invalid claim_boundary.classification")
        if claim.get("assessment_status") not in {"unassessed", "assessed"}:
            errors.append(f"{label}: invalid claim_boundary.assessment_status")
        if claim.get("metrics") is not False:
            errors.append(f"{label}: metrics claims are not permitted by this reconciliation scaffold")
        if claim.get("classification") in {"candidate", "unknown"}:
            if any(claim.get(k) is not False for k in ("product_vulnerability", "cia", "cve")):
                errors.append(f"{label}: candidate/unknown cannot assert product vulnerability, CIA or CVE")
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
    for key in ("product_vulnerability_claim", "cia_claim", "cve_claim", "precision_recall_claim", "fp_fn_claim"):
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
    }
    if required != expected_required:
        errors.append("expected-regressions: required_coverage must be exactly the fail-closed suite")
    families = reg.get("families")
    if not isinstance(families, list):
        return errors + ["expected-regressions: families must be array"]
    family_ids = {f.get("family_id") for f in families if isinstance(f, dict)}
    for needed in expected_required:
        if needed == "guard_before" or needed == "guard_after" or needed == "guard_unknown":
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
    return errors


def git_probe(path: Path) -> dict[str, str]:
    out = {"commit": UNKNOWN, "tree": UNKNOWN, "blob": UNKNOWN, "status": "unknown"}
    def run(args: list[str]) -> str | None:
        try:
            p = subprocess.run(["git", *args], cwd=REPO, text=True, capture_output=True, check=False)
        except (FileNotFoundError, OSError):
            return None
        return p.stdout.strip() if p.returncode == 0 else None
    commit = run(["rev-parse", "HEAD"])
    tree = run(["rev-parse", "HEAD^{tree}"])
    rel = path.relative_to(REPO).as_posix() if path.is_relative_to(REPO) else path.as_posix()
    stage = run(["ls-files", "--stage", "--", rel])
    if commit:
        out["commit"] = commit
    if tree:
        out["tree"] = tree
    if stage:
        parts = stage.split()
        if len(parts) >= 2:
            out["blob"] = parts[1]
    out["status"] = "verified_local" if all(out[k] != UNKNOWN for k in ("commit", "tree", "blob")) else "partial"
    return out


def refresh_input_manifest(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    manifest["status"] = "present"
    manifest["execution_status"] = "ready_for_reconciliation"
    manifest["sha256"] = sha256_bytes(data)
    manifest["git_identity"] = git_probe(path)
    manifest["input_assertions"]["file_read"] = True
    manifest["input_assertions"]["entries_extracted"] = 0
    manifest["input_assertions"]["fabricated_entries"] = False
    manifest["next_obligation"] = "Extract only explicit c8-audit-entries JSON blocks; keep missing/unknown fields fail-closed."
    return manifest


def extract_entries(path: Path) -> tuple[list[Any], list[str]]:
    text = path.read_text(encoding="utf-8-sig")
    errors: list[str] = []
    entries: list[Any] = []
    blocks = re.findall(r"```c8-audit-entries\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if not blocks:
        return [], ["input has no fenced c8-audit-entries JSON block; entries are not inferred from prose"]
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate C8 source-audit reconciliation without scanner execution")
    parser.add_argument("--strict-input", action="store_true", help="return non-zero when the source-audit input is missing")
    parser.add_argument("--write-run-manifest", action="store_true", help="write run-manifest.json in this scaffold directory")
    args = parser.parse_args(argv)

    failures: list[str] = []
    unknown_ledger: list[str] = []
    schema = read_json(SCHEMA)
    if schema.get("$id") != "ohscanner.source-audit-entry/v2":
        failures.append("audit-schema: $id mismatch")
    manifest = read_json(INPUT_MANIFEST)
    known = read_json(KNOWN)
    regressions = read_json(REGRESSIONS)

    known_failures, controls = validate_known(known)
    failures.extend(known_failures)
    failures.extend(validate_regressions(regressions, known, controls))

    input_rel = manifest.get("input_path", "源码漏洞审查记录_20261018.md")
    input_path = REPO / input_rel
    extracted: list[Any] = []
    input_status = "missing"
    execution_status = "blocked_missing_input"
    if not input_path.exists():
        unknown_ledger.append("source-audit input missing: no vulnerability entries imported")
        if args.strict_input:
            execution_status = "blocked_missing_input_strict"
    else:
        input_status = "present"
        if manifest.get("status") == "missing" or manifest.get("sha256") in (None, UNKNOWN):
            manifest = refresh_input_manifest(input_path, manifest)
            write_json(INPUT_MANIFEST, manifest)
        recorded_sha = manifest.get("sha256")
        actual_sha = sha256_bytes(input_path.read_bytes())
        if not nonempty_string(recorded_sha) or recorded_sha.lower() != actual_sha:
            failures.append("input-manifest: present input SHA-256 is not bound; refresh is required")
        extracted, extract_errors = extract_entries(input_path)
        failures.extend(extract_errors)
        if extracted:
            for i, entry in enumerate(extracted):
                failures.extend(validate_entry(entry, controls, f"input.entries[{i}]"))
            execution_status = "completed" if not failures else "blocked_invalid_input"
        else:
            execution_status = "blocked_no_supported_entries"
            unknown_ledger.append("input exists but no supported explicit entries were extracted")
        manifest["input_assertions"]["entries_extracted"] = len(extracted)

    # Known substitute findings are always validated but never promoted into input entries.
    if not failures and not extracted and input_status == "missing":
        execution_status = "blocked_missing_input"

    summary = {
        "schema_version": "c8.source-audit.run-manifest/v1",
        "run_id": "c8-source-audit-reconciliation-20261019",
        "started_at": now_iso(),
        "checkout": str(REPO),
        "head": "556cb145fec9f52afd1c49d10290e01036200f00",
        "input_status": input_status,
        "execution_status": execution_status,
        "scanner_execution": False,
        "metrics_computed": False,
        "input_path": input_rel,
        "extracted_vulnerability_entries": len(extracted),
        "known_substitute_findings": len(known.get("findings", [])),
        "validation": {
            "entry_schema": "pass" if not any("input.entries" in x for x in failures) else "fail",
            "source_identity": "pass" if not any("source_identity" in x or "SHA-256" in x or "Git blob" in x for x in failures) else "fail",
            "mapping": "pass" if not any("mapping" in x or "detector_id" in x or "rule_id" in x or "control" in x for x in failures) else "fail",
            "controls": "pass" if not any("control" in x for x in failures) else "fail",
            "regression_scaffolding": "pass" if not any(x.startswith("expected-regressions") for x in failures) else "fail"
        },
        "failures": failures,
        "unknown_ledger": unknown_ledger,
        "next_slice": [
            "Restore or provide 源码漏洞审查记录_20261018.md and rerun with --write-run-manifest.",
            "For each imported entry, bind repo/commit/tree/blob/source hash and keep partial/failed/unknown explicit.",
            "After missing historical objects are restored, run the authorized local replay and keep failures in the ledger."
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if args.write_run_manifest:
        write_json(RUN_MANIFEST, summary)
    if failures:
        return 2
    if args.strict_input and input_status == "missing":
        return 3
    if execution_status.startswith("blocked_invalid"):
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))