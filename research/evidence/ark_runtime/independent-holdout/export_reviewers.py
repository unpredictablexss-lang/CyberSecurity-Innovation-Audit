#!/usr/bin/env python3
"""Export two isolated source-only reviewer packets after verifying pinned source identities."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "admin" / "holdout_source_manifest.csv"
DECLARATION = ROOT / "reviewer-packet-export" / "reviewer_declaration_template.md"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = os.environ.copy()
    env.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    p = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf-8", "replace").strip())
    return p.stdout


def safe_remove_target_message(target):
    if target.exists() and any(target.iterdir()):
        raise SystemExit("output directory must be empty: " + str(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", required=True, help="Existing local Git object store; no fetch is performed")
    parser.add_argument("--scanner-root", required=True, help="Clean archive of the exact frozen scanner commit")
    parser.add_argument("--reviewer1-declaration", required=True, help="Signed JSON declaration completed before source packet access")
    parser.add_argument("--reviewer2-declaration", required=True, help="Signed JSON declaration completed before source packet access")
    parser.add_argument("--family-audit", required=True, help="Completed admin family-level leakage audit")
    parser.add_argument("--output-dir", required=True, help="Empty private directory outside this repository")
    args = parser.parse_args()
    repo = Path(args.runtime_repo).resolve()
    scanner = Path(args.scanner_root).resolve()
    out = Path(args.output_dir).resolve()
    if not repo.is_dir() or not scanner.is_dir():
        raise SystemExit("runtime-repo and scanner-root must be existing directories")
    if out == ROOT or ROOT in out.parents:
        raise SystemExit("reviewer output must be outside the assessment repository")
    safe_remove_target_message(out)
    key_path = ROOT / "admin" / "reviewer_id_key.csv"
    if key_path.exists():
        raise SystemExit("reviewer ID key already exists; do not overwrite or regenerate this assessment")
    declarations = {}
    declaration_ids = set()
    for reviewer, declaration_arg in (("reviewer_1", args.reviewer1_declaration),
                                      ("reviewer_2", args.reviewer2_declaration)):
        path = Path(declaration_arg)
        record = json.loads(path.read_text(encoding="utf-8"))
        if (not record.get("reviewer_id") or not record.get("signed_name") or not record.get("signed_utc")
                or record.get("participated_in_detector_or_rule_design_tuning") is not False
                or record.get("seen_predictions_or_tuning_results_for_these_cases") is not False
                or record.get("can_label_independently_without_contact") is not True):
            raise SystemExit(reviewer + " has not attested independence before source access")
        if record["reviewer_id"] in declaration_ids:
            raise SystemExit("the two reviewer identities must be different")
        declaration_ids.add(record["reviewer_id"])
        if record.get("prior_public_source_or_patch_exposure") != "none":
            raise SystemExit(reviewer + " reports prior source/patch exposure; recruit a replacement")
        declarations[reviewer] = path.read_bytes()
    rows = list(csv.DictReader(MANIFEST.open(encoding="utf-8-sig", newline="")))
    families = list(csv.DictReader(Path(args.family_audit).open(encoding="utf-8-sig", newline="")))
    family_ids = {row["family_id"] for row in rows}
    audited_ids = {row["family_id"] for row in families}
    if (audited_ids != family_ids or len(families) != len(audited_ids)
            or any(row.get("overlap_found", "").lower() != "no"
                   or row.get("scope_complete", "").lower() != "yes"
                   or not row.get("evidence_reference", "") for row in families)):
        raise SystemExit("complete family-level audit covering every sample family, with no development/tuning overlap, is required before reviewer export")
    for family in families:
        ids = set(filter(None, family["sample_ids_in_holdout"].split(";")))
        expected_ids = {row["sample_id"] for row in rows if row["family_id"] == family["family_id"]}
        if ids != expected_ids or family["disposition"] != "retained":
            raise SystemExit("family audit does not match the frozen holdout manifest")
    lock = json.loads((ROOT / "admin" / "frozen_detector.json").read_text(encoding="utf-8"))
    from sys import path as sys_path
    sys_path.insert(0, str(scanner))
    from src.parser.ast import parse_source
    from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel, VERSION
    if VERSION != lock["detector_version"] or RuntimeTypeModel().digest != lock["model_digest_sha256"]:
        raise SystemExit("scanner model/version mismatch")
    if sha((scanner / "src/parser/ast.py").read_bytes()) != lock["parser_ast_sha256"]:
        raise SystemExit("parser source hash mismatch")
    for rel, expected in lock["implementation_sha256"].items():
        if sha((scanner / rel).read_bytes()) != expected:
            raise SystemExit("detector implementation hash mismatch: " + rel)
    if not rows:
        raise SystemExit("empty source manifest")
    verified = []
    for row in rows:
        commit, path = row["commit"], row["path"]
        tree = git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()
        blob = git(repo, "rev-parse", "--verify", commit + ":" + path).decode().strip()
        raw = git(repo, "cat-file", "blob", commit + ":" + path)
        if tree != row["tree"] or blob != row["blob"] or sha(raw) != row["source_sha256"]:
            raise SystemExit("source identity mismatch for " + row["sample_id"])
        parsed = parse_source(raw.decode("utf-8", "strict"), "cpp")
        if parsed.parse_status != row["parse_status"] or len(parsed.parse_issues) != int(row["parse_issue_count"]):
            raise SystemExit("frozen parser status mismatch for " + row["sample_id"])
        verified.append((row, raw))

    out.mkdir(parents=True, exist_ok=True)
    key = []
    for reviewer in ("reviewer_1", "reviewer_2"):
        reviewer_dir = out / reviewer
        cases_dir = reviewer_dir / "cases"
        cases_dir.mkdir(parents=True)
        form_path = reviewer_dir / "labels.csv"
        with form_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["case_id", "label", "root_cause_description", "evidence_lines", "reasoning", "unknown_or_exclusion_reason", "submitted_utc"])
            # Independent randomization prevents a shared row order from revealing pair membership.
            shuffled = list(verified)
            import random
            random.SystemRandom().shuffle(shuffled)
            for row, raw in shuffled:
                case_id = uuid.uuid4().hex[:12].upper()
                key.append({"reviewer": reviewer, "case_id": case_id, "sample_id": row["sample_id"]})
                case_path = cases_dir / (case_id + ".txt")
                prompt = (
                    "Assess this exact source unit independently. Choose vulnerable, fixed, safe, unrelated, or unknown. "
                    "State a stable root-cause description when one exists, cite line numbers, and explain uncertainty. "
                    "Do not infer a label from revision chronology or detector behavior.\n\n"
                    + "Input parser status: " + row["parse_status"] + " (issues: " + row["parse_issue_count"] + ").\n"
                    + "Review scope: " + row["review_scope"] + "\n\n"
                    + "----- exact source bytes follow -----\n"
                ).encode("utf-8")
                case_path.write_bytes(prompt + raw)
                writer.writerow([case_id, "", "", "", "", "", ""])
        (reviewer_dir / "independence_declaration.json").write_bytes(declarations[reviewer])
        (reviewer_dir / "README.txt").write_text(
            "Private blind packet. Do not share or compare with the other reviewer.\n"
            "This directory intentionally excludes predictions, model/rule details, tuning results, source revision IDs, hashes, patch references, and family IDs.\n"
            "The pre-access independence_declaration.json is included. Return labels.csv with evidence and unknown/exclusion reasons completed.\n",
            encoding="utf-8")
    admin = ROOT / "admin"
    admin.mkdir(exist_ok=True)
    with (admin / "reviewer_id_key.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["reviewer", "case_id", "sample_id"])
        writer.writeheader(); writer.writerows(key)
    print(json.dumps({"reviewer_packets": 2, "source_units_each": len(verified),
                      "source_identities_verified": True, "predictions_included": False,
                      "output_dir": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()

