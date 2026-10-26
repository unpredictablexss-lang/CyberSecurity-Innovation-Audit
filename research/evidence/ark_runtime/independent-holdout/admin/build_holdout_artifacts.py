#!/usr/bin/env python3
"""Verify pinned Ark Runtime holdout source identities and write metadata-only review files."""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = os.environ.copy()
    env.update({"GIT_NO_REPLACE_OBJECTS":"1", "GIT_NO_LAZY_FETCH":"1", "GIT_ALLOW_PROTOCOL":"", "GIT_TERMINAL_PROMPT":"0", "GIT_OPTIONAL_LOCKS":"0"})
    proc = subprocess.run(["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip() or f"git exited {proc.returncode}")
    return proc.stdout


def write_csv(path, rows, columns):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-repo", required=True, help="Local Git object store containing the pinned upstream commits")
    parser.add_argument("--scanner-root", required=True, help="Clean archive of the exact scanner commit in frozen_detector.json")
    parser.add_argument("--output-dir", required=True, help="Metadata-only output directory")
    parser.add_argument("--specs", default=str(Path(__file__).with_name("holdout_specs.json")))
    parser.add_argument("--freeze", default=str(Path(__file__).with_name("frozen_detector.json")))
    args = parser.parse_args()

    repo = Path(args.runtime_repo).resolve()
    scanner_root = Path(args.scanner_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    specs = json.loads(Path(args.specs).read_text(encoding="utf-8-sig"))
    freeze = json.loads(Path(args.freeze).read_text(encoding="utf-8-sig"))
    if not repo.is_dir() or not scanner_root.is_dir():
        raise SystemExit("runtime repo and scanner archive must be existing directories")
    sys.path.insert(0, str(scanner_root))
    from src.parser.ast import parse_source
    from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel, VERSION
    model = RuntimeTypeModel()
    if VERSION != freeze["detector_version"] or model.digest != freeze["model_digest_sha256"]:
        raise SystemExit("scanner model/version does not match the frozen lock")
    if sha256((scanner_root / "src/parser/ast.py").read_bytes()) != freeze["parser_ast_sha256"]:
        raise SystemExit("parser implementation does not match the frozen commit lock")
    for relpath, expected in freeze["implementation_sha256"].items():
        if sha256((scanner_root / relpath).read_bytes()) != expected:
            raise SystemExit("detector implementation hash mismatch: " + relpath)
    model_paths = set(freeze["model_input_paths"])

    manifest_rows, blind_rows, annotation_rows = [], [], []
    identity_errors = []
    for spec in specs["samples"]:
        try:
            commit = spec["commit"]
            actual_tree = git(repo, "rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
            if actual_tree != spec["tree"]:
                raise ValueError("commit tree mismatch")
            raw = git(repo, "cat-file", "blob", commit + ":" + spec["path"])
            actual_blob = git(repo, "rev-parse", "--verify", commit + ":" + spec["path"]).decode("ascii").strip()
            if actual_blob != hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest():
                raise ValueError("Git blob OID mismatch")
            if spec["path"] in model_paths:
                raise ValueError("sample path overlaps frozen model inputs")
            source = raw.decode("utf-8", "strict")
            ast = parse_source(source, "cpp")
            row = dict(spec)
            row.update({
                "repository": specs["repository"], "source_origin": "official GitHub repository; local pinned Git object",
                "blob": actual_blob, "source_sha256": sha256(raw), "bytes": len(raw),
                "parse_status": ast.parse_status, "parse_issue_count": len(ast.parse_issues),
                "parser": "scanner Tree-sitter light-ast", "parser_ast_sha256": freeze["parser_ast_sha256"],
                "tree_sitter_version": importlib.metadata.version("tree-sitter"),
                "tree_sitter_cpp_version": importlib.metadata.version("tree-sitter-cpp"),
                "independence_check": "path absent from frozen model inputs; not found in C1-C6 Ark Runtime experiment materials",
                "review_status": "pending_independent_review", "label": "", "reviewer_1_label": "",
                "reviewer_2_label": "", "adjudicated_label": "", "evidence_and_disagreement": "",
                "detector_prediction": "withheld_until_label_freeze", "execution_status": "not_run",
                "source_url": f"https://raw.githubusercontent.com/{specs['repository']}/{commit}/{spec['path']}"
            })
            manifest_rows.append(row)
            blind_rows.append({
                "blind_id": spec["blind_id"], "repository": specs["repository"], "commit": commit,
                "tree": actual_tree, "path": spec["path"], "blob": actual_blob,
                "source_sha256": row["source_sha256"], "bytes": len(raw),
                "source_url": row["source_url"], "review_scope": spec["review_scope"],
                "parser_status": ast.parse_status, "parser_issue_count": len(ast.parse_issues),
                "labels_allowed": "vulnerable|fixed|safe|unrelated|unknown",
                "instruction": "Review source and behavior independently. Do not infer a label from patch direction, commit chronology, or detector output. Cite source lines and explain uncertainty."
            })
            annotation_rows.append({
                "blind_id": spec["blind_id"], "reviewer_1_id": "", "reviewer_1_label": "",
                "reviewer_1_evidence": "", "reviewer_1_reasoning": "", "reviewer_1_submitted_utc": "",
                "reviewer_2_id": "", "reviewer_2_label": "", "reviewer_2_evidence": "",
                "reviewer_2_reasoning": "", "reviewer_2_submitted_utc": "",
                "disagreement_summary": "", "adjudicated_label": "", "adjudication_evidence": "",
                "label_snapshot_sha256": ""
            })
        except Exception as exc:
            identity_errors.append({"sample_id": spec["sample_id"], "status": "blocked_or_invalid", "error": str(exc)})
    if identity_errors:
        print(json.dumps({"errors": identity_errors}, ensure_ascii=False))
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(output_dir / "holdout_source_manifest.csv", manifest_rows, [
        "sample_id","blind_id","repository","component","commit","commit_date","tree","path","blob","source_sha256","bytes","source_origin","source_url","family_id","revision_role","split","strata","review_scope","parse_status","parse_issue_count","parser","parser_ast_sha256","tree_sitter_version","tree_sitter_cpp_version","independence_check","review_status","reviewer_1_label","reviewer_2_label","adjudicated_label","evidence_and_disagreement","detector_prediction","execution_status","patch_evidence_reference"
    ])
    write_csv(output_dir / "blind_review_packet.csv", blind_rows, [
        "blind_id","repository","commit","tree","path","blob","source_sha256","bytes","source_url","review_scope","parser_status","parser_issue_count","labels_allowed","instruction"
    ])
    write_csv(output_dir / "annotation_template.csv", annotation_rows, [
        "blind_id","reviewer_1_id","reviewer_1_label","reviewer_1_evidence","reviewer_1_reasoning","reviewer_1_submitted_utc","reviewer_2_id","reviewer_2_label","reviewer_2_evidence","reviewer_2_reasoning","reviewer_2_submitted_utc","disagreement_summary","adjudicated_label","adjudication_evidence","label_snapshot_sha256"
    ])
    print(json.dumps({"verified_sources": len(manifest_rows), "parse_status_counts": {s: sum(r["parse_status"] == s for r in manifest_rows) for s in sorted(set(r["parse_status"] for r in manifest_rows))}, "labels_frozen": False, "outputs": ["holdout_source_manifest.csv", "blind_review_packet.csv", "annotation_template.csv"]}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
