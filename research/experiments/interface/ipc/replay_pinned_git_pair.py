"""Replay one fixed Git parent/patch pair over an explicit source-file scope.

Unlike the archived patch-file replay, this script reads blobs from pinned Git
objects and records both Git blob IDs and SHA-256 values. It is still a static
candidate regression, not product or exploit validation.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path, PurePosixPath

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout


def validate_commit(repo, commit):
    resolved = git(repo, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if resolved != commit:
        raise ValueError("commit must be a full resolved SHA: " + commit)
    return git(repo, "rev-parse", commit + "^{tree}").decode().strip()


def replay_side(repo, repository, commit, tree, paths):
    units, asts, files = [], {}, []
    for path in sorted(paths):
        posix = PurePosixPath(path)
        if posix.is_absolute() or ".." in posix.parts:
            raise ValueError("include path must stay inside the repository: " + path)
        object_spec = commit + ":" + path
        kind = git(repo, "cat-file", "-t", object_spec).decode().strip()
        if kind != "blob":
            raise ValueError("included path is not a Git blob: " + object_spec)
        raw = git(repo, "show", object_spec)
        text = raw.decode("utf-8", errors="replace")
        language = "c" if Path(path).suffix.lower() == ".c" else "cpp"
        parsed = parse_source(text, language=language)
        unit = SourceUnit(path, language, text, hashlib.sha256(raw).hexdigest(),
                          parsed.parse_status)
        units.append(unit)
        asts[path] = parsed.to_dict()
        files.append({
            "path": path,
            "git_blob": git(repo, "rev-parse", object_spec).decode().strip(),
            "source_sha256": unit.sha256,
            "parse_status": unit.parse_status,
        })
    request = ScanRequest("pinned-git-disclosure-pair", repository, commit,
                          snapshot_digest(tuple(units)), "current-component:" + repository)
    context = ScanContext(request, tuple(units), {"ast": asts})
    run = IpcInterfaceDetector().detect(context, tuple(units))
    findings = [{
        "file": item.file,
        "line": item.line,
        "rule_id": item.rule_id,
        "symbol": item.symbol,
        "message": item.message,
        "evidence_obligations": [
            {"kind": obligation.kind, "description": obligation.description}
            for obligation in item.evidence_obligations
        ],
    } for item in run.findings]
    return {
        "commit": commit,
        "tree": tree,
        "status": run.status,
        "files": files,
        "parse_counts": {
            "complete": sum(unit.parse_status == "complete" for unit in units),
            "partial": sum(unit.parse_status == "partial" for unit in units),
            "failed": sum(unit.parse_status == "failed" for unit in units),
        },
        "finding_count": len(findings),
        "findings": findings,
        "limitations": list(run.limitations),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--vulnerable", required=True)
    parser.add_argument("--fixed", required=True)
    parser.add_argument("--include", action="append", required=True,
                        help="repository-relative source file; repeat to add files")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo_dir.resolve()
    vulnerable_tree = validate_commit(repo, args.vulnerable)
    fixed_tree = validate_commit(repo, args.fixed)
    result = {
        "schema_version": 1,
        "experiment": "pinned_git_disclosure_pair_replay",
        "detector_id": IpcInterfaceDetector.detector_id,
        "detector_version": IpcInterfaceDetector.version,
        "model_version": IpcInterfaceDetector.model_version,
        "repository": args.repository,
        "scope": args.include,
        "product_or_exploit_validation": False,
        "vulnerable": replay_side(repo, args.repository, args.vulnerable,
                                  vulnerable_tree, args.include),
        "fixed": replay_side(repo, args.repository, args.fixed, fixed_tree, args.include),
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    print(json.dumps({
        "json_out": str(args.json_out),
        "detector_version": result["detector_version"],
        "model_version": result["model_version"],
        "vulnerable": {"status": result["vulnerable"]["status"],
                       "findings": result["vulnerable"]["finding_count"],
                       "parse": result["vulnerable"]["parse_counts"]},
        "fixed": {"status": result["fixed"]["status"],
                  "findings": result["fixed"]["finding_count"],
                  "parse": result["fixed"]["parse_counts"]},
    }, indent=2))


if __name__ == "__main__":
    main()
