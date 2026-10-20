"""Offline, manifest-bound two-file regression across fixed detector revisions."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.indexing import environment_fingerprint

BASE = "6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f"
FIRST_INTEGRATION = "6f4f203ba4ab4dc811eb918a96bdd97531fddd08"
TARGET = "src/ohscanner/detectors/data/sensitive_exposure.py"


def detector_at(revision):
    source = subprocess.check_output(["git", "show", revision + ":" + TARGET], cwd=ROOT)
    module = types.ModuleType("src.ohscanner.detectors.data._t84_" + revision)
    module.__package__ = "src.ohscanner.detectors.data"
    sys.modules[module.__name__] = module
    exec(compile(source, revision + ":" + TARGET, "exec"), module.__dict__)
    return module.SensitiveExposureDetector, hashlib.sha256(source).hexdigest()


def verified_sample(name, local_path, git_dir=None):
    directory = ROOT / "research/data_sensitive"
    if name == "wifi":
        manifest_path = directory / "D40_WIFI_PRESHAREDKEY_PANEL_REPLAY.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {"repository": manifest["repository"], "commit": manifest["commit"],
                    "tree": manifest["tree"], "path": manifest["source_path"],
                    "blob": manifest["upstream_blob"],
                    "sha256": manifest["repeat_run_signatures"][0]["source_sha256"]}
    else:
        manifest_path = directory / "D27_IOTC_PANEL_REPLAY.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {"repository": manifest["repository"], "commit": manifest["commit"],
                    "tree": manifest["git_tree"], "path": manifest["include_paths"][0],
                    **manifest["runs"][0]["source"]}
    data = local_path.read_bytes()
    actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if hashlib.sha256(data).hexdigest() != expected["sha256"] or actual_blob != expected["blob"]:
        raise ValueError("source bytes do not match pinned manifest: " + name)
    expected.update(bytes=len(data), local_path=str(local_path.resolve()),
                    manifest=str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
                    manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                    byte_verification="SHA-256 and Git blob SHA-1 match existing pinned manifest",
                    commit_tree_verification="inherited from existing manifest; not reverified from local commit/tree objects")
    if git_dir is not None:
        environment = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="",
                           GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
        def git(*args):
            return subprocess.check_output(["git", "-C", str(git_dir), *args],
                                           env=environment, text=True).strip()
        if git("rev-parse", expected["commit"] + "^{commit}") != expected["commit"]:
            raise ValueError("commit identity mismatch: " + name)
        if git("rev-parse", expected["commit"] + "^{tree}") != expected["tree"]:
            raise ValueError("tree identity mismatch: " + name)
        entry = git("ls-tree", expected["commit"], "--", expected["path"])
        fields = entry.split()
        if len(fields) != 4 or fields[1] != "blob" or fields[2] != expected["blob"] or fields[3] != expected["path"]:
            raise ValueError("commit/path/blob mismatch: " + name)
        expected.update(git_dir=str(git_dir.resolve()),
                        commit_tree_verification="verified local commit/tree/path/blob objects with network disabled")
    language = "cpp" if expected["path"].endswith(".cpp") else "c"
    return expected, GitSource(expected["path"], language, actual_blob, data)


def signature(summary):
    return sorted((f["file"], f["line"], f["rule_id"], f["message"])
                  for f in summary["findings"])


def run(detector, context):
    start = time.perf_counter()
    result = detector().detect(context, context.units)
    seconds = time.perf_counter() - start
    return {"candidate_count": len(result.findings), "status": result.status,
            "seconds": seconds, "file_outcomes": list(result.file_outcomes),
            "coverage_counts": dict(Counter(state for _, state in result.file_outcomes)),
            "findings": [asdict(item) for item in result.findings],
            "limitations": list(result.limitations)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wifi-source", type=Path, required=True)
    parser.add_argument("--iot-source", type=Path, required=True)
    parser.add_argument("--wifi-git-dir", type=Path)
    parser.add_argument("--iot-git-dir", type=Path)
    parser.add_argument("--revision", default=FIRST_INTEGRATION)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    revisions = [BASE, FIRST_INTEGRATION]
    if args.revision not in revisions:
        revisions.append(args.revision)
    detectors = {}
    metadata = {}
    # Only sensitive_exposure changed in this comparison. Fail if loading its
    # historic implementation against current package dependencies is unsafe.
    dependencies = [p for p in subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", BASE,
         "src/ohscanner/detectors/data", "src/ohscanner/frontend.py",
         "src/ohscanner/contracts.py", "src/ohscanner/facts.py"], cwd=ROOT,
        text=True).splitlines() if p != TARGET]
    for revision in revisions:
        changed = subprocess.check_output(["git", "diff", "--name-only", BASE, revision,
                                           "--", *dependencies], cwd=ROOT, text=True).strip()
        if changed:
            raise ValueError("comparison requires revision-specific dependency loading: " + changed)
        detectors[revision], digest = detector_at(revision)
        metadata[revision] = {"version": detectors[revision].version,
                              "implementation_sha256": digest}
    output = {"experiment": "T84 fixed two-component single-file regression",
              "scope": "one selected source file per component; not whole-component coverage",
              "baseline": BASE, "revisions": metadata, "environment": environment_fingerprint(),
              "samples": [], "validated_vulnerability": 0,
              "limitations": [
                  "Previously used development samples, not independent accuracy labels.",
                  "Candidate changes measure behavior; they are not TP/FP/FN or precision/recall.",
                  "Commit/tree objects are locally verified only when an explicit git-dir is supplied; otherwise manifest binding is inherited.",
                  "No target execution, product inclusion, runtime visibility, or impact verification.",
                  "One file from each repository; omitted component files remain unexamined."]}
    for name, path, git_dir in (("wifi", args.wifi_source, args.wifi_git_dir),
                                ("iot", args.iot_source, args.iot_git_dir)):
        identity, source = verified_sample(name, path, git_dir)
        units, ast, parsing = index_sources((source,))
        request = ScanRequest("T84:" + name, identity["repository"], identity["commit"],
                              snapshot_digest(units), "current-component:" + identity["repository"],
                              profile_id="light-ast", provenance="fixture")
        context = ScanContext(request, units, {"ast": ast})
        runs = {rev: [run(detector, context), run(detector, context)]
                for rev, detector in detectors.items()}
        for revision, repeats in runs.items():
            if signature(repeats[0]) != signature(repeats[1]) or repeats[0]["file_outcomes"] != repeats[1]["file_outcomes"]:
                raise ValueError("nondeterministic result: " + name + " " + revision)
        baseline = set(signature(runs[BASE][0]))
        deltas = {rev: {"added": sorted(set(signature(repeats[0])) - baseline),
                        "removed": sorted(baseline - set(signature(repeats[0]))),
                        "same_source_and_parser": True,
                        "delta_attribution": "detector implementation only; dependencies verified unchanged"}
                  for rev, repeats in runs.items() if rev != BASE}
        output["samples"].append({"identity": identity, "snapshot_sha256": request.snapshot_sha256,
                                  "indexed_file_count": len(units), "parsing": parsing,
                                  "runs": runs, "repeat_signatures_equal": True, "delta": deltas})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(output, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(json.dumps({s["identity"]["repository"]: {rev: r[0]["candidate_count"]
                                                   for rev, r in s["runs"].items()}
                      for s in output["samples"]}))


if __name__ == "__main__":
    main()
