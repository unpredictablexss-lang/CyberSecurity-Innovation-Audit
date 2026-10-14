"""Container-side fixed AUTH-01 harness runner; invoked only by validation.py."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from src.ohscanner.poc import run_poc


def git(repo, *args, data=None):
    done = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(done.stderr.decode("utf-8", "replace")[-1000:])
    return done.stdout


def patched_target(repo, work, manifest):
    revisions = manifest["revisions"]
    vulnerable = revisions["vulnerable"]["commit"]
    fixed = revisions["fixed"]["commit"]
    source = next(x for x in manifest["sources"] if x["revision"] == "vulnerable")
    path = source["path"]
    clone = work / "patched-target"
    subprocess.run(["git", "init", "--quiet", str(clone)], check=True)
    git(clone, "remote", "add", "origin", str(repo))
    for commit in (vulnerable, fixed):
        git(clone, "fetch", "--quiet", "--depth", "1", "origin", commit)
    git(clone, "checkout", "--quiet", "--detach", vulnerable)
    patch = git(repo, "diff", "--binary", vulnerable, fixed, "--", path)
    if not patch:
        raise ValueError("pinned upstream fix produces an empty patch")
    patch_file = work / "auth01-upstream-fix.patch"
    patch_file.write_bytes(patch)
    git(clone, "apply", "--check", "-", data=patch)
    git(clone, "apply", "-", data=patch)
    patched_blob = (clone / path).read_bytes()
    expected = next(x["sha256"] for x in manifest["sources"] if x["revision"] == "fixed")
    actual = hashlib.sha256(patched_blob).hexdigest()
    if actual != expected:
        raise ValueError("applied patch output does not match the pinned fixed-source hash")
    git(clone, "add", "--", path)
    env = {**os.environ, "GIT_AUTHOR_NAME": "OHScanner validation", "GIT_AUTHOR_EMAIL": "local@invalid",
           "GIT_COMMITTER_NAME": "OHScanner validation", "GIT_COMMITTER_EMAIL": "local@invalid",
           "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
    done = subprocess.run(["git", "-C", str(clone), "commit", "--quiet", "-m", "OHScanner patch replay"],
                          env=env, capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(done.stderr.decode("utf-8", "replace")[-1000:])
    synthetic = git(clone, "rev-parse", "HEAD").decode().strip()
    manifest["revisions"]["patched"] = {"commit": synthetic, "expected": "no_trigger",
        "origin_commit": vulnerable, "fix_commit": fixed, "patch_sha256": hashlib.sha256(patch).hexdigest()}
    manifest["sources"].append({"revision": "patched", "commit": synthetic, "path": path, "sha256": actual})
    for case in manifest["cases"]:
        case["expect"]["patched"] = case["expect"]["fixed"]
    return clone, synthetic, hashlib.sha256(patch).hexdigest()


def gate(result):
    revisions = result["revisions"]
    if set(revisions) != {"vulnerable", "fixed", "patched"}:
        return False, "one or more pinned revisions were not tested"
    for run in revisions.values():
        if not run["build"]["returncode"] == 0:
            return False, "a target revision failed to build"
        if not all(run["expectations_met"].values()):
            return False, "a positive or negative control did not meet its expected outcome"
        if not run["replay"].get("all_cases_match"):
            return False, "repeated controls were unstable"
    if revisions["vulnerable"]["replay"]["label"] != "stable_reproduced":
        return False, "the vulnerable attack was not stably reproduced"
    if revisions["fixed"]["replay"]["label"] not in {"stable_rejected", "no_trigger"}:
        return False, "the upstream fixed revision did not stably reject attacks"
    if revisions["patched"]["replay"]["label"] not in {"stable_rejected", "no_trigger"}:
        return False, "the patch replay did not stably reject attacks"
    return True, "component harness controls passed; product reachability remains unproven"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--cutils", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--repeats", type=int, choices=[3], default=3)
    args = parser.parse_args()
    work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())
    clone, synthetic, patch_hash = patched_target(Path(args.target), work, manifest)
    local_manifest = work / "auth01-manifest.json"
    local_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    result = run_poc(local_manifest, clone, work / "poc", compiler="clang++", cutils_dir=args.cutils,
                     harness_dir=manifest_path.parent, repeats=args.repeats,
                     build_timeout=300, run_timeout=60).to_dict()
    passed, reason = gate(result)
    output = {"status": "completed_with_limitations", "case_id": None,
        "validation_gate": "passed" if passed else "not_passed", "gate_reason": reason,
        "result": result, "patched_revision": {"synthetic_commit": synthetic,
            "base_commit": manifest["revisions"]["vulnerable"]["commit"],
            "fixed_commit": manifest["revisions"]["fixed"]["commit"], "patch_sha256": patch_hash},
        "validated_vulnerability": 0,
        "limitations": ["Harness calls the component stub directly; product entry reachability is not proven.",
                        "Component-level reproduction does not establish a reportable product vulnerability."]}
    Path(args.out).write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()