"""M2 before/after through the project's formal execution path.

Runs the production command (`python -m src.cli ohscan-run --detector
ohscanner.interface.ipc`) over exactly the scope the M1 platform reports persisted,
and reports every candidate that disappeared, that was added, or that kept its
identity but changed the reason it states.

Topology. `src/ohscanner/detectors/catalog.py` is the project owner's registry and
lives in the integration worktree, whose `interface/` package is a snapshot from
before M1. The CLI is therefore run from a scratch copy of that worktree with
teammate B's `interface/` package overlaid (plus the owner's `m2_adapter.py`, which
only wraps execution depth) -- so the registered detector id resolves to the code
under measurement. `--project-dir` names that copy.

Both sides are the platform report shape, keyed the way the project's own
verification script keys them -- (file, line, rule_id, source_sha256) -- so the rule
identity moving 0.4.0 -> 0.5.0 cannot hide a real candidate change, and a reworded
reason is reported separately.

    python research/experiments/interface/ipc/m2_platform_delta.py \
        --baseline-dir outputs/reports/m1_descriptor_identity \
        --out-dir outputs/reports/m2_relay_guard \
        --project-dir /tmp/m2_platform
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

NAMES = ("security_access_token", "window_window_manager", "communication_dsoftbus",
         "update_updateservice", "distributeddatamgr_kv_store")


def platform_candidates(report):
    """The run's candidates, with each file's source hash attached."""
    run = report["detector_runs"][0]
    coverage = report["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    sha = coverage["source_sha256"]
    found = {}
    for item in run["diagnostics"]:
        found[(item["file"], item["line"], item["rule_id"], sha[item["file"]])] = item
    return found, coverage, run


def binding_of(report):
    """The versions the run actually bound to, read off the coverage sidecar."""
    coverage = report["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    obligations = coverage["evidence_obligations"] or [{}]
    binding = obligations[0].get("source_binding") or {}
    run = report["detector_runs"][0]
    return {
        "detector_version": run["tool_version"],
        "bound_detector_version": binding.get("detector_version"),
        "commit": report["commit"], "snapshot_sha256": report["snapshot_sha256"],
        "profile_id": report.get("profile_id"), "coverage_status": coverage["status"],
        "coverage_counts": coverage["coverage_counts"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", required=True,
                        help="platform reports of the previous run (the 'before')")
    parser.add_argument("--out-dir", required=True, help="where this run writes")
    parser.add_argument("--project-dir", required=True,
                        help="project copy whose catalog.py registers the detector")
    parser.add_argument("--component", action="append", default=None,
                        help="restrict to one component; repeatable")
    parser.add_argument("--baseline-manifest-dir",
                        help="where <component>.manifest.json lives, if not the baseline dir")
    args = parser.parse_args(argv)

    baseline_dir = pathlib.Path(args.baseline_dir).resolve()
    manifest_dir = pathlib.Path(args.baseline_manifest_dir or args.baseline_dir).resolve()
    out_dir = pathlib.Path(args.out_dir).resolve()
    project = pathlib.Path(args.project_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    for name in (args.component or NAMES):
        baseline = json.loads((baseline_dir / (name + ".json")).read_text())
        manifest = json.loads((manifest_dir / (name + ".manifest.json")).read_text())
        paths = sorted(baseline["scope"]["declared_scope"])
        # The scope has to be the one the baseline itself recorded, given path by
        # path: a prefix rule would silently widen or narrow the comparison.
        if len(paths) != baseline["scope"]["selected_source_files"]:
            raise AssertionError("%s: declared scope is not the selected path set" % name)
        output = out_dir / (name + ".json")
        command = [sys.executable, "-m", "src.cli", "ohscan-run",
                   "--repo-dir", manifest["source_repo_path"],
                   "--repository", baseline["repository"],
                   "--commit", baseline["commit"],
                   "--detector", "ohscanner.interface.ipc",
                   "--json-out", str(output), "--md-out", str(out_dir / (name + ".md"))]
        for path in paths:
            command.extend(("--include", path))
        print("START", name, "files=", len(paths), flush=True)
        start = time.perf_counter()
        done = subprocess.run(command, cwd=str(project), text=True, capture_output=True)
        (out_dir / (name + ".terminal.txt")).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError(name + ": " + done.stderr[-3000:])
        elapsed = time.perf_counter() - start
        report = json.loads(output.read_text())
        if report["scope"]["selected_source_files"] != len(paths):
            raise AssertionError(name + ": source scope drifted")
        if report["validated_vulnerability"] != 0:
            raise AssertionError(name + ": validated_vulnerability is not zero")

        old, _, _ = platform_candidates(baseline)
        new, _, _ = platform_candidates(report)
        removed, added = sorted(set(old) - set(new)), sorted(set(new) - set(old))
        kept = set(old) & set(new)
        reworded = sorted(k for k in kept if old[k]["message"] != new[k]["message"])

        print("RESULT %s  baseline=%d -> now=%d  removed=%d added=%d reworded=%d  %.1fs"
              % (name, len(old), len(new), len(removed), len(added), len(reworded), elapsed),
              flush=True)
        for k in removed:
            print("  REMOVED  %s:%s  %s" % (k[0], k[1], k[2]))
            print("           was: %s" % old[k]["message"][:300])
            print("           file still reported %d time(s)"
                  % sum(1 for x in new if x[0] == k[0]))
        for k in added:
            print("  ADDED    %s:%s  %s" % (k[0], k[1], k[2]))
            print("           now: %s" % new[k]["message"][:300])
        for k in reworded:
            print("  REWORDED %s:%s  %s" % (k[0], k[1], k[2]))
            print("           was: %s" % old[k]["message"][:300])
            print("           now: %s" % new[k]["message"][:300])

        summaries.append({
            "component": name, "repository": report["repository"],
            "commit": report["commit"], "git_tree": report.get("git_tree"),
            "snapshot_sha256": report.get("snapshot_sha256"),
            "indexed_files": len(paths), "elapsed_seconds": round(elapsed, 2),
            "baseline_candidates": len(old), "candidates": len(new),
            "removed": [list(k) for k in removed], "added": [list(k) for k in added],
            "reworded": [list(k) for k in reworded],
            "before_binding": binding_of(baseline), "after_binding": binding_of(report),
            "removed_detail": [{"file": k[0], "line": k[1], "rule_id": k[2],
                                "was": old[k]["message"]} for k in removed],
        })
        print(flush=True)

    delta = out_dir / "m2_delta.json"
    delta.write_text(json.dumps(summaries, ensure_ascii=False, indent=1))
    print("TOTAL baseline=%d -> now=%d  removed=%d added=%d reworded=%d"
          % (sum(s["baseline_candidates"] for s in summaries),
             sum(s["candidates"] for s in summaries),
             sum(len(s["removed"]) for s in summaries),
             sum(len(s["added"]) for s in summaries),
             sum(len(s["reworded"]) for s in summaries)))
    print("delta:", delta)


if __name__ == "__main__":
    main()
