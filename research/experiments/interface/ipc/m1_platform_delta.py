"""M1 before/after through the project's formal execution path.

Runs the production command (`python -m src.cli ohscan-run --detector
ohscanner.interface.ipc`) over exactly the persisted baseline scope, then reports
every candidate that disappeared, that was added, or that kept its identity but
changed the reason it states.

The baseline is the pre-M1 artifact set written by the component-audit driver
(rule 0.3.0, `candidates`); this run is the platform report the CLI emits
(`detector_runs[0].diagnostics` + the coverage sidecar). Both sides are keyed the
way the project's own verification script keys them --
(file, line, rule_id, source_sha256) -- so the rule_version move cannot hide a
real candidate change, and a reworded reason is reported separately.
"""
import collections
import hashlib
import json
import pathlib
import subprocess
import sys
import time

NAMES = ("security_access_token", "window_window_manager", "communication_dsoftbus",
         "update_updateservice", "distributeddatamgr_kv_store")


def baseline_key(candidate):
    return (candidate["file"], candidate["line"], candidate["rule_id"],
            candidate["source_sha256"])


def platform_candidates(report):
    """The run's candidates, with the coverage sidecar's obligations attached."""
    run = report["detector_runs"][0]
    coverage = report["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    sha = coverage["source_sha256"]
    proofs = {p["diagnostic_id"]: p for p in coverage["evidence_obligations"]}
    found = {}
    for item in run["diagnostics"]:
        proof = proofs.get(item["diagnostic_id"], {})
        record = dict(item)
        record["source_sha256"] = sha[item["file"]]
        record["obligations"] = proof.get("obligations", [])
        record["analysis_status"] = proof.get("analysis_status", "")
        found[(item["file"], item["line"], item["rule_id"], sha[item["file"]])] = record
    return found, coverage, run


def main():
    baseline_dir = pathlib.Path(sys.argv[1])
    out_dir = pathlib.Path(sys.argv[2])
    project = pathlib.Path(sys.argv[3]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    for name in NAMES:
        baseline = json.loads((baseline_dir / (name + ".json")).read_text())
        manifest = json.loads((baseline_dir / (name + ".manifest.json")).read_text())
        repo = manifest["source_repo_path"]
        paths = sorted(p for shard in baseline["scope"]["shards"] for p in shard["paths"])
        if len(paths) != len(set(paths)) or not paths:
            raise ValueError(name + ": baseline scope is not a unique explicit path set")
        output = out_dir / (name + ".json")
        markdown = out_dir / (name + ".md")
        command = [sys.executable, "-m", "src.cli", "ohscan-run",
                   "--repo-dir", repo,
                   "--repository", baseline["repository"],
                   "--commit", baseline["commit"],
                   "--detector", "ohscanner.interface.ipc",
                   "--json-out", str(output), "--md-out", str(markdown)]
        for path in paths:
            command.extend(("--include", path))
        print("START", name, "files=", len(paths), flush=True)
        start = time.perf_counter()
        done = subprocess.run(command, cwd=str(project), text=True, capture_output=True)
        (out_dir / (name + ".terminal.txt")).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError(name + ": " + done.stderr[-3000:])
        report = json.loads(output.read_text())
        if report["scope"]["selected_source_files"] != len(paths):
            raise AssertionError(name + ": source scope drifted")
        if report["validated_vulnerability"] != 0:
            raise AssertionError(name + ": validated_vulnerability is not zero")

        old = {baseline_key(c): c for c in baseline["candidates"]}
        new, coverage, run = platform_candidates(report)
        removed, added = sorted(set(old) - set(new)), sorted(set(new) - set(old))
        kept = set(old) & set(new)
        reworded = sorted(k for k in kept if old[k]["message"] != new[k]["message"])
        still_reported = collections.Counter(c["file"] for c in report["candidates"]
                                             ) if "candidates" in report else collections.Counter(
            item["file"] for item in run["diagnostics"])

        print("RESULT", name, "baseline=", len(old), "-> now=", len(new),
              "removed=", len(removed), "added=", len(added), "reworded=", len(reworded),
              flush=True)
        for k in removed:
            print("  REMOVED  %s:%s  %s" % (k[0], k[1], k[2]))
            print("           was: %s" % old[k]["message"][:300])
            print("           same file still reported %d time(s)"
                  % still_reported.get(k[0], 0))
        for k in added:
            print("  ADDED    %s:%s  %s" % (k[0], k[1], k[2]))
            print("           now: %s" % new[k]["message"][:300])
        for k in reworded:
            print("  REWORDED %s:%s  %s" % (k[0], k[1], k[2]))
            print("           was: %s" % old[k]["message"][:300])
            print("           now: %s" % new[k]["message"][:300])

        summaries.append({
            "component": name,
            "repository": report["repository"], "commit": report["commit"],
            "git_tree": report["git_tree"], "snapshot_sha256": report["snapshot_sha256"],
            "indexed_files": len(paths),
            "baseline_candidates": len(old), "candidates": len(new),
            "removed": [list(k) for k in removed],
            "added": [list(k) for k in added],
            "reworded": [list(k) for k in reworded],
            "removed_detail": [{
                "file": k[0], "line": k[1], "rule_id": k[2],
                "baseline_message": old[k]["message"],
                "baseline_rule_version": old[k]["rule_version"],
                "baseline_confidence": old[k]["confidence"],
                "baseline_severity": old[k]["severity"],
                "baseline_symbol": old[k].get("symbol", ""),
                "baseline_evidence_type": old[k]["evidence_type"],
                "baseline_obligation_kinds": sorted(
                    {o["kind"] for o in old[k].get("obligations", [])}),
            } for k in removed],
            "kept_detail": [{
                "file": k[0], "line": k[1], "rule_id": k[2],
                "symbol": new[k].get("symbol", ""),
                "message": new[k]["message"],
                "obligation_kinds": sorted({o["kind"] for o in new[k]["obligations"]}),
                "analysis_status": new[k]["analysis_status"],
            } for k in sorted(kept)],
            "rule_versions": sorted({c["rule_version"] for c in baseline["candidates"]}
                                    ) + ["->"] + [run.get("tool_version", "")],
            "tool_version": run["tool_version"],
            "model_versions": sorted({p["model_version"]
                                      for p in coverage["evidence_obligations"]}),
            "per_rule": dict(collections.Counter(
                item["rule_id"] for item in run["diagnostics"])),
            "candidates_with_obligations": sum(bool(p["obligations"])
                                               for p in coverage["evidence_obligations"]),
            "coverage_status": coverage["status"],
            "coverage_counts": coverage["coverage_counts"],
            "applicable_files": coverage["applicable_files"],
            "unexamined_files": len(coverage["unexamined"]),
            "not_analyzed_files": len(coverage["not_analyzed_files"]),
            "validated_vulnerability": report["validated_vulnerability"],
            "elapsed_seconds": round(time.perf_counter() - start, 3),
            "command": command,
            "artifacts": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (output, markdown)},
        })
    (out_dir / "m1_delta.json").write_text(
        json.dumps(summaries, ensure_ascii=False, indent=2) + "\n")
    print("wrote", out_dir / "m1_delta.json")


if __name__ == "__main__":
    main()
