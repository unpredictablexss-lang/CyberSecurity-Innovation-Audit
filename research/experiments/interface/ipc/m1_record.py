"""One record for the M1 experiment: what ran, where, on which bytes, and the result.

Prints the environment, the command for each component, the artifact checksums, the
before/after counts, and one line per removed candidate with the guard that removed
it, so the whole measurement can be replayed and each claim checked against a hash.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, sys.argv[3] if len(sys.argv) > 3 else ".")


def main():
    out_dir = pathlib.Path(sys.argv[1])
    basis_path = pathlib.Path(sys.argv[2])
    delta = json.loads((out_dir / "m1_delta.json").read_text())
    basis = json.loads(basis_path.read_text())
    record = {
        "experiment": "M1 descriptor interface identity",
        "date": "2026-10-11",
        "rule": "ipc.relay.descriptor-boundary",
        "tool_version": delta[0]["tool_version"],
        "model_versions": delta[0]["model_versions"],
        "baseline_rule_versions": delta[0]["rule_versions"][0],
        "environment": json.loads(subprocess.run(
            [sys.executable, "-c",
             "import json,sys,tree_sitter,tree_sitter_c,tree_sitter_cpp;"
             "print(json.dumps({'python':sys.version.split()[0],"
             "'tree_sitter':tree_sitter.__version__ if hasattr(tree_sitter,'__version__') else 'n/a',"
             "'tree_sitter_c':getattr(tree_sitter_c,'__version__','n/a'),"
             "'tree_sitter_cpp':getattr(tree_sitter_cpp,'__version__','n/a')}))"],
            capture_output=True, text=True).stdout),
        "delta_artifact": {"path": str(out_dir / "m1_delta.json"),
                           "sha256": hashlib.sha256(
                               (out_dir / "m1_delta.json").read_bytes()).hexdigest()},
        "basis_artifact": {"path": str(basis_path),
                           "sha256": hashlib.sha256(basis_path.read_bytes()).hexdigest()},
        "components": [],
    }
    by_key = {(b["component"], b["file"], b["line"]): b for b in basis}
    for component in delta:
        record["components"].append({
            "component": component["component"],
            "repository": component["repository"], "commit": component["commit"],
            "git_tree": component["git_tree"], "snapshot_sha256": component["snapshot_sha256"],
            "indexed_files": component["indexed_files"],
            "baseline_candidates": component["baseline_candidates"],
            "candidates": component["candidates"],
            "removed": len(component["removed"]), "added": len(component["added"]),
            "reworded": len(component["reworded"]),
            "candidates_with_obligations": component["candidates_with_obligations"],
            "validated_vulnerability": component["validated_vulnerability"],
            "coverage_status": component["coverage_status"],
            "coverage_counts": component["coverage_counts"],
            "command": " ".join(component["command"]),
            "report_sha256": component["artifacts"][str(out_dir / (component["component"]
                                                                   + ".json"))],
            "removed_detail": [dict(b, _component=component["component"]) for b in basis
                               if b["component"] == component["component"]],
        })
    print(json.dumps(record, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
