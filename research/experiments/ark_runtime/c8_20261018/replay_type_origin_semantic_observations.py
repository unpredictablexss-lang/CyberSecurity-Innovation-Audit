"""Replay the local TypeOrigin analyzer over pinned Ark Runtime Git objects.

This is a research sidecar. The production entry-point result remains in the
paired ohscan-run JSON/Markdown reports. No fetch or source synchronization is
performed here.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.parser.ast import parse_source


TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
CASES = (
    ("i11196_direct_parent", "2ea501258ab4155826b64f01b499b43d1911e0e2", "official"),
    ("i11196_direct_fix", "919e4fbb011f610427e788889083fa8e28d2f951", "official"),
    ("i11684_safe_parent", "bcf67a5df41bcf37b94d848812e54884f6bedb95", "official"),
    ("i11684_safe_fix", "b362fab4f80c7466b1a33d882fa65b828d952712", "official"),
    ("a65_product_snapshot", "a65a2853ccae13da167d9aa4720ab8b11ec16656", "history"),
    ("official_master", "d1a58d59166777e16574ceed64c15f0b2f44a76c", "official"),
)


def git(repo, *args):
    return subprocess.check_output(["git", f"--git-dir={repo}", *args])


def replay(label, commit, repo):
    source = git(repo, "show", f"{commit}:{TARGET}")
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    blob = git(repo, "rev-parse", f"{commit}:{TARGET}").decode().strip()
    text = source.decode("utf-8")
    parsed = parse_source(text, "cpp")
    unit = SourceUnit(TARGET, "cpp", text, hashlib.sha256(source).hexdigest(),
                      parsed.parse_status, tuple(parsed.parse_issues))
    result = analyze_unit(unit, research_partial=True)
    return {
        "case": label,
        "repository": "openharmony/arkcompiler_ets_runtime",
        "commit": commit,
        "tree": tree,
        "path": TARGET,
        "blob": blob,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "scope": "one exact translation unit; light AST; no preprocessor or build profile",
        "direct_analyzer_result": asdict(result),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-git-dir", required=True)
    parser.add_argument("--history-git-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = []
    for label, commit, source_repo in CASES:
        repo = args.official_git_dir if source_repo == "official" else args.history_git_dir
        rows.append(replay(label, commit, repo))
    output = {"schema_version": 1, "replay_kind": "research_direct_analyzer_observations",
              "fetch_performed": False, "cases": rows}
    Path(args.output).write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")


if __name__ == "__main__":
    main()
