"""Verify T61 libpng source identities, CLI results, and preserved queue baseline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
REPORT = EVIDENCE / "t61_libpng_independent_acceptance_20261030.json"


def git(git_dir: str, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def main() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    replay_path = EVIDENCE / report["independent_replay"]["artifact"]
    assert hashlib.sha256(replay_path.read_bytes()).hexdigest() == report["independent_replay"]["sha256"]
    replay = json.loads(replay_path.read_text(encoding="utf-8"))
    assert replay["detector_version"] == report["detector_version"] == "0.4.2"
    repos = {
        "33416": r"D:/openHarmonyScanner/tmp/libpng-gitlab-mirror-pins-20261019.git",
        "46675": r"D:/openHarmonyScanner/tmp/t34-libpng46675-source-20261023.git",
    }
    checks: dict[str, bool] = {}
    for case, variants in report["sources"].items():
        git_dir = repos[case]
        expected_files = ["pngset.c", "png.c", "pngread.c", "pngrtran.c"] if case == "33416" else ["pngrutil.c"]
        for variant in ("vulnerable", "fixed"):
            binding = variants[variant]
            commit_text = git(git_dir, "cat-file", "-p", binding["commit"])
            assert f"tree {binding['tree']}" in commit_text.splitlines()
            assert f"parent {binding['parent']}" in commit_text.splitlines()
            for path in expected_files:
                file_binding = binding["files"][path]
                entry = git(git_dir, "ls-tree", binding["commit"], path)
                assert entry.split()[2] == file_binding["blob"]
                data = git(git_dir, "show", f"{binding['commit']}:{path}", binary=True)
                assert hashlib.sha256(data).hexdigest() == file_binding["sha256"]
                assert len(data) == file_binding["bytes"]
                if case == "33416":
                    actual = replay["33416_full_files"][variant][path]
                else:
                    actual = replay["46675_full_files"][variant]
                assert actual["sha256"] == file_binding["sha256"]
            parent = binding["parent_object"]
            available = subprocess.run(
                ["git", f"--git-dir={git_dir}", "cat-file", "-e", parent["commit"]],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).returncode == 0
            assert available == parent["object_available_in_local_mirror"]
            if available:
                parent_text = git(git_dir, "cat-file", "-p", parent["commit"])
                assert f"tree {parent['tree']}" in parent_text.splitlines()
                if case == "46675":
                    entry = git(git_dir, "ls-tree", parent["commit"], "pngrutil.c")
                    assert entry.split()[2] == parent["pngrutil.c"]["blob"]
                    data = git(git_dir, "show", f"{parent['commit']}:pngrutil.c", binary=True)
                    assert hashlib.sha256(data).hexdigest() == parent["pngrutil.c"]["sha256"]
        checks[f"{case}_source_objects"] = True

    for case, variants in report["production_cli"].items():
        for variant, expected in variants.items():
            path = EVIDENCE / expected["artifact"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == expected["sha256"]
            cli = json.loads(path.read_text(encoding="utf-8"))
            run = next(x for x in cli["detector_runs"] if x["tool"] == report["detector"])
            assert cli["commit"] == expected["commit"]
            assert cli["git_tree"] == expected["tree"]
            assert cli["scope"]["selected_source_files"] == expected["scope_files"]
            assert cli["scope"]["selected_source_bytes"] == expected["scope_bytes"]
            assert cli["source_parsing"]["parsing_status"] == expected["parsing_status"]
            assert run["tool_version"] == expected["detector_version"] == report["detector_version"]
            assert run["status"] == expected["run_status"] == "blocked"
            assert run["diagnostic_count"] == expected["diagnostics"] == 0
        checks[f"{case}_production_cli"] = True

    queue = json.loads((EVIDENCE / report["queue_invariant"]["artifact"]).read_text(encoding="utf-8"))
    for key in ("overall_ok", "source_candidates", "queue_rows", "unique_queue_ids", "original_status_counts", "queue_status_counts"):
        assert queue[key] == report["queue_invariant"][key]
    assert queue["unique_queue_ids"] == 345
    checks["a0_prior_verified_baseline"] = True
    print(json.dumps({"overall_ok": all(checks.values()), "checks": checks,
                      "dispositions": report["acceptance"]}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
