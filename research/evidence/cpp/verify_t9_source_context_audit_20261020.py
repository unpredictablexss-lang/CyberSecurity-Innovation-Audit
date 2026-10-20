from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = Path(__file__).resolve().parent
TMP = Path(r"D:\openHarmonyScanner\tmp\t9-preprocessed")
REPOS = Path(r"D:\openHarmonyScanner\tmp\t9-source-context-20261020")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def main() -> None:
    source_targets = {
        "33416": {
            "repo": "libpng33416", "parent": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
            "file": "pngset.c", "sha256": "9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0",
        },
        "33416-fixed": {
            "repo": "libpng33416-fixed", "parent": "d5515b5b8be3901aac04e5bd8bd5c89f287bcd33",
            "file": "pngset.c", "sha256": "d3a203e40b6a6000a7cb78a61e0fd9664b0c39a65d82260efedb0f0184a8bc19",
        },
        "46675": {
            "repo": "libpng46675", "parent": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
            "file": "pngrutil.c", "sha256": "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e",
        },
        "46675-fixed": {
            "repo": "libpng46675-fixed", "parent": "aa77ef38c17ab2fc1b41bec09fb973c6a386641d",
            "file": "pngrutil.c", "sha256": "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e",
        },
    }
    roles = {
        "33416-vuln": ("33416", "33416-vuln-pngset.c.i", "33416-vuln-cli.json"),
        "33416-fixed": ("33416-fixed", "33416-fixed-pngset.c.i", "33416-fixed-cli.json"),
        "46675-vuln": ("46675", "46675-vuln-pngrutil.c.i", "46675-vuln-cli.json"),
        "46675-fixed": ("46675-fixed", "46675-fixed-pngrutil.c.i", "46675-fixed-cli.json"),
    }
    outputs = {}
    for role, (source_key, preprocessed_name, cli_name) in roles.items():
        binding = source_targets[source_key]
        repo = REPOS / binding["repo"]
        derived = git(repo, "rev-parse", "HEAD")
        parent = git(repo, "rev-parse", "HEAD^" )
        assert parent == binding["parent"]
        pre = TMP / preprocessed_name
        cli_path = TMP / cli_name
        cli = json.loads(cli_path.read_text(encoding="utf-8"))
        run = next(x for x in cli["detector_runs"] if x["tool"] == "ohscanner.cpp.resource_lifetime")
        assert cli["commit"] == derived
        assert run["tool_version"] == "0.4.2" and run["status"] == "blocked" and run["diagnostic_count"] == 0
        assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
        source_blob = subprocess.check_output(["git", "-C", str(repo), "show", f"{parent}:{binding['file']}"])
        assert hashlib.sha256(source_blob).hexdigest() == binding["sha256"]
        assert b'"' + binding["file"].encode() + b'"' in pre.read_bytes()[:256]
        outputs[role] = {
            "upstream_parent_commit": parent,
            "upstream_target_sha256": binding["sha256"],
            "derived_preprocessed_commit": derived,
            "preprocessed_artifact": preprocessed_name,
            "preprocessed_bytes": pre.stat().st_size,
            "preprocessed_sha256": sha(pre),
            "source_map": "GCC #line markers retained",
            "cli_report": cli_name,
            "cli_report_sha256": sha(cli_path),
            "parse": cli["source_parsing"]["parsing_status"],
            "detector": run["tool"],
            "detector_version": run["tool_version"],
            "detector_status": run["status"],
            "findings": run["diagnostic_count"],
        }

    tiff = {}
    for role, path, expected in (
        ("vulnerable", TMP / "tiff-vuln.i", "502c806ef700126e4bb8fb9e15f4512c89a136c831466f3f3229141835f1cfc5"),
        ("fixed", TMP / "tiff-fixed.i", "1edf650ada64cff5c6d0e91767812789b8764c83bbcae583bce604199389a061"),
    ):
        assert sha(path) == expected
        tiff[role] = {"artifact": path.name, "bytes": path.stat().st_size, "sha256": expected,
                      "source_map": "GCC #line markers retained", "cli": "not_run: local promisor mirror lacks ancestor c6b523b5911c298a3e099c380a79446ad207b21e"}

    t61 = subprocess.check_output(["python", str(EVIDENCE / "verify_t61_libpng_acceptance_20261020.py")], text=True)
    t6 = subprocess.check_output(["python", str(EVIDENCE / "verify_t6_remaining_matrix_replay_20261020.py"), "--scanner-repo", str(ROOT)], text=True)
    t23 = subprocess.check_output(["python", str(EVIDENCE / "verify_t23_supervisor_race_acceptance.py")], text=True)
    assert json.loads(t61)["overall_ok"]
    assert "PASS" in t6
    assert json.loads(t23)["overall_ok"]
    scanner_diff = subprocess.check_output(["git", "diff", "81dd4aea9bb51522ac912b33504ef0d2ddb79089", "--", "src"], cwd=ROOT)
    assert not scanner_diff

    record = {
        "schema_version": 1,
        "task": "T9 exact-source build-context and preprocessed CLI audit",
        "scanner_worktree_head": git(ROOT, "rev-parse", "HEAD"),
        "scanner_baseline": "81dd4aea9bb51522ac912b33504ef0d2ddb79089",
        "scanner_src_matches_baseline": True,
        "cases": {"libpng_33416": "PARTIAL/BLOCK", "libpng_46675": "PARTIAL/BLOCK", "libtiff_9900": "PARTIAL/BLOCK"},
        "libpng_preprocessed_cli": outputs,
        "libtiff_preprocessed": tiff,
        "verifiers": {"t61": "PASS", "t6": "PASS", "t23_a0": "PASS; 345 IDs/status baseline retained"},
        "interpretation": "Exact-source preprocessing with upstream/CMake compile context was obtained. The scanner still reports partial/blocked for both libpng preprocessed source files; libtiff source-mapped preprocessed inputs were generated but CLI replay could not be constructed from the available promisor mirror. No zero finding is a safe/fixed conclusion. No source, detector, test, fixture, or A0 data changed.",
    }
    (EVIDENCE / "t9_source_context_audit_20261020.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"overall_ok": True, "cases": record["cases"], "verifiers": record["verifiers"]}, indent=2))


if __name__ == "__main__":
    main()
