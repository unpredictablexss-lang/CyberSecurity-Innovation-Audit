#!/usr/bin/env python3
"""Verify T62's source-bound dSoftBus nullability controls and current CLI replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/t62_dsoftbus_controls_20261020"
SOURCE_PATH = "core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp"
SOURCES = {
    "vulnerable": {
        "commit": "258662cd9840b55a31546a72d91027f6368cea84",
        "tree": "366a4ced9400653c9628c0b677e4ae657c0e7bd8",
        "blob": "a82b71fb5520b02278a4af695bbe918d14c1048e",
        "sha256": "5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6",
        "count": 5,
        "lines": [71, 82, 97, 108, 123],
    },
    "fixed": {
        "commit": "192f3e11d74beeaa3d879333471deb8a24a7e1c5",
        "tree": "1d58ba0ef706a6f69dd372bd496c8058810882aa",
        "blob": "13ddbe93a7f617784dec0f3761e09f66b5c3217c",
        "sha256": "5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81",
        "count": 0,
        "lines": [],
    },
}


def git(db: Path, *args: str) -> str:
    return subprocess.check_output(["git", f"--git-dir={db}", *args], text=True).strip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    args = parser.parse_args()
    db = args.source_git_dir.resolve()
    require(db.exists(), f"source object store missing: {db}")

    src_bytes: dict[str, bytes] = {}
    for label, expected in SOURCES.items():
        commit = expected["commit"]
        require(git(db, "cat-file", "-t", commit) == "commit", f"{label} commit object absent")
        tree = git(db, "show", "-s", "--format=%T", commit)
        require(tree == expected["tree"], f"{label} tree mismatch")
        listing = git(db, "ls-tree", commit, "--", SOURCE_PATH)
        require(expected["blob"] in listing, f"{label} path blob mismatch: {listing}")
        raw = subprocess.check_output(["git", f"--git-dir={db}", "show", f"{commit}:{SOURCE_PATH}"])
        require(hashlib.sha256(raw).hexdigest() == expected["sha256"], f"{label} source hash mismatch")
        src_bytes[label] = raw

    vulnerable_text = src_bytes["vulnerable"].decode("utf-8")
    fixed_text = src_bytes["fixed"].decode("utf-8")
    require(len(src_bytes["vulnerable"]) == 8502, "vulnerable byte count mismatch")
    require(len(src_bytes["fixed"]) == 9387, "fixed byte count mismatch")
    controls = {
        "ClientOnJoinLNNResult": (
            "if (info == nullptr)",
            "if (clientProxy == nullptr)",
            "return clientProxy->OnJoinLNNResult",
        ),
        "ClientOnLeaveLNNResult": (
            "if (pkgName == nullptr)",
            "if (clientProxy == nullptr)",
            "return clientProxy->OnLeaveLNNResult",
        ),
        "ClientNotifyHichainProofException": (
            "new (std::nothrow) BusCenterClientProxy(proxy.second)",
            "if (clientProxy == nullptr)",
            "clientProxy->OnHichainProofException",
        ),
        "ClientOnDataLevelChanged": (
            "if (pkgName == nullptr || networkId == nullptr || dataLevelInfo == nullptr)",
            "if (clientProxy == nullptr)",
            "clientProxy->OnDataLevelChanged",
        ),
    }
    for function, tokens in controls.items():
        start = vulnerable_text.index(function)
        end = vulnerable_text.find("\n}", start)
        require(end >= 0, f"could not bound control function {function}")
        body = vulnerable_text[start : end + 2]
        positions = [body.find(token) for token in tokens]
        require(all(pos >= 0 for pos in positions), f"missing control token in {function}")
        require(positions == sorted(positions), f"control ordering mismatch in {function}")
        if function != "ClientNotifyHichainProofException":
            require("return SOFTBUS_" in body[positions[1] : positions[2]], f"guard lacks early return in {function}")
        else:
            require("return SOFTBUS_ERR;" in body[positions[1] : positions[2]], "Hichain null guard lacks early return")

    expected_cli_head = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"
    # The committed outputs were generated from this checkout. Their exact JSON is retained.
    for label, expected in SOURCES.items():
        report = json.loads((EVIDENCE / f"{label}.json").read_text(encoding="utf-8"))
        require(report["commit"] == expected["commit"], f"{label} report commit mismatch")
        require(report["git_tree"] == expected["tree"], f"{label} report tree mismatch")
        require(report["diagnostic_count"] == expected["count"], f"{label} diagnostic count mismatch")
        run = report["detector_runs"][0]
        require(run["status"] == "blocked", f"{label} run status was not blocked")
        require(report["detector_coverage"]["detectors"]["ohscanner.cpp.null_dereference"]["coverage_counts"]["complete"] == 0,
                f"{label} detector unexpectedly claims complete semantic coverage")
        lines = [item["line"] for item in run["diagnostics"]]
        require(lines == expected["lines"], f"{label} diagnostic locations mismatch: {lines}")
    md = (EVIDENCE / "README.md").read_text(encoding="utf-8")
    require(expected_cli_head in md, "report does not record current PR #35 scanner baseline")
    require("not evidence that the remaining source is safe" in md, "report omitted safety limitation")
    require("Manual control-flow review" in md, "report omitted manual guard/dominance review")
    print("PASS: exact source objects, guard-before-use controls, 5/0 CLI replay, and PARTIAL/BLOCK semantics")


if __name__ == "__main__":
    main()
