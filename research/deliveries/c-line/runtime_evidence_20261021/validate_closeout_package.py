#!/usr/bin/env python3
"""Validate closeout references, statuses, blocker evidence, and package hashes."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


EVIDENCE_DIR = Path(__file__).resolve().parent
CLINE_DIR = EVIDENCE_DIR.parent
REPO_ROOT = EVIDENCE_DIR.parents[3]
SUMS = EVIDENCE_DIR / "SHA256SUMS.txt"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def markdown_links() -> None:
    documents = [
        CLINE_DIR / "typedarray_set_d1a58_source_component_report_20261021.md",
        EVIDENCE_DIR / "README.md",
    ]
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for document in documents:
        body = document.read_text(encoding="utf-8")
        for raw in link_pattern.findall(body):
            target = raw.split()[0]
            if target.startswith(("https://", "http://", "mailto:")):
                continue
            path_text, _, anchor = target.partition("#")
            path = (document.parent / unquote(path_text)).resolve() if path_text else document
            if not path.is_file():
                fail(f"broken Markdown reference in {document.name}: {target}")
            if anchor:
                headings = re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", path.read_text(encoding="utf-8"), re.M)
                slugs = {
                    re.sub(r"[^\w -]", "", heading.lower()).strip().replace(" ", "-")
                    for heading in headings
                }
                if unquote(anchor).lower() not in slugs:
                    fail(f"broken Markdown anchor in {document.name}: {target}")


def evidence_status() -> None:
    replay = json.loads((CLINE_DIR / "typedarray_set_d1a58_source_replay_20261021.json").read_text())
    harness = json.loads((CLINE_DIR / "typedarray_set_boundary_harness_20261021.json").read_text())
    task = json.loads((CLINE_DIR / "typedarray_set_offset_task_tree_20261021.json").read_text())
    if replay["source"]["commit"] != "d1a58d59166777e16574ceed64c15f0b2f44a76c":
        fail("d1a58 source commit mismatch")
    if replay["source"]["tree"] != "2cd854aa7d9f987de89d31a6a512e735779e75b6":
        fail("d1a58 source tree mismatch")
    if replay["candidate"]["backing_store_oob"] or replay["candidate"]["runtime_execution"] != "not_run":
        fail("source replay overstates runtime or backing-store evidence")
    if harness["ark_runtime_execution"] != "not_run" or harness["backing_store_oob"]:
        fail("component harness overstates runtime or backing-store evidence")
    if task["evidence"]["source_and_component_model"] != "COMPLETED":
        fail("source/component model is not marked complete")
    if task["evidence"]["component_harness"] != "COMPLETED_MODEL_AND_NODE_V8_CONTROL_ONLY":
        fail("component harness scope is not explicit")
    if task["status"] != "COMPLETED_WITH_BUILD_BLOCKER" or task["evidence"]["ark_runtime_execution"] != "NOT_RUN":
        fail("task terminal state is inconsistent")
    if task["evidence"]["product_impact"] != "UNKNOWN" or task["evidence"]["severity"] != "UNSCORED":
        fail("product impact/severity state overclaims evidence")
    if task["candidate_boundary"]["backing_store_oob_supported"]:
        fail("candidate boundary overstates backing-store evidence")
    regression = task["evidence"]["detector_regression"]
    if regression["passed"] != 11 or regression["failed"] != 0 or regression["exit_code"] != 0:
        fail("task regression count is not 11")
    if regression["code_commit"] != "45c2694dbcb9851dfd42f3663ba63e1b4d6d924a":
        fail("detector regression code commit is not pinned to the tested C-line revision")
    if regression["code_tree"] != "34473d7ed1f9e582ceb5ce4a85750ca70ee8712a":
        fail("detector regression code tree mismatch")
    if regression["command"] != "python -m unittest tests.detectors.ark_runtime.test_arraylike_set_bounds -v":
        fail("detector regression reproduction command mismatch")

    regression_log = (EVIDENCE_DIR / "detector_regression_11.log").read_text(encoding="utf-8")
    if "Ran 11 tests" not in regression_log or not regression_log.rstrip().endswith("OK"):
        fail("11-test regression log is incomplete or failing")
    regression_command = (EVIDENCE_DIR / "detector_regression_11.command.txt").read_text(encoding="utf-8")
    for expected in (regression["code_branch"], regression["code_commit"], regression["code_tree"], regression["command"]):
        if expected not in regression_command:
            fail(f"detector regression command record is missing {expected}")
    if (EVIDENCE_DIR / "detector_regression_11.exit").read_text().strip() != "0":
        fail("detector regression exit marker is not zero")
    if (EVIDENCE_DIR / "d1a58_source_replay.exit").read_text().strip() != "0":
        fail("source replay exit marker is not zero")
    if (EVIDENCE_DIR / "component_harness.exit").read_text().strip() != "0":
        fail("component harness exit marker is not zero")
    source_stdout = json.loads((EVIDENCE_DIR / "d1a58_source_replay.log").read_text(encoding="utf-8"))
    if source_stdout != replay:
        fail("source replay stdout differs from the recorded JSON artifact")
    component_stdout = json.loads((EVIDENCE_DIR / "component_harness.log").read_text(encoding="utf-8"))
    if component_stdout != harness:
        fail("component harness stdout differs from the recorded JSON artifact")
    if (EVIDENCE_DIR / "rk3568_shell_exit.txt").read_text().strip() != "255":
        fail("RK3568 natural exit marker mismatch")
    if (EVIDENCE_DIR / "host_selection_shell_exit.txt").read_text().strip() != "255":
        fail("host selection natural exit marker mismatch")
    if "weex-loader" not in (EVIDENCE_DIR / "rk3568_gn_error.log").read_text(encoding="utf-8"):
        fail("RK3568 GN blocker is missing")
    host_log = (EVIDENCE_DIR / "host_selection_hb_set.log").read_text(encoding="utf-8")
    if "run_application" not in host_log or "Code:        0000" not in host_log:
        fail("host HB blocker details are missing")


def hash_manifest(write: bool) -> None:
    evidence_files = sorted(
        path for path in EVIDENCE_DIR.rglob("*")
        if path.is_file() and path != SUMS
    )
    shared_files = [
        CLINE_DIR / "typedarray_set_d1a58_source_component_report_20261021.md",
        CLINE_DIR / "typedarray_set_d1a58_source_replay.py",
        CLINE_DIR / "typedarray_set_d1a58_source_replay_20261021.json",
        CLINE_DIR / "typedarray_set_boundary_harness_20261021.js",
        CLINE_DIR / "typedarray_set_boundary_harness_20261021.json",
        CLINE_DIR / "typedarray_set_offset_task_tree_20261021.json",
        REPO_ROOT / "docs" / "项目现状与下一步.md",
    ]
    files = sorted({*evidence_files, *shared_files})
    rows = [f"{sha256(path)}  {path.relative_to(REPO_ROOT).as_posix()}" for path in files]
    if write:
        SUMS.write_text("\n".join(rows) + "\n", encoding="utf-8")
    else:
        if not SUMS.is_file():
            fail("SHA256SUMS.txt is missing; run with --write-hashes")
        expected = SUMS.read_text(encoding="utf-8").splitlines()
        if expected != rows:
            fail("SHA-256 manifest is stale or mismatched; run with --write-hashes and review")


def main() -> None:
    write = sys.argv[1:] == ["--write-hashes"]
    if sys.argv[1:] not in ([], ["--write-hashes"]):
        fail("usage: python validate_closeout_package.py [--write-hashes]")
    markdown_links()
    evidence_status()
    hash_manifest(write)
    print("PASS: Markdown links, terminal status, 11-test result, both natural blockers, and SHA-256 manifest")


if __name__ == "__main__":
    main()
