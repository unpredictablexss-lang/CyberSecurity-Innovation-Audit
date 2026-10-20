"""One bounded scanner process, never imports browser-supplied module names."""

import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import sys
from src.ohscanner.execution import run_fixed_commit_scan, write_report_json
from src.ohscanner.git_source import load_git_sources
from src.workbench.service import engine_fingerprint
from src.workbench.store import Store


def main():
    data_dir, key, expected_parent = sys.argv[1:]
    # Linux: abrupt Worker death must not leave the scanner running indefinitely.
    libc = ctypes.CDLL(None)
    if libc.prctl(1, signal.SIGKILL) != 0 or os.getppid() != int(expected_parent):
        raise RuntimeError("worker parent unavailable")
    store = Store(Path(data_dir))
    job = store.job(key)
    spec = job["spec"]
    memory = spec["memory_mb"] * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(
        resource.RLIMIT_CPU, (spec["timeout_seconds"] + 5, spec["timeout_seconds"] + 10)
    )
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    if engine_fingerprint() != spec["engine_sha256"]:
        raise ValueError(
            "scanner implementation changed after task creation; retry with a new snapshot"
        )
    repo = store.repository(job["repository_id"])
    root = Path(repo["path"])
    commit, tree, sources, _ = load_git_sources(
        root, spec["commit"], tuple(spec["include_paths"])
    )
    if tree != spec["git_tree"]:
        raise ValueError("pinned tree mismatch")
    store.event(
        key,
        "source_loaded",
        f"Loaded {len(sources)} fixed Git source files; preparing parser and detectors",
    )
    out = Path(data_dir) / "artifacts" / key
    store.event(
        key,
        "core_running",
        "Running shared parser and approved detectors; no estimated percentage",
    )
    report = run_fixed_commit_scan(
        root,
        spec["repository"],
        commit,
        tuple(spec["include_paths"]),
        tuple(spec["detector_ids"]),
        out / "report.json",
        out / "report.md",
        expected_plan=spec.get("audit_plan"),
    )
    if engine_fingerprint() != spec["engine_sha256"]:
        raise ValueError("scanner implementation changed during task execution")
    import hashlib

    report["_workbench"] = {
        "engine_sha256": spec["engine_sha256"],
        "total_source_lines": sum(len(s.data.splitlines()) for s in sources),
        "execution_boundary": {
            "kind": "local_static_scan_process",
            "hard_task_timeout_seconds": spec["timeout_seconds"],
            "address_space_limit_mb": spec["memory_mb"],
            "per_detector_hard_timeout": False,
            "untrusted_build_sandbox": False,
        },
        "markdown_sha256": hashlib.sha256((out / "report.md").read_bytes()).hexdigest(),
        "source_inventory": [
            {
                "file": s.path,
                "blob": s.oid,
                "sha256": hashlib.sha256(s.data).hexdigest(),
                "archive_binding": s.archive_binding,
            }
            for s in sources
        ],
    }
    write_report_json(report, out / "report.json")
    store.event(
        key,
        "report_written",
        "Core execution completed; verifying report before publishing",
    )
    print(
        json.dumps(
            {"status": report["status"], "candidate_count": report["diagnostic_count"]}
        )
    )


if __name__ == "__main__":
    main()
