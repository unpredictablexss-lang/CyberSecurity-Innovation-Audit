"""Seed a real OpenHarmony product-component browser audit without touching its dirty worktree."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner.git_source import load_git_sources
from src.workbench import service
from src.workbench.settings import Settings
from src.workbench.store import Store


PRODUCT_REPOSITORY = "openharmony/inputmethod_imf"
PRODUCT_COMMIT = "e663b47013d534a56165ab7467fbb3e14bf7172b"
PRODUCT_TREE = "5037e995cb4f3f29d54307b6e0fbf352cc9d6252"
COMPONENT_REPOSITORY = "openharmony/commonlibrary_c_utils"
COMPONENT_COMMIT = "b807d3dadb7dbb7639fe85b3a5f72da18d318da2"
COMPONENT_TREE = "52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d"
DETECTOR = "ohscanner.interface.ipc"


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_binding(repo, commit, tree):
    observed_commit = git(repo, "rev-parse", "HEAD")
    observed_tree = git(repo, "rev-parse", "HEAD^{tree}")
    subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", commit + "^{commit}"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", tree + "^{tree}"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if observed_commit != commit or observed_tree != tree:
        raise RuntimeError(
            f"fixed checkout moved: commit={observed_commit} tree={observed_tree}"
        )
    status = git(repo, "status", "--porcelain=v1", "--branch")
    dirty = [line for line in status.splitlines() if not line.startswith("##")]
    return {
        "repository": str(repo),
        "head_commit": observed_commit,
        "head_tree": observed_tree,
        "dirty_file_count": len(dirty),
        "dirty_status_sha256": digest(status.encode("utf-8")),
        "preservation": "read-only Git object scan; checkout was not reset, cleaned, or overwritten",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--product-repo",
        type=Path,
        default=Path("/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf"),
    )
    parser.add_argument(
        "--component-repo",
        type=Path,
        default=Path("/home/audit/openharmony-targets/commonlibrary_c_utils"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit("real-product browser acceptance root must be absent or empty")
    root.mkdir(parents=True, exist_ok=True)

    product_repo = args.product_repo.resolve()
    component_repo = args.component_repo.resolve()
    product_binding = verify_binding(product_repo, PRODUCT_COMMIT, PRODUCT_TREE)
    component_binding = verify_binding(component_repo, COMPONENT_COMMIT, COMPONENT_TREE)

    targets = root / "targets"
    targets.mkdir()
    settings = Settings(
        root / "data",
        (product_repo.parent, component_repo.parent),
    )
    settings.initialize()
    store = Store(settings.data_dir)
    product = store.add_repository(PRODUCT_REPOSITORY, str(product_repo))
    component = store.add_repository(COMPONENT_REPOSITORY, str(component_repo))

    exact_command = [
        "python",
        "-m",
        "src.cli",
        "ohscan-run",
        "--repo-dir",
        str(product_repo),
        "--repository",
        PRODUCT_REPOSITORY,
        "--commit",
        PRODUCT_COMMIT,
        "--include",
        ".",
        "--detector",
        DETECTOR,
    ]
    spec = service.make_spec(product, PRODUCT_COMMIT, ["."], [DETECTOR], 300, 2048)
    job = store.create_job(product["id"], spec)
    store.claim()
    artifacts = service.artifact_dir(settings, job["id"])
    artifacts.mkdir(parents=True, exist_ok=False)
    report = run_fixed_commit_scan(
        product_repo,
        PRODUCT_REPOSITORY,
        PRODUCT_COMMIT,
        (".",),
        (DETECTOR,),
        artifacts / "report.json",
        artifacts / "report.md",
    )
    _, _, sources, _ = load_git_sources(product_repo, PRODUCT_COMMIT, (".",))
    report["_workbench"] = {
        "engine_sha256": service.engine_fingerprint(),
        "total_source_lines": sum(len(source.data.splitlines()) for source in sources),
        "execution_boundary": {
            "kind": "local_static_scan_process",
            "hard_task_timeout_seconds": 300,
            "address_space_limit_mb": 2048,
            "per_detector_hard_timeout": False,
            "untrusted_build_sandbox": False,
        },
        "markdown_sha256": digest((artifacts / "report.md").read_bytes()),
        "source_inventory": [
            {"file": source.path, "blob": source.oid, "sha256": digest(source.data)}
            for source in sources
        ],
    }
    raw = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    (artifacts / "report.json").write_bytes(raw)
    report_sha = digest(raw)
    store.finish(job["id"], status=report["status"], report_sha256=report_sha, elapsed=0.1)

    candidates = service.findings(report)
    clusters = service.finding_clusters(report)
    expanded = next((group for group in clusters if len(group["candidates"]) >= 2), None)
    if not candidates or expanded is None:
        raise RuntimeError("real product component must produce an expandable candidate cluster")
    validation_source = "services/src/platform_callback_stub.cpp"
    reviewed = next(
        (item for item in candidates if item["file"] == validation_source),
        expanded["candidates"][0],
    )
    coverage = report["detector_coverage"]["detectors"][DETECTOR]
    seed = {
        "schema_version": 1,
        "task": "PLATFORM-REAL-PRODUCT-BROWSER-01",
        "root": str(root),
        "product_binding": product_binding,
        "component_binding": component_binding,
        "scope": {"include_paths": ["."], "mode": "repository_snapshot"},
        "detector": {
            "id": DETECTOR,
            "version": spec["detector_versions"][DETECTOR],
            "evidence_level": "candidate/unassessed",
        },
        "coverage": {
            "status": coverage.get("status"),
            "analyzed_files": len(coverage.get("analyzed_files", [])),
            "file_outcomes": coverage.get("file_outcomes"),
            "limitations": coverage.get("limitations", []),
        },
        "repository_id": product["id"],
        "component_repository_id": component["id"],
        "job_id": job["id"],
        "candidate_ids": [item["id"] for item in candidates],
        "reviewed_candidate_id": reviewed["id"],
        "reviewed_candidate_file": reviewed["file"],
        "validation_source_file": validation_source,
        "cluster_id": expanded["cluster_id"],
        "cluster_member_ids": [item["id"] for item in expanded["candidates"]],
        "report_sha256": report_sha,
        "report_status": report["status"],
        "diagnostic_count": report.get("diagnostic_count", len(candidates)),
        "report_schema_version": report["detector_runs"][0].get("schema_version"),
        "exact_scan_command": exact_command,
        "boundary": (
            "Static browser audit of a fixed real product component. "
            "It is not product vulnerability confirmation, dynamic exploitation, "
            "multi-user deployment validation, or a public-network deployment claim."
        ),
    }
    (root / "seed.json").write_text(
        json.dumps(seed, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(seed, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()