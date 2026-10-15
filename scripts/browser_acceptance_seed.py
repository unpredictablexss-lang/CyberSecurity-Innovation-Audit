"""Seed a persistent local fixture for reproducible browser acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import subprocess

from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner.git_source import load_git_sources
from src.workbench import service
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def commit(repo, message, date):
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True, env={
        **os.environ,
        "GIT_AUTHOR_DATE": date,
        "GIT_COMMITTER_DATE": date,
    })


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if root.exists() and any(root.iterdir()):
        raise SystemExit("browser acceptance root must be absent or empty")
    targets = root / "targets"
    repo = targets / "sample"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    git(repo, "config", "user.name", "browser-acceptance")
    git(repo, "config", "user.email", "browser@example.invalid")
    (repo / "seed.txt").write_text("baseline\n", encoding="utf-8")
    (repo / "baseline.cpp").write_text("int baseline() { return 0; }\n", encoding="utf-8")
    git(repo, "add", "seed.txt", "baseline.cpp")
    commit(repo, "baseline", "2025-01-01T00:00:00+00:00")
    commit_a = git(repo, "rev-parse", "HEAD")
    (repo / "middle.txt").write_text("middle\n", encoding="utf-8")
    git(repo, "add", "middle.txt")
    commit(repo, "middle", "2025-01-02T00:00:00+00:00")
    commit_b = git(repo, "rev-parse", "HEAD")
    (repo / "common_types.h").write_text(
        Path("tests/fixtures/ipc/common_types.h").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (repo / "cluster.cpp").write_text(
        "#define Stub BrowserFixture\n"
        '#include "common_types.h"\n\n'
        "int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,"
        "MessageParcel &reply,MessageOption &option) {\n"
        "if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n"
        "StartAbility();\nStartAbility();\nreturn 0;\n}\n",
        encoding="utf-8",
    )
    git(repo, "add", "common_types.h", "cluster.cpp")
    commit(repo, "candidate", "2025-01-03T00:00:00+00:00")
    commit_c = git(repo, "rev-parse", "HEAD")

    host_ip = "127.0.0.1"
    fixture = root / "git-fixture"
    fixture.mkdir()
    fixture_source = fixture / "controlled-source"
    fixture_source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=fixture_source, check=True)
    git(fixture_source, "config", "user.name", "browser-acceptance")
    git(fixture_source, "config", "user.email", "browser@example.invalid")
    (fixture_source / "README.md").write_text(
        "Controlled loopback Git source for source-sync acceptance.\n",
        encoding="utf-8",
    )
    git(fixture_source, "add", "README.md")
    commit(fixture_source, "controlled source", "2025-01-01T00:00:00+00:00")
    for bare_name in ("c_utils.git", "ace_napi.git"):
        subprocess.run(
            ["git", "clone", "--bare", str(fixture_source), str(fixture / bare_name)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        git(fixture / bare_name, "update-server-info")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(fixture / "key.pem"), "-out", str(fixture / "cert.pem"),
        "-days", "1", "-subj", "/CN=127.0.0.1",
        "-addext", f"subjectAltName=IP:{host_ip}",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    settings = Settings(root / "data", (targets,))
    settings.initialize()
    cache = settings.data_dir / "repo-cache"
    for name, port in (("c_utils", 9443), ("ace_napi", 9444)):
        target = cache / name
        subprocess.run(
            ["git", "clone", "--bare", str(fixture / (name + ".git")), str(target)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        rewritten = f"https://{host_ip}:{port}/{name}.git"
        original = f"https://github.com/openharmony/{name}.git"
        git(target, "config", f"url.{rewritten}.insteadOf", original)
        git(target, "config", "http.sslCAInfo", str(fixture / "cert.pem"))
    store = Store(settings.data_dir)
    repository = store.add_repository("fixture/sample", str(repo))
    job = store.create_job(repository["id"], service.make_spec(
        repository, commit_c, ["."], ["ohscanner.interface.ipc"], 300, 2048
    ))
    store.claim()
    artifacts = service.artifact_dir(settings, job["id"])
    artifacts.mkdir(parents=True, exist_ok=False)
    report = run_fixed_commit_scan(
        repo, "fixture/sample", commit_c, (".",),
        ("ohscanner.interface.ipc",), artifacts / "report.json", artifacts / "report.md"
    )
    _, _, sources, _ = load_git_sources(repo, commit_c, (".",))
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
    if len(candidates) < 2:
        raise RuntimeError("browser fixture must produce at least two clustered candidates")
    first = candidates[0]
    store.add_review(
        job["id"], first["id"], "under_review", "browser-review",
        "Persisted review for restart acceptance", 0
    )
    evidence = service.source_excerpt(
        settings, store, store.job(job["id"]), first["id"], first["file"],
        1, min(2, len((repo / first["file"]).read_text(encoding="utf-8").splitlines())),
        "Persisted evidence for restart acceptance"
    )
    case_id = store.create_case("Browser acceptance case", [{
        "job_id": job["id"],
        "candidate_id": first["id"],
        "rationale": "Two same-scope observations are grouped for review only",
    }])

    ops = Operations(store)
    running = ops.create("source_sync", {
        "name": "openharmony/ace_napi",
        "url": "https://github.com/openharmony/ace_napi.git",
        "timeout_seconds": 600,
    })
    claimed = ops.claim()
    if claimed["id"] != running["id"]:
        raise RuntimeError("failed to seed running recovery operation")
    queued = ops.create("source_sync", {
        "name": "openharmony/c_utils",
        "url": "https://github.com/openharmony/c_utils.git",
        "timeout_seconds": 300,
    })
    cluster = next(
        group for group in service.finding_clusters(report)
        if len(group["candidates"]) >= 2
    )
    seed = {
        "root": str(root),
        "repo": str(repo),
        "repository_id": repository["id"],
        "commits": {"baseline": commit_a, "middle": commit_b, "endpoint": commit_c},
        "job_id": job["id"],
        "candidate_ids": [item["id"] for item in candidates],
        "reviewed_candidate_id": first["id"],
        "evidence_id": evidence["id"],
        "case_id": case_id,
        "cluster_id": cluster["cluster_id"],
        "cluster_member_ids": [item["id"] for item in cluster["candidates"]],
        "git_fixture_root": str(fixture),
        "git_host_ip": host_ip,
        "report_sha256": report_sha,
        "queued_cancel_operation_id": queued["id"],
        "running_recovery_operation_id": running["id"],
    }
    (root / "seed.json").write_text(
        json.dumps(seed, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(seed, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
