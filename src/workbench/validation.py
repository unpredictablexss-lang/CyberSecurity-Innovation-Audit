"""Docker-only AUTH-01 validation adapter. Missing isolation returns blocked, never host fallback."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

from . import service

HARNESS = Path(__file__).resolve().parents[2] / "src/ohscanner/poc/harnesses/auth01_descriptor_bypass"
PROJECT = Path(__file__).resolve().parents[2]


def _run(argv, timeout=10, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False, **kwargs)


def docker_binary():
    configured = os.environ.get("OHSCANNER_DOCKER")
    return configured or shutil.which("docker")


def _digest_image(image):
    import re
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", image))


def readiness():
    docker = docker_binary()
    image = os.environ.get("OHSCANNER_VALIDATION_IMAGE", "")
    if not docker:
        return {"ready": False, "reason": "Docker CLI is unavailable in this execution environment"}
    if not _digest_image(image):
        return {"ready": False, "reason": "Set OHSCANNER_VALIDATION_IMAGE to an immutable sha256 image reference"}
    daemon = _run([docker, "info", "--format", "{{.ServerVersion}}"], timeout=8)
    if daemon.returncode:
        return {"ready": False, "reason": "Docker daemon unavailable: " + daemon.stderr.decode("utf-8", "replace")[-500:]}
    inspected = _run([docker, "image", "inspect", image, "--format", "{{.Id}} {{json .RepoDigests}}"], timeout=8)
    if inspected.returncode:
        return {"ready": False, "reason": "Pinned validation image is not present locally"}
    try:
        image_id, digests = inspected.stdout.decode().strip().split(" ", 1)
        digests = json.loads(digests)
    except Exception:
        return {"ready": False, "reason": "Docker image inspection returned an invalid record"}
    if image.startswith("sha256:") and image_id != image:
        return {"ready": False, "reason": "Local image ID does not match the pinned ID"}
    if "@sha256:" in image and image not in digests:
        return {"ready": False, "reason": "Local repository digest does not match the configured pin"}
    return {"ready": True, "image": image, "image_id": image_id, "docker_version": daemon.stdout.decode().strip()}


def _extract_safe_archive(raw, destination, max_bytes=64 * 1024 * 1024):
    if len(raw) > max_bytes:
        raise ValueError("pinned support source archive exceeds 64 MiB")
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=__import__("io").BytesIO(raw), mode="r:") as archive:
        for member in archive.getmembers():
            item = PurePosixPath(member.name)
            if item.is_absolute() or ".." in item.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError("support source archive contains an unsafe entry")
            target = (root / Path(*item.parts)).resolve()
            if not target.is_relative_to(root):
                raise ValueError("support source archive escapes its destination")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("support source archive entry cannot be read")
                target.write_bytes(stream.read())


def _support_archive(repo, commit):
    result = _run(["git", "-C", str(repo), "archive", "--format=tar", commit,
                   "base/include", "base/src"], timeout=30)
    if result.returncode:
        raise FileNotFoundError("pinned commonlibrary_c_utils archive is unavailable: " + result.stderr.decode("utf-8", "replace")[-500:])
    return result.stdout


def _sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def cleanup_container(operation_id):
    docker = docker_binary()
    if not docker or len(operation_id) != 32 or any(c not in "0123456789abcdef" for c in operation_id):
        return
    _run([docker, "rm", "--force", "ohscanner-validation-" + operation_id], timeout=8)


def cleanup_stale_containers():
    docker = docker_binary()
    if not docker:
        return
    listed = _run([docker, "ps", "-aq", "--filter", "name=^/ohscanner-validation-[0-9a-f]{32}$"], timeout=8)
    if listed.returncode:
        return
    for identity in listed.stdout.decode().splitlines():
        if identity and all(c in "0123456789abcdef" for c in identity):
            _run([docker, "rm", "--force", identity], timeout=8)


def execute_validation(settings, store, ops, task):
    spec = task["spec"]
    try:
        ready = readiness()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "blocked", "reason": "Docker readiness check failed: " + str(exc)[:400],
                "validated_vulnerability": 0}
    if not ready["ready"]:
        return {"status": "blocked", "reason": ready["reason"], "validated_vulnerability": 0,
                "isolation": {"required": "Docker, no network, dropped capabilities", "host_fallback": False}}
    target = Path(service.check_repository(settings, spec["target_path"]))
    cutils = Path(service.check_repository(settings, spec["cutils_path"]))
    target_commit = spec.get("target_commit")
    if not target_commit:
        return {"status": "blocked", "reason": "target commit must be explicitly selected", "validated_vulnerability": 0}
    harness_manifest = HARNESS / "manifest.json"
    manifest = json.loads(harness_manifest.read_text(encoding="utf-8"))
    if spec["harness_id"] != manifest["harness"] or spec["target_repository"] != manifest["repository"]:
        raise ValueError("requested harness and target do not match the reviewed manifest")
    for revision in manifest["revisions"].values():
        check = _run(["git", "-C", str(target), "cat-file", "-e", revision["commit"] + "^{commit}"], timeout=15)
        if check.returncode:
            return {"status": "blocked", "reason": "one pinned AUTH-01 commit is absent from local Git objects",
                    "validated_vulnerability": 0}
    support_obj = _run(["git", "-C", str(cutils), "cat-file", "-e", spec["cutils_commit"] + "^{commit}"], timeout=15)
    if support_obj.returncode:
        return {"status": "blocked", "reason": "pinned c_utils commit is absent", "validated_vulnerability": 0}
    folder = ops.directory(task["id"])
    inputs = folder / "input"
    inputs.mkdir(parents=True, exist_ok=True)
    support = inputs / "cutils"
    if support.exists():
        shutil.rmtree(support)
    archive = _support_archive(cutils, spec["cutils_commit"])
    _extract_safe_archive(archive, support)
    archive_hash = hashlib.sha256(archive).hexdigest()
    manifest_hash = _sha(harness_manifest)
    harness_hashes = {str(p.relative_to(HARNESS)): _sha(p) for p in sorted(HARNESS.rglob("*")) if p.is_file()}
    folder.mkdir(parents=True, exist_ok=True)
    command = [ready.get("docker_binary") or docker_binary(), "run", "--name", "ohscanner-validation-" + task["id"],
        "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--pids-limit", "64", "--memory", str(spec.get("memory_mb", 2048)) + "m",
        "--cpus", "2", "--user", str(os.getuid()) + ":" + str(os.getgid()),
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
        "--mount", "type=bind,src=" + str(PROJECT) + ",dst=/opt/ohscanner,readonly",
        "--mount", "type=bind,src=" + str(target) + ",dst=/input/target,readonly",
        "--mount", "type=bind,src=" + str(support) + ",dst=/input/cutils,readonly",
        "--mount", "type=bind,src=" + str(folder) + ",dst=/work",
        "-e", "OHSCANNER_VALIDATION_CONTAINER=1", "-w", "/opt/ohscanner", ready["image"], "-m", "src.workbench.validation_child",
        "--manifest", "/opt/ohscanner/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json",
        "--target", "/input/target", "--cutils", "/input/cutils", "--work", "/work/poc",
        "--out", "/work/validation-result.json", "--repeats", str(spec["repeats"])]
    (folder / "validation-command.json").write_text(json.dumps(command, indent=2) + "\n")
    (folder / "input-manifest.json").write_text(json.dumps({"target_repository": spec["target_repository"],
        "target_commit": target_commit, "harness_manifest_sha256": manifest_hash,
        "harness_files_sha256": harness_hashes, "cutils_commit": spec["cutils_commit"],
        "cutils_archive_sha256": archive_hash, "docker_image": ready["image"],
        "docker_image_id": ready["image_id"], "docker_version": ready["docker_version"]}, indent=2) + "\n")
    try:
        done = subprocess.run(command, capture_output=True, timeout=spec["timeout_seconds"], check=False)
    except subprocess.TimeoutExpired as exc:
        cleanup_container(task["id"])
        (folder / "docker.log").write_bytes((exc.stdout or b"") + b"\n" + (exc.stderr or b""))
        return {"status": "timed_out", "reason": "Docker validation deadline exceeded", "validated_vulnerability": 0}
    finally:
        cleanup_container(task["id"])
    log = done.stdout + b"\n" + done.stderr
    (folder / "docker.log").write_bytes(log[-2 * 1024 * 1024:])
    if done.returncode:
        return {"status": "completed_with_limitations", "reason": "Harness build/run did not complete successfully inside Docker",
                "docker_exit_code": done.returncode, "docker_log_sha256": hashlib.sha256(log).hexdigest(),
                "validated_vulnerability": 0, "validation_gate": "not_passed"}
    result_path = folder / "validation-result.json"
    if not result_path.is_file() or result_path.stat().st_size > 16 * 1024 * 1024:
        return {"status": "failed", "reason": "container produced no bounded result artifact", "validated_vulnerability": 0}
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result.update({"status": "completed_with_limitations", "case_id": spec["case_id"],
        "validation_gate": result.get("validation_gate", "not_passed"),
        "input_manifest_sha256": _sha(folder / "input-manifest.json"),
        "validation_command_sha256": _sha(folder / "validation-command.json"),
        "docker_log_sha256": hashlib.sha256(log).hexdigest(), "docker_exit_code": 0,
        "validated_vulnerability": 0})
    return result