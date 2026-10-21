"""Docker-only execution of the two fixed C++ component reproduction tests."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from . import validation
from .validation_catalog import CPP_IDS, HARNESS_ROOT, LIFETIME_ID, SHARED_PTR_ID, manifest_path, shared_sources

PROJECT = Path(__file__).resolve().parents[2]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(settings, ops, task):
    spec = task["spec"]
    harness_id = spec.get("harness_id")
    if harness_id not in CPP_IDS:
        raise ValueError("unknown C++ reproduction test")
    try:
        ready = validation.readiness()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "blocked", "reason": "Docker readiness check failed: " + str(exc)[:400],
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0}
    if not ready["ready"]:
        return {"status": "blocked", "reason": ready["reason"],
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0,
                "isolation": {"required": "Docker, no network, dropped capabilities", "host_fallback": False}}

    harness_dir = HARNESS_ROOT / harness_id
    manifest_file = manifest_path(harness_id)
    if _sha(manifest_file) != spec.get("manifest_sha256"):
        return {"status": "blocked", "reason": "fixed harness manifest changed after task creation",
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0}
    folder = ops.directory(task["id"])
    inputs = folder / "input"
    inputs.mkdir(parents=True, exist_ok=True)
    staged_sources = {}
    if harness_id == SHARED_PTR_ID:
        try:
            sources = shared_sources()
        except (ValueError, OSError, UnicodeError) as exc:
            return {"status": "blocked", "reason": str(exc),
                    "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                    "validated_vulnerability": 0}
        for relative, content in sources.items():
            destination = inputs / "source" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            staged_sources[relative] = hashlib.sha256(content).hexdigest()

    harness_hashes = {str(path.relative_to(harness_dir)): _sha(path)
                      for path in sorted(harness_dir.rglob("*")) if path.is_file()}
    manifest_record = {
        "harness_id": harness_id, "validation_scope": spec["validation_scope"],
        "harness_manifest_sha256": spec["manifest_sha256"],
        "harness_files_sha256": harness_hashes, "staged_source_files_sha256": staged_sources,
        "source_binding_status": "preserved_artifact_hash_verified" if staged_sources else "self_authored_harness_hash_verified",
        "source_provenance": "preserved file bytes, manifest SHA-256 and required quotes; Git object availability is not asserted" if staged_sources else "self-authored fixture hash bound to the reviewed manifest",
        "docker_image": ready["image"], "docker_image_id": ready["image_id"],
        "docker_version": ready["docker_version"],
    }
    manifest_path_out = folder / "input-manifest.json"
    manifest_path_out.write_text(json.dumps(manifest_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    command = [ready.get("docker_binary") or validation.docker_binary(), "run",
        "--name", "ohscanner-validation-" + task["id"], "--rm", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
        "--pids-limit", "64", "--memory", str(spec.get("memory_mb", 2048)) + "m", "--cpus", "2",
        "--user", str(os.getuid()) + ":" + str(os.getgid()),
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777",
        "--mount", "type=bind,src=" + str(PROJECT) + ",dst=/opt/ohscanner,readonly",
        "--mount", "type=bind,src=" + str(inputs) + ",dst=/input,readonly",
        "--mount", "type=bind,src=" + str(folder) + ",dst=/work",
        "-e", "OHSCANNER_VALIDATION_CONTAINER=1", "-w", "/opt/ohscanner", ready["image"],
        "-m", "src.workbench.validation_cpp_child", "--harness-id", harness_id,
        "--inputs", "/input", "--work", "/work/poc", "--out", "/work/validation-result.json"]
    command_path = folder / "validation-command.json"
    command_path.write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
    try:
        done = subprocess.run(command, capture_output=True, timeout=spec["timeout_seconds"], check=False)
    except subprocess.TimeoutExpired as exc:
        validation.cleanup_container(task["id"])
        (folder / "docker.log").write_bytes((exc.stdout or b"") + b"\n" + (exc.stderr or b""))
        return {"status": "timed_out", "reason": "Docker validation deadline exceeded",
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0}
    finally:
        validation.cleanup_container(task["id"])
    log = done.stdout + b"\n" + done.stderr
    (folder / "docker.log").write_bytes(log[-2 * 1024 * 1024:])
    if done.returncode:
        return {"status": "completed_with_limitations", "reason": "C++ component test did not complete successfully inside Docker",
                "docker_exit_code": done.returncode, "docker_log_sha256": hashlib.sha256(log).hexdigest(),
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0, "validation_gate": "not_passed"}
    result_path = folder / "validation-result.json"
    if not result_path.is_file() or result_path.stat().st_size > 32 * 1024 * 1024:
        return {"status": "failed", "reason": "container produced no bounded result artifact",
                "validation_scope": spec["validation_scope"], "harness_id": harness_id,
                "validated_vulnerability": 0}
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result.update({"status": "completed_with_limitations", "case_id": spec["case_id"],
        "harness_id": harness_id, "validation_scope": spec["validation_scope"],
        "validation_gate": "not_applicable_component_reproduction",
        "input_manifest_sha256": _sha(manifest_path_out),
        "validation_command_sha256": _sha(command_path),
        "docker_log_sha256": hashlib.sha256(log).hexdigest(), "docker_exit_code": 0,
        "validated_vulnerability": 0})
    return result
