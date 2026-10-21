"""Pinned, no-checkout imports from the GitCode OpenHarmony catalog."""
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid

from . import service
from .source_catalog import approved_clone_url, validate_branch, validate_commit


def git_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_ALLOW_PROTOCOL": "https", "GIT_ASKPASS": "/bin/false",
                "GIT_SSH_COMMAND": "/bin/false"})
    return env


def _git(repo, *args, timeout=120):
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "http.followRedirects=false",
               "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
               "-c", "credential.helper=", "-C", str(repo), *args]
    env = git_environment()
    result = subprocess.run(command, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace")[:1000]
        if "redirect" in detail.lower():
            raise ValueError("Git redirect refused; repository was not imported")
        if "no space left" in detail.lower() or "disk quota" in detail.lower():
            raise OSError("repository cache disk is full")
        raise ValueError("Git import failed: " + detail)
    return result.stdout


def _safe_cache_root(root):
    root = Path(root).expanduser()
    if not root.is_absolute():
        raise ValueError("repository cache root must be absolute")
    if root.is_symlink():
        raise ValueError("repository cache root cannot be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.resolve(strict=True) != root:
        raise ValueError("repository cache root path contains a symlink")
    if not root.is_dir():
        raise ValueError("repository cache root is not a directory")
    return root


def _directory_size(root):
    total = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        folder_path = Path(folder)
        dirs[:] = [name for name in dirs if not (folder_path / name).is_symlink()]
        for name in files:
            path = folder_path / name
            if path.is_symlink():
                raise ValueError("repository cache contains a symlink")
            try:
                total += path.stat(follow_symlinks=False).st_size
            except FileNotFoundError:
                continue
    return total


def _choose_root(settings, required_free=0, required_size=0):
    failures = []
    for configured in settings.repository_cache_roots:
        try:
            root = _safe_cache_root(configured)
            usage = shutil.disk_usage(root)
            needed = max(settings.repository_cache_min_free_bytes, required_free)
            if usage.free < needed:
                failures.append("insufficient free space")
                continue
            if settings.repository_cache_max_bytes:
                used = _directory_size(root)
                if used + required_size > settings.repository_cache_max_bytes:
                    failures.append("repository cache quota reached")
                    continue
            return root
        except (OSError, ValueError) as exc:
            failures.append(type(exc).__name__)
    raise OSError("no repository cache root has safe paths and sufficient disk capacity: "
                  + (", ".join(failures) or "no roots configured"))


def _within(path, parent):
    return path.resolve(strict=False).is_relative_to(parent.resolve(strict=True))


def _safe_remove_stage(stage, namespace):
    stage = Path(stage)
    if stage.is_symlink() or not _within(stage, namespace):
        raise ValueError("refusing to remove an import path outside the repository cache")
    if stage.exists():
        shutil.rmtree(stage)


def _remove_abandoned_stages(family, commit):
    prefix = "." + commit + ".import-"
    for child in family.iterdir():
        if not child.name.startswith(prefix):
            continue
        if child.is_symlink() or child.parent.resolve(strict=True) != family.resolve(strict=True):
            raise ValueError("abandoned import staging path is unsafe")
        if child.is_dir():
            _safe_remove_stage(child, family)


def _terminate_clone(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, AttributeError):
        process.terminate()
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, AttributeError):
            process.kill()
        process.communicate()


def _fetch_to_stage(stage, slug, branch, commit, timeout, *, cache_root=None,
                    cache_used_before=0, cache_max_bytes=0, minimum_free_bytes=0):
    url = approved_clone_url(slug)
    env = git_environment()
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "http.followRedirects=false",
               "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
               "-c", "credential.helper=", "clone", "--no-checkout", "--no-recurse-submodules",
               "--depth=1", "--single-branch", "--no-tags", "--branch", branch,
               "--", url, str(stage)]
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, start_new_session=True)
    start = time.monotonic()
    last_check = 0.0
    failure = None
    while process.poll() is None:
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            failure = subprocess.TimeoutExpired(command, timeout)
            break
        if cache_root is not None and elapsed - last_check >= 0.5:
            last_check = elapsed
            try:
                stage_size = _directory_size(stage) if stage.exists() else 0
                if cache_max_bytes and cache_used_before + stage_size > cache_max_bytes:
                    failure = OSError("repository cache size quota would be exceeded during download")
                    break
                if shutil.disk_usage(cache_root).free < minimum_free_bytes:
                    failure = OSError("repository cache minimum free-space reserve would be violated during download")
                    break
            except OSError as exc:
                failure = exc
                break
        time.sleep(0.1)
    if failure is not None:
        _terminate_clone(process)
        raise failure
    stderr = process.communicate()[1]
    if process.returncode:
        detail = stderr.decode("utf-8", "replace")[:1000]
        if "redirect" in detail.lower():
            raise ValueError("Git redirect refused; repository was not imported")
        if "no space left" in detail.lower() or "disk quota" in detail.lower():
            raise OSError("repository cache disk is full")
        raise ValueError("Git import failed: " + detail)
    branch_head = _git(stage, "rev-parse", "refs/heads/" + branch).decode().strip()
    if branch_head != commit:
        raise ValueError("default branch changed after preview; refresh the commit preview and retry")
    pinned = _git(stage, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if pinned != commit:
        raise ValueError("downloaded Git commit does not match the previewed commit")
    tree = _git(stage, "rev-parse", commit + "^{tree}").decode().strip()
    entries = _git(stage, "ls-tree", "-r", "-z", commit)
    if any(item.startswith(b"160000 commit ") for item in entries.split(b"\0") if item):
        raise ValueError("repository contains Git submodules; submodule fetching is disabled")
    return tree


def import_and_queue_scan(settings, store, spec):
    slug = spec["slug"]
    branch = validate_branch(spec["branch"])
    commit = validate_commit(spec["commit"])
    if spec["clone_url"] != approved_clone_url(slug):
        raise ValueError("clone URL does not match the fixed GitCode catalog source")
    timeout = spec["timeout_seconds"]
    estimated = spec.get("estimated_size_kib")
    if estimated is not None and (not isinstance(estimated, int) or isinstance(estimated, bool) or estimated < 0):
        raise ValueError("invalid catalog repository size metadata")
    expected_bytes = (estimated or 0) * 1024
    lockdir = Path(settings.data_dir) / "sync-locks"
    if lockdir.is_symlink():
        raise ValueError("repository import lock directory is unsafe")
    lockdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_key = hashlib.sha256(("openharmony/" + slug).encode()).hexdigest()
    lock_path = lockdir / (lock_key + ".lock")
    if lock_path.is_symlink():
        raise ValueError("repository import lock is unsafe")
    with lock_path.open("a") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        root = None
        target = None
        for configured in settings.repository_cache_roots:
            try:
                candidate_root = _safe_cache_root(configured)
                candidate_namespace = candidate_root / "openharmony"
                candidate_family = candidate_namespace / slug
                candidate_target = candidate_family / commit
                if (candidate_namespace.is_symlink() or candidate_family.is_symlink()
                        or candidate_target.is_symlink()):
                    raise ValueError("repository cache path contains a symlink")
                if candidate_target.exists():
                    if not _within(candidate_target, candidate_namespace):
                        raise ValueError("repository cache target is unsafe")
                    root, target = candidate_root, candidate_target
                    break
            except (OSError, ValueError):
                continue
        if root is None:
            root = _choose_root(settings,
                                required_free=expected_bytes + max(1024 ** 2, expected_bytes // 2),
                                required_size=expected_bytes)
        namespace = root / "openharmony"
        if namespace.is_symlink():
            raise ValueError("repository cache namespace cannot be a symlink")
        namespace.mkdir(mode=0o700, exist_ok=True)
        if namespace.resolve(strict=True) != namespace:
            raise ValueError("repository cache namespace contains a symlink")
        family = namespace / slug
        if family.is_symlink():
            raise ValueError("repository cache path cannot be a symlink")
        family.mkdir(mode=0o700, exist_ok=True)
        if family.resolve(strict=True) != family:
            raise ValueError("repository cache path contains a symlink")
        _remove_abandoned_stages(family, commit)
        target = target or family / commit
        if target.is_symlink() or not _within(target, family):
            raise ValueError("repository cache target is unsafe")
        stage = family / ("." + commit + ".import-" + uuid.uuid4().hex)
        if target.exists():
            if target.is_symlink() or not _within(target, namespace):
                raise ValueError("repository cache target is unsafe")
            service.check_repository(settings, str(target))
            existing_commit = service.revision({"path": str(target)}, "HEAD")["commit"]
            if existing_commit != commit:
                raise ValueError("cached repository is pinned to a different commit; explicit cache refresh is required")
            tree = _git(target, "rev-parse", commit + "^{tree}").decode().strip()
            fetched = False
        else:
            try:
                used_before = _directory_size(root)
                if settings.repository_cache_max_bytes and (
                        used_before + expected_bytes > settings.repository_cache_max_bytes):
                    raise OSError("catalog size estimate exceeds the remaining repository cache quota")
                tree = _fetch_to_stage(stage, slug, branch, commit, timeout,
                                       cache_root=root, cache_used_before=used_before,
                                       cache_max_bytes=settings.repository_cache_max_bytes,
                                       minimum_free_bytes=settings.repository_cache_min_free_bytes)
                size = _directory_size(stage)
                if expected_bytes and size > max(expected_bytes * 2, expected_bytes + 1024 ** 2):
                    raise OSError("download exceeded the catalog size estimate; cache import stopped")
                if settings.repository_cache_max_bytes and (
                        _directory_size(root) > settings.repository_cache_max_bytes):
                    raise OSError("repository cache size quota would be exceeded")
                if shutil.disk_usage(root).free < settings.repository_cache_min_free_bytes:
                    raise OSError("repository cache minimum free-space reserve would be violated")
                if target.exists() or target.is_symlink():
                    raise ValueError("repository cache target appeared during import")
                os.replace(stage, target)
                fetched = True
            except Exception:
                _safe_remove_stage(stage, family)
                raise
        repo = next((item for item in store.repositories() if Path(item["path"]) == target), None)
        if repo is not None and repo["name"] != "openharmony/" + slug:
            raise ValueError("repository cache path is registered under a conflicting name")
        repo_for_plan = repo or {"id": "pending-registration", "name": "openharmony/" + slug,
                                 "path": str(target)}
        service.check_repository(settings, repo_for_plan["path"])
        scan_spec = service.make_spec(repo_for_plan, commit, spec["include_paths"], spec["detector_ids"],
                                     spec["scan_timeout_seconds"], spec["memory_mb"])
        if scan_spec["commit"] != commit or scan_spec["git_tree"] != tree:
            raise ValueError("locally resolved tree does not match the immutable preview binding")
        repo, job = store.register_repository_and_create_job("openharmony/" + slug, str(target), scan_spec)
        return {"status": "completed", "repository": {"id": repo["id"], "name": repo["name"]},
                "commit": commit, "git_tree": tree, "scan_job": {"id": job["id"], "status": "queued"},
                "cache": "downloaded" if fetched else "hit",
                "source_provenance": "GitCode public OpenHarmony organization catalog; metadata is not independent ownership verification",
                "limitations": ["No checkout, build, hooks, or submodule fetch was performed.",
                                "The operation queues a fixed-revision static scan; candidates remain subject to review."]}
