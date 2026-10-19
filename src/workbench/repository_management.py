"""Read-only catalog checks and bounded discovery inside configured source roots."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait
import os
from pathlib import Path
import re
import subprocess
import time

from . import service


DISCOVERY_MAX_DEPTH = 6
DISCOVERY_MAX_DIRECTORIES = 5000
DISCOVERY_MAX_REPOSITORIES = 1000
DISCOVERY_MAX_ENTRIES_PER_DIRECTORY = 10000
CATALOG_TIME_BUDGET_SECONDS = 15
CATALOG_MAX_WORKERS = 8
DISCOVERY_TIME_BUDGET_SECONDS = 20


def _unavailable_reason(error):
    text = str(error).lower()
    if "outside configured target roots" in text:
        return "该仓库不在服务端已批准的源码根目录内"
    if "cannot be a symlink" in text or "symbolic link" in text:
        return "仓库路径包含符号链接，未通过目录安全校验"
    if "not a local git repository" in text:
        return "该目录不是可读取的本地 Git 仓库"
    if "register the repository root" in text:
        return "登记路径不是 Git 仓库根目录"
    if isinstance(error, PermissionError):
        return "服务进程无权读取仓库目录"
    if isinstance(error, FileNotFoundError):
        return "仓库路径已不存在或不可达"
    if isinstance(error, (subprocess.TimeoutExpired, TimeoutError)):
        return "Git 校验超时或目录核验达到时间预算；仓库保持不可用"
    return "仓库路径、Git 对象或提交引用无法验证"


def _catalog_head_commit(settings, path):
    raw = Path(path).expanduser()
    if raw.is_symlink():
        raise ValueError("repository cannot be a symlink")
    resolved = raw.resolve(strict=True)
    roots = tuple(Path(root).resolve(strict=False) for root in settings.target_roots)
    if not any(resolved.is_relative_to(root) and resolved != root for root in roots):
        raise ValueError("repository is outside configured target roots")
    service._git_metadata_directories(resolved, roots)

    if (resolved / ".git").exists():
        output = service._git(
            resolved, "rev-parse", "--show-prefix", "--verify", "HEAD^{commit}", timeout=2
        ).decode().splitlines()
        if len(output) < 2 or output[0] != "":
            raise ValueError("registered path is not the repository root")
        commit = output[1]
    else:
        output = service._git(
            resolved, "rev-parse", "--is-bare-repository", "--verify", "HEAD^{commit}", timeout=2
        ).decode().splitlines()
        if len(output) < 2 or output[0] != "true":
            raise ValueError("not a local Git repository")
        commit = output[1]
    if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", commit):
        raise ValueError("HEAD did not resolve to a commit")
    return commit


def repository_catalog(settings, store):
    """Return user-facing status without exposing repository filesystem paths."""
    records = store.repositories()
    name_counts = Counter(item["name"] for item in records)
    seen_names = Counter()
    labels = []
    for repo in records:
        seen_names[repo["name"]] += 1
        display_name = repo["name"]
        if name_counts[repo["name"]] > 1:
            display_name += f"（副本 {seen_names[repo['name']]}）"
        labels.append({
            "id": repo["id"],
            "name": repo["name"],
            "display_name": display_name,
        })

    def verify(repo, label):
        result = dict(label, status="available", reason="")
        try:
            commit = _catalog_head_commit(settings, repo["path"])
            result["head_commit"] = commit
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result["status"] = "unavailable"
            result["reason"] = _unavailable_reason(error)
        except Exception:
            # Fail closed while keeping internal exception details out of the UI.
            result["status"] = "unavailable"
            result["reason"] = "仓库校验失败；请在设置页重新检查目录"
        return result

    if not records:
        return []
    executor = ThreadPoolExecutor(max_workers=min(CATALOG_MAX_WORKERS, len(records)))
    futures = {
        executor.submit(verify, repo, labels[index]): index
        for index, repo in enumerate(records)
    }
    done, pending = wait(futures, timeout=CATALOG_TIME_BUDGET_SECONDS)
    catalog = [None] * len(records)
    for future in done:
        index = futures[future]
        try:
            catalog[index] = future.result()
        except Exception:
            catalog[index] = dict(
                labels[index], status="unavailable",
                reason="仓库校验失败；请在设置页重新检查目录",
            )
    for future in pending:
        future.cancel()
        index = futures[future]
        catalog[index] = dict(
            labels[index], status="unavailable",
            reason="仓库状态核验超出时间预算；请稍后重试",
        )
    # Git calls have their own timeout; do not hold the HTTP response on stragglers.
    executor.shutdown(wait=False, cancel_futures=True)
    return catalog


def _is_git_repository(path):
    marker = path / ".git"
    if marker.is_symlink():
        return False
    if marker.exists():
        return True
    return (path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "config").is_file()


def _default_name(relative_path):
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", relative_path.replace("/", "-"))
    slug = slug.strip(".-_") or "repository"
    return "local/" + slug[:190]


def discover_repositories(settings, store, root_index):
    """Discover unregistered Git repositories without following links or scanning without bounds."""
    if root_index < 0 or root_index >= len(settings.target_roots):
        raise ValueError("source root selection is invalid")
    root = settings.target_roots[root_index]
    if root.is_symlink() or not root.is_dir():
        raise ValueError("configured source root is unavailable")
    root = root.resolve(strict=True)

    registered = set()
    for repo in store.repositories():
        try:
            registered.add(Path(repo["path"]).resolve(strict=False))
        except OSError:
            continue

    started = time.monotonic()
    pending = [(root, 0)]
    visited = 0
    discovered = []
    registered_count = 0
    truncated = False

    while pending:
        if visited >= DISCOVERY_MAX_DIRECTORIES or len(discovered) >= DISCOVERY_MAX_REPOSITORIES:
            truncated = True
            break
        if time.monotonic() - started >= DISCOVERY_TIME_BUDGET_SECONDS:
            truncated = True
            break
        current, depth = pending.pop()
        visited += 1
        try:
            entries = []
            with os.scandir(current) as iterator:
                for index, entry in enumerate(iterator):
                    if index >= DISCOVERY_MAX_ENTRIES_PER_DIRECTORY:
                        truncated = True
                        break
                    entries.append(entry)
            entries.sort(key=lambda entry: entry.name)
        except OSError:
            continue

        child_dirs = []
        for entry in entries:
            if entry.name in {".git", ".hg", ".svn", "node_modules", "vendor", "build", "out"}:
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    child_dirs.append(Path(entry.path))
            except OSError:
                continue

        for child in child_dirs:
            if not _is_git_repository(child):
                continue
            try:
                canonical = service.check_repository(settings, child, timeout=2)
                repo = {"path": str(canonical)}
                refs = service.revisions(repo, timeout=2)
                if not refs:
                    # Empty or unborn repositories cannot be selected for a fixed-commit audit.
                    continue
                commit = service._git(
                    canonical, "rev-parse", "--verify", refs[0]["ref"] + "^{commit}", timeout=2
                ).decode().strip()
                if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", commit):
                    raise ValueError("revision did not resolve to a commit")
            except (OSError, ValueError, subprocess.SubprocessError):
                # A folder that looks like Git but fails validation is not offered for registration.
                continue
            if canonical in registered:
                registered_count += 1
                continue
            relative = canonical.relative_to(root).as_posix()
            discovered.append(
                {
                    "name_guess": _default_name(relative),
                    "path": str(canonical),
                    "revision_count": len(refs),
                }
            )
            registered.add(canonical)

        if depth < DISCOVERY_MAX_DEPTH:
            # Reverse before stack insertion so traversal stays deterministic.
            pending.extend((child, depth + 1) for child in reversed(child_dirs)
                           if not _is_git_repository(child))

    return {
        "root_index": root_index,
        "root_name": root.name,
        "root_path": str(root),
        "repositories": discovered,
        "registered_count": registered_count,
        "visited_directories": visited,
        "truncated": truncated,
        "limits": {
            "max_depth": DISCOVERY_MAX_DEPTH,
            "max_directories": DISCOVERY_MAX_DIRECTORIES,
            "max_repositories": DISCOVERY_MAX_REPOSITORIES,
            "max_entries_per_directory": DISCOVERY_MAX_ENTRIES_PER_DIRECTORY,
            "time_budget_seconds": DISCOVERY_TIME_BUDGET_SECONDS,
        },
    }
