"""Read-only catalog checks and bounded discovery inside configured source roots."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
from concurrent.futures import ThreadPoolExecutor, wait
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import service
from .source_roots import load_managed_roots, managed_root_is_current, record_root_check
from .source_identity import repository_source_id


DISCOVERY_MAX_DEPTH = 6
DISCOVERY_MAX_DIRECTORIES = 5000
DISCOVERY_MAX_REPOSITORIES = 1000
DISCOVERY_MAX_ENTRIES_PER_DIRECTORY = 10000
CATALOG_TIME_BUDGET_SECONDS = 15
CATALOG_MAX_WORKERS = 8
DISCOVERY_TIME_BUDGET_SECONDS = 20
ONLINE_CATALOG_PAGE_SIZE = 100
ONLINE_CATALOG_PAGE_LIMIT = 20
ONLINE_CATALOG_CACHE_SECONDS = 120
_ONLINE_CATALOG_CACHE = {}


def online_repository_catalog(page=1):
    """Discover a bounded page from GitHub's public OpenHarmony org listing.

    Discovery by organization name is not proof of upstream ownership or mirror
    identity. Cloning still requires an explicit operator action.
    """
    if not isinstance(page, int) or isinstance(page, bool) or not 1 <= page <= ONLINE_CATALOG_PAGE_LIMIT:
        raise ValueError("online catalog page must be between 1 and 20")
    cached = _ONLINE_CATALOG_CACHE.get(page)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    endpoint = "https://api.github.com/orgs/openharmony/repos?" + urlencode({
        "per_page": ONLINE_CATALOG_PAGE_SIZE, "page": page, "type": "public", "sort": "full_name"})
    request = Request(endpoint, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "OHScanner-local-workbench",
    })
    try:
        with urlopen(request, timeout=8) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
            link_header = response.headers.get("Link", "")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ValueError("GitHub repository discovery is unavailable; you can still enter an approved URL manually") from exc
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("GitHub repository discovery page exceeds the response budget")
    try:
        rows = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub repository discovery returned invalid JSON") from exc
    if not isinstance(rows, list) or len(rows) > ONLINE_CATALOG_PAGE_SIZE:
        raise ValueError("GitHub repository discovery returned an invalid page")
    repositories = []
    for row in rows:
        owner = row.get("owner") if isinstance(row, dict) else None
        if not isinstance(owner, dict) or str(owner.get("login", "")).lower() != "openharmony":
            continue
        name = row.get("name")
        full_name = row.get("full_name")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name)
                or full_name != "openharmony/" + name):
            continue
        branch = row.get("default_branch")
        if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch):
            branch = ""
        description = row.get("description")
        repositories.append({
            "name": full_name,
            "source_id": repository_source_id("https://github.com/openharmony/" + name + ".git"),
            "url": "https://github.com/openharmony/" + name + ".git",
            "web_url": "https://github.com/openharmony/" + name,
            "description": description[:500] if isinstance(description, str) else "",
            "default_branch": branch,
            "archived": bool(row.get("archived")),
            "fork": bool(row.get("fork")),
            "stars": row.get("stargazers_count") if isinstance(row.get("stargazers_count"), int) else None,
            "updated_at": row.get("updated_at") if isinstance(row.get("updated_at"), str) else None,
        })
    result = {
        "source": "GitHub public organization repository discovery",
        "organization": "openharmony", "identity_verified": False,
        "page": page, "per_page": ONLINE_CATALOG_PAGE_SIZE,
        "next_page": page + 1 if 'rel="next"' in link_header and page < ONLINE_CATALOG_PAGE_LIMIT else None,
        "repositories": repositories,
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "limitations": [
            "This endpoint lists repositories under the GitHub organization name only; it does not verify upstream ownership, mirror identity, or project membership.",
            "No repository is downloaded until the operator explicitly queues a sync operation.",
        ],
    }
    _ONLINE_CATALOG_CACHE[page] = (time.monotonic() + ONLINE_CATALOG_CACHE_SECONDS, result)
    return result


def _safe_allowed_roots(settings):
    roots = []
    for configured in settings.target_roots:
        path = Path(configured)
        try:
            # A managed root that was replaced by a symlink must stop granting
            # access, even though its registry entry still exists.
            if path.resolve(strict=False) != path:
                continue
            roots.append(path)
        except (OSError, RuntimeError):
            continue
    return tuple(roots)


def _root_records(settings):
    managed = load_managed_roots(settings.data_dir)
    managed_paths = {row["path"] for row in managed}
    configured = [Path(path) for path in settings._configured_target_roots]
    # The internal repo cache is configured but not an operator-facing source root.
    cache = (Path(settings.data_dir) / "repo-cache").resolve(strict=False)
    configured = [path for path in configured if path != cache and str(path) not in managed_paths]
    rows = []
    for path in configured:
        rows.append({
            "id": "configured-" + hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:20],
            "alias": path.name or f"源码根目录 {len(rows) + 1}",
            "path": str(path),
            "managed": False,
            "last_checked_at": None,
            "discovery": {
                "max_depth": DISCOVERY_MAX_DEPTH,
                "max_directories": DISCOVERY_MAX_DIRECTORIES,
                "max_repositories": DISCOVERY_MAX_REPOSITORIES,
                "time_budget_seconds": DISCOVERY_TIME_BUDGET_SECONDS,
            },
        })
    rows.extend(managed)
    return [dict(row, index=index) for index, row in enumerate(rows)]


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
    roots = _safe_allowed_roots(settings)
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
    root_entries = _root_records(settings)
    roots = _safe_allowed_roots(settings)
    root_aliases = {
        Path(row["path"]): row["alias"]
        for row in root_entries
        if Path(row["path"]) in roots
    }
    name_counts = Counter(item["name"] for item in records)
    seen_names = Counter()
    labels = []
    for repo in records:
        seen_names[repo["name"]] += 1
        try:
            path = Path(repo["path"]).resolve(strict=False)
            matching_roots = [root for root in roots if path.is_relative_to(root)]
            matched = max(matching_roots, key=lambda root: len(root.parts)) if matching_roots else None
            root_alias = root_aliases.get(matched, "未知来源")
        except (OSError, ValueError):
            root_alias = "未知来源"
        display_name = repo["name"]
        if name_counts[repo["name"]] > 1:
            display_name += f"（{root_alias} · 副本 {seen_names[repo['name']]}）"
        labels.append({
            "id": repo["id"],
            "name": repo["name"],
            "display_name": display_name,
            "root_alias": root_alias,
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


def repository_roots(settings, store):
    """Describe configured and operator-managed roots for the settings page."""
    repositories = store.repositories()
    result = []
    for root in _root_records(settings):
        raw = Path(root["path"])
        try:
            resolved = raw.resolve(strict=False)
            available = (
                raw.is_dir()
                and not raw.is_symlink()
                and resolved == raw
                and os.access(raw, os.R_OK | os.X_OK)
                and (not root["managed"] or managed_root_is_current(root))
            )
        except OSError:
            available = False
        # Repository paths are canonicalized at registration. Use lexical
        # containment here so a settings page does not stat every repository.
        root_prefix = os.path.normcase(os.path.normpath(str(raw))).rstrip(os.sep) + os.sep
        count = sum(
            1 for repo in repositories
            if os.path.normcase(os.path.normpath(repo["path"])).startswith(root_prefix)
        )
        result.append({
            "index": root["index"],
            "id": root["id"],
            "alias": root["alias"],
            "path": str(raw),
            "status": "available" if available else "unavailable",
            "repository_count": count,
            "managed": bool(root["managed"]),
            "last_checked_at": root.get("last_checked_at"),
            "discovery": root["discovery"],
        })
    return result


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


def _discovery_limit(policy, name, default, maximum, minimum=1):
    value = policy.get(name, default) if isinstance(policy, dict) else default
    if isinstance(value, bool) or not isinstance(value, int):
        value = default
    return max(minimum, min(maximum, value))


def discover_repositories(settings, store, root_index=None, root_id=None):
    """Discover unregistered Git repositories without following links or scanning without bounds."""
    records = _root_records(settings)
    if root_id is not None:
        selected = next((row for row in records if row["id"] == root_id), None)
    elif root_index is not None and 0 <= root_index < len(records):
        selected = records[root_index]
    else:
        selected = None
    if selected is None:
        raise ValueError("source root selection is invalid")
    root_index = selected["index"]
    policy = selected.get("discovery", {})
    max_depth = _discovery_limit(policy, "max_depth", DISCOVERY_MAX_DEPTH, DISCOVERY_MAX_DEPTH, 0)
    max_directories = _discovery_limit(
        policy, "max_directories", DISCOVERY_MAX_DIRECTORIES, DISCOVERY_MAX_DIRECTORIES
    )
    max_repositories = _discovery_limit(
        policy, "max_repositories", DISCOVERY_MAX_REPOSITORIES, DISCOVERY_MAX_REPOSITORIES
    )
    time_budget = _discovery_limit(
        policy, "time_budget_seconds", DISCOVERY_TIME_BUDGET_SECONDS,
        DISCOVERY_TIME_BUDGET_SECONDS
    )
    raw_root = Path(selected["path"])
    if (
        raw_root.is_symlink()
        or not raw_root.is_dir()
        or raw_root.resolve(strict=True) != raw_root
        or (selected["managed"] and not managed_root_is_current(selected))
    ):
        raise ValueError("configured source root is unavailable")
    root = raw_root

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
        if visited >= max_directories or len(discovered) >= max_repositories:
            truncated = True
            break
        if time.monotonic() - started >= time_budget:
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

        if depth < max_depth:
            # Reverse before stack insertion so traversal stays deterministic.
            pending.extend((child, depth + 1) for child in reversed(child_dirs)
                           if not _is_git_repository(child))

    return {
        "root_index": root_index,
        "root_id": selected["id"],
        "root_name": selected["alias"],
        "root_path": str(root),
        "repositories": discovered,
        "registered_count": registered_count,
        "visited_directories": visited,
        "truncated": truncated,
        "limits": {
            "max_depth": max_depth,
            "max_directories": max_directories,
            "max_repositories": max_repositories,
            "max_entries_per_directory": DISCOVERY_MAX_ENTRIES_PER_DIRECTORY,
            "time_budget_seconds": time_budget,
        },
    }
