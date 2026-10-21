"""Read-only OpenHarmony public-repository catalog and immutable branch preview."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPException
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
import unicodedata
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


API_ROOT = "https://api.gitcode.com/api/v5"
CATALOG_PATH = "/orgs/openharmony/repos"
CATALOG_DOC = "https://docs.gitcode.com/docs/apis/get-api-v-5-orgs-org-repos/"
BRANCH_DOC = "https://docs.gitcode.com/docs/apis/get-api-v-5-repos-owner-repo-branches-branch/"
CATALOG_TTL_SECONDS = 300
MAX_CATALOG_PAGES = 20
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,199}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def is_safe_repository_slug(value):
    """Accept one GitCode path segment; dots are valid except for traversal segments."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 100
        and value not in {".", ".."}
        and all("/" != char and "\\" != char and unicodedata.category(char) != "Cc"
                for char in value)
    )


def validate_repository_slug(value):
    if not is_safe_repository_slug(value):
        raise ValueError("invalid repository name")
    return value


_CACHE_LOCK = threading.Lock()
_MEMORY_CACHE = {}


class CatalogUnavailable(RuntimeError):
    pass


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _request_json(path, query=None):
    url = API_ROOT + path
    if query:
        url += "?" + urlencode(query)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "OHScanner/1 source-catalog"})
    opener = build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=10) as response:
            if response.geturl() != url:
                raise CatalogUnavailable("GitCode API redirected; request was refused")
            raw = response.read(MAX_PAGE_BYTES + 1)
            if len(raw) > MAX_PAGE_BYTES:
                raise CatalogUnavailable("GitCode API response exceeds the size limit")
            payload = json.loads(raw.decode("utf-8"))
            return payload, response.headers
    except HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            raise CatalogUnavailable("GitCode API redirected; request was refused") from None
        raise CatalogUnavailable("GitCode API returned HTTP " + str(exc.code)) from None
    except (URLError, TimeoutError, OSError, HTTPException, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogUnavailable("GitCode API request failed: " + type(exc).__name__) from None


def _normalize_page(rows):
    if not isinstance(rows, list):
        raise CatalogUnavailable("GitCode API returned an unexpected catalog shape")
    normalized = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        namespace = row.get("namespace") if isinstance(row.get("namespace"), dict) else {}
        slug = row.get("path")
        if (namespace.get("path") != "openharmony" or row.get("repo_type") != "code"
                or row.get("public") is not True or row.get("private") is True
                or not is_safe_repository_slug(slug)
                ):
            continue
        branch = row.get("default_branch")
        if not isinstance(branch, str) or not _BRANCH.fullmatch(branch) or ".." in branch:
            continue
        normalized.append({
            "slug": slug,
            "name": "openharmony/" + slug,
            "description": str(row.get("description") or "")[:2000],
            "default_branch": branch,
            "language": str(row.get("language") or "unknown")[:100],
            "pushed_at": str(row.get("pushed_at") or "")[:80],
            "fork": bool(row.get("fork", False)),
            "size_kib": (row.get("size") if isinstance(row.get("size"), int)
                         and not isinstance(row.get("size"), bool) and row.get("size") >= 0 else None),
            "web_url": "https://gitcode.com/openharmony/" + quote(slug, safe=""),
            "clone_url": approved_clone_url(slug),
            "catalog_source": "GitCode OpenHarmony public code repository listing",
        })
    return normalized


def _fetch_catalog_pages():
    first, headers = _request_json(CATALOG_PATH, {
        "type": "public", "repo_type": "code", "per_page": 100, "page": 1,
    })
    try:
        total_pages = int(headers.get("total_page", "1"))
        total_count = int(headers.get("total_count", str(len(first))))
    except (TypeError, ValueError):
        raise CatalogUnavailable("GitCode API returned invalid pagination metadata") from None
    if not 1 <= total_pages <= MAX_CATALOG_PAGES or total_count < 0:
        raise CatalogUnavailable("GitCode catalog exceeds the configured pagination limit")
    pages = {1: first}
    if total_pages > 1:
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="ohscanner-catalog") as pool:
            futures = {
                page: pool.submit(_request_json, CATALOG_PATH, {
                    "type": "public", "repo_type": "code", "per_page": 100, "page": page,
                })
                for page in range(2, total_pages + 1)
            }
            for page, future in futures.items():
                rows, _ = future.result()
                pages[page] = rows
    raw_size = sum(len(json.dumps(rows, ensure_ascii=False).encode("utf-8")) for rows in pages.values())
    if raw_size > MAX_TOTAL_BYTES:
        raise CatalogUnavailable("GitCode catalog exceeds the total response size limit")
    records = []
    for page in range(1, total_pages + 1):
        records.extend(_normalize_page(pages[page]))
    deduped = {row["slug"]: row for row in records}
    return sorted(deduped.values(), key=lambda row: row["slug"].casefold()), total_count


def _cache_file(settings):
    return Path(settings.data_dir) / "catalog-cache" / "gitcode-openharmony-public.json"


def _read_saved_cache(settings):
    path = _cache_file(settings)
    try:
        if (path.parent.is_symlink() or path.parent.resolve(strict=False) != path.parent
                or path.is_symlink() or path.stat().st_size > MAX_TOTAL_BYTES):
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        records = value.get("items")
        saved = float(value.get("saved_epoch"))
        if (not isinstance(records, list) or len(records) > 2000
                or any(not isinstance(row, dict) or not is_safe_repository_slug(row.get("slug")) for row in records)):
            return None
        return {"items": records, "total_count": int(value.get("total_count", len(records))),
                "saved_epoch": saved, "catalog_sha256": value.get("catalog_sha256")}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def _save_cache(settings, value):
    path = _cache_file(settings)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.parent.resolve() != path.parent:
        raise CatalogUnavailable("catalog cache directory is unsafe")
    temporary = path.with_name(path.name + ".tmp-" + hashlib.sha256(os.urandom(16)).hexdigest()[:12])
    data = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def catalog_snapshot(settings, *, refresh=False):
    key = str(Path(settings.data_dir).resolve())
    with _CACHE_LOCK:
        cached = _MEMORY_CACHE.get(key)
        if not refresh and cached and time.time() - cached["saved_epoch"] <= CATALOG_TTL_SECONDS:
            return {**cached, "stale": False}
        if not refresh:
            saved = _read_saved_cache(settings)
            if saved and time.time() - saved["saved_epoch"] <= CATALOG_TTL_SECONDS:
                _MEMORY_CACHE[key] = saved
                return {**saved, "stale": False}
        try:
            records, total_count = _fetch_catalog_pages()
            canonical = json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            saved = {"items": records, "total_count": total_count, "saved_epoch": time.time(),
                     "catalog_sha256": hashlib.sha256(canonical).hexdigest()}
            _save_cache(settings, saved)
            _MEMORY_CACHE[key] = saved
            return {**saved, "stale": False}
        except CatalogUnavailable as exc:
            saved = cached or _read_saved_cache(settings)
            if saved:
                return {**saved, "stale": True, "refresh_error": str(exc)}
            raise


def repository_catalog(settings, *, query="", page=1, per_page=50, refresh=False):
    if not isinstance(query, str) or len(query) > 120:
        raise ValueError("catalog search text is too long")
    if not isinstance(page, int) or isinstance(page, bool) or not 1 <= page <= 1000:
        raise ValueError("catalog page is out of range")
    if not isinstance(per_page, int) or isinstance(per_page, bool) or not 1 <= per_page <= 100:
        raise ValueError("catalog page size must be between 1 and 100")
    snapshot = catalog_snapshot(settings, refresh=refresh)
    term = query.casefold().strip()
    rows = [row for row in snapshot["items"] if not term or term in " ".join(
        (row.get("name", ""), row.get("description", ""), row.get("language", ""), row.get("slug", ""))
    ).casefold()]
    start = (page - 1) * per_page
    return {
        "items": rows[start:start + per_page], "total": len(rows), "page": page,
        "per_page": per_page, "catalog_total_count": snapshot["total_count"],
        "catalog_sha256": snapshot["catalog_sha256"], "catalog_updated_at": datetime.fromtimestamp(
            snapshot["saved_epoch"], timezone.utc).isoformat(),
        "stale": snapshot.get("stale", False), "refresh_error": snapshot.get("refresh_error"),
        "provenance": {"source": "GitCode public organization repository API",
                       "organization_path": "openharmony", "repository_type": "public code",
                       "listing_api": API_ROOT + CATALOG_PATH, "documentation": CATALOG_DOC,
                       "identity_note": "This catalog entry records the GitCode organization listing; it is not an independent cryptographic verification of project ownership."},
    }


def _catalog_entry(settings, slug):
    if not is_safe_repository_slug(slug):
        raise ValueError("invalid OpenHarmony repository name")
    snapshot = catalog_snapshot(settings)
    if snapshot.get("stale"):
        raise CatalogUnavailable("catalog is stale because GitCode is unreachable; refresh it before selecting a repository")
    entry = next((row for row in snapshot["items"] if row["slug"] == slug), None)
    if entry is None:
        raise ValueError("repository is not present in the current public OpenHarmony code catalog")
    return entry, snapshot


def repository_preview(settings, slug):
    entry, snapshot = _catalog_entry(settings, slug)
    branch = entry["default_branch"]
    payload, _ = _request_json(
        "/repos/openharmony/" + quote(slug, safe="") + "/branches/" + quote(branch, safe=""),
    )
    if not isinstance(payload, dict) or payload.get("name") != branch:
        raise CatalogUnavailable("GitCode branch API returned an unexpected response")
    commit_row = payload.get("commit") if isinstance(payload.get("commit"), dict) else {}
    commit = commit_row.get("id")
    if not isinstance(commit, str) or not _SHA.fullmatch(commit):
        raise CatalogUnavailable("GitCode branch response has no full immutable commit SHA")
    tree_payload, _ = _request_json(
        "/repos/openharmony/" + quote(slug, safe="") + "/git/trees/" + quote(commit, safe=""),
    )
    tree_rows = tree_payload.get("tree") if isinstance(tree_payload, dict) else None
    if not isinstance(tree_rows, list):
        raise CatalogUnavailable("GitCode tree API returned an unexpected response")
    tree_preview = [{"path": str(item.get("path") or item.get("name") or "")[:500],
                     "type": str(item.get("type") or "unknown")[:32],
                     "object_sha": item.get("sha") if isinstance(item.get("sha"), str)
                     and _SHA.fullmatch(item["sha"]) else None}
                    for item in tree_rows[:100] if isinstance(item, dict)]
    binding = {"repository": entry["name"], "slug": slug, "branch": branch,
               "commit": commit, "clone_url": entry["clone_url"],
               "catalog_sha256": snapshot["catalog_sha256"], "catalog_source": entry["catalog_source"]}
    digest = hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        **entry, "commit": commit, "tree": None, "preview_sha256": digest,
        "catalog_sha256": snapshot["catalog_sha256"],
        "tree_preview": tree_preview,
        "tree_preview_truncated": len(tree_rows) > 100,
        "previewed_at": datetime.now(timezone.utc).isoformat(),
        "commit_message": str(commit_row.get("title") or commit_row.get("message") or "")[:1000],
        "commit_date": str(commit_row.get("committed_date") or "")[:80],
        "tree_note": "此处为 GitCode API 返回的目录项预览，尚未独立验证。完整根 Tree SHA 会在本地取得固定 Commit 后由 Git 对象核验并写入扫描任务。",
        "provenance": {"source": "GitCode public organization repository API",
                       "branch_api": API_ROOT + "/repos/openharmony/" + quote(slug, safe="") + "/branches/" + quote(branch, safe=""),
                       "documentation": BRANCH_DOC,
                       "identity_note": "组织目录和 API 元数据说明来源，不等同于独立身份认证。"},
    }


def validate_preview(settings, slug, branch, commit, preview_sha256):
    current = repository_preview(settings, slug)
    if (branch != current["default_branch"] or commit != current["commit"]
            or preview_sha256 != current["preview_sha256"]):
        raise ValueError("repository preview changed; refresh the fixed version before scanning")
    return current


def approved_clone_url(slug):
    if not is_safe_repository_slug(slug):
        raise ValueError("invalid OpenHarmony repository name")
    return "https://gitcode.com/openharmony/" + quote(slug, safe="") + ".git"


def validate_branch(value):
    if not isinstance(value, str) or not _BRANCH.fullmatch(value) or ".." in value:
        raise ValueError("invalid default branch name")
    return value


def validate_commit(value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("commit must be a full SHA-1 hash")
    return value
