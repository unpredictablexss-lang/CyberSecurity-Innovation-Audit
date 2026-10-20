"""Persistent, operator-managed source-root allowlist."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid


ROOTS_FILENAME = "managed-source-roots.json"
MAX_ROOTS = 64
MAX_FILE_BYTES = 1024 * 1024


def _registry_path(data_dir):
    return Path(data_dir) / ROOTS_FILENAME


def load_managed_roots(data_dir):
    path = _registry_path(data_dir)
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise ValueError("managed source-root registry is unsafe")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("managed source-root registry exceeds the safe limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("managed source-root registry is unreadable") from error
    if not isinstance(data, list) or len(data) > MAX_ROOTS:
        raise ValueError("managed source-root registry has an invalid shape")
    rows = []
    ids = set()
    paths = set()
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("managed source-root registry has an invalid entry")
        root_id, alias, raw_path = row.get("id"), row.get("alias"), row.get("path")
        if (
            not isinstance(root_id, str) or not root_id
            or not isinstance(alias, str) or not alias
            or not isinstance(raw_path, str) or not Path(raw_path).is_absolute()
            or root_id in ids or raw_path in paths
            or not isinstance(row.get("device"), int) or not isinstance(row.get("inode"), int)
        ):
            raise ValueError("managed source-root registry has an invalid entry")
        ids.add(root_id)
        paths.add(raw_path)
        rows.append({
            "id": root_id,
            "alias": alias,
            "path": raw_path,
            "managed": True,
            "last_checked_at": row.get("last_checked_at"),
            "device": row["device"],
            "inode": row["inode"],
            "discovery": row.get("discovery") or {
                "max_depth": 6,
                "max_directories": 5000,
                "max_repositories": 1000,
            },
        })
    return rows


def managed_root_is_current(row):
    path = Path(row["path"])
    try:
        if path.is_symlink() or path.resolve(strict=False) != path or not path.is_dir():
            return False
        metadata = path.stat()
        return (
            metadata.st_dev == row.get("device")
            and metadata.st_ino == row.get("inode")
            and not (metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
            and os.access(path, os.R_OK | os.X_OK)
        )
    except OSError:
        return False


@contextmanager
def _locked(data_dir):
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = data_dir / "managed-source-roots.lock"
    if lock_path.is_symlink():
        raise ValueError("managed source-root lock is unsafe")
    with lock_path.open("a", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _write(data_dir, rows):
    path = _registry_path(data_dir)
    if path.is_symlink():
        raise ValueError("managed source-root registry is unsafe")
    data = json.dumps(rows, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if len(data.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("managed source-root registry exceeds the safe limit")
    fd, temporary = tempfile.mkstemp(prefix=".managed-source-roots-", dir=data_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(data_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _canonical_root(settings, raw_path):
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("请输入服务器上的源码目录绝对路径")
    candidate = Path(raw_path.strip()).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("源码根目录必须是规范的绝对路径")
    if not candidate.exists():
        raise ValueError("源码根目录不存在或服务不可访问")
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("源码根目录路径不能包含符号链接")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("源码根目录必须是可读取的目录")
    if resolved == Path(resolved.anchor) or os.path.ismount(resolved):
        raise ValueError("不能把文件系统根目录或磁盘挂载点登记为源码根目录")
    data_dir = Path(settings.data_dir).resolve(strict=False)
    if resolved == data_dir or resolved.is_relative_to(data_dir) or data_dir.is_relative_to(resolved):
        raise ValueError("源码根目录不能包含工作台数据库、缓存或产物目录")
    metadata = resolved.stat()
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("源码根目录不能由其他用户或共享组写入")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise ValueError("服务进程无权读取源码根目录")
    return resolved


def add_managed_root(settings, alias, raw_path):
    canonical = _canonical_root(settings, raw_path)
    name = alias.strip() if isinstance(alias, str) else ""
    name = name or canonical.name
    if len(name) > 80 or any(ord(character) < 32 for character in name):
        raise ValueError("根目录别名须为 1 到 80 个可见字符")
    if not name:
        raise ValueError("根目录别名不能为空")
    with _locked(settings.data_dir):
        rows = load_managed_roots(settings.data_dir)
        configured = tuple(Path(path).resolve(strict=False) for path in settings.target_roots)
        for existing in configured:
            if canonical == existing or canonical.is_relative_to(existing) or existing.is_relative_to(canonical):
                raise ValueError("源码根目录与现有根目录重叠；请使用已有根目录或选择独立目录")
        if len(rows) >= MAX_ROOTS:
            raise ValueError("受控源码根目录数量已达上限")
        if any(row["path"] == str(canonical) for row in rows):
            raise ValueError("该源码根目录已经登记")
        configured_aliases = {
            Path(path).name.casefold()
            for path in settings._configured_target_roots
            if Path(path).name and Path(path).name != "repo-cache"
        }
        if name.casefold() in configured_aliases or any(
            row["alias"].casefold() == name.casefold() for row in rows
        ):
            raise ValueError("根目录别名已经使用，请换一个名称")
        row = {
            "id": uuid.uuid4().hex,
            "alias": name,
            "path": str(canonical),
            "device": canonical.stat().st_dev,
            "inode": canonical.stat().st_ino,
            "last_checked_at": datetime.now(timezone.utc).isoformat(),
            "discovery": {
                "max_depth": 6,
                "max_directories": 5000,
                "max_repositories": 1000,
                "time_budget_seconds": 20,
            },
        }
        rows.append(row)
        _write(settings.data_dir, rows)
    return {**row, "managed": True}


def remove_managed_root(settings, root_id):
    with _locked(settings.data_dir):
        rows = load_managed_roots(settings.data_dir)
        remaining = [row for row in rows if row["id"] != root_id]
        if len(remaining) == len(rows):
            raise KeyError("managed source root not found")
        _write(settings.data_dir, remaining)
    return {"id": root_id, "removed": True}


def record_root_check(settings, root_id):
    with _locked(settings.data_dir):
        rows = load_managed_roots(settings.data_dir)
        found = False
        for row in rows:
            if row["id"] == root_id:
                row["last_checked_at"] = datetime.now(timezone.utc).isoformat()
                found = True
        if found:
            _write(settings.data_dir, rows)
