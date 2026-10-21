"""Selected source download locations; Windows drive paths work through WSL mounts."""
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tempfile

try:
    import fcntl
except ImportError:  # pragma: no cover - the current service runtime is Linux/WSL
    fcntl = None

REGISTRY_FILENAME = "download-locations.json"
MAX_LOCATIONS = 64
WINDOWS_DRIVE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def _is_wsl():
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text(
            encoding="utf-8", errors="replace"
        ).casefold()
    except OSError:
        return False


def normalize_download_dir(settings, raw_path):
    """Validate and canonicalize a server-side path without creating it."""
    if raw_path is None or (isinstance(raw_path, str) and not raw_path.strip()):
        return str(Path(settings.repository_cache_roots[0]).resolve(strict=False))
    if not isinstance(raw_path, str) or len(raw_path) > 4096:
        raise ValueError("下载目录路径无效或超过 4096 个字符")
    raw = raw_path.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("下载目录不能包含控制字符")

    drive = WINDOWS_DRIVE.fullmatch(raw)
    if os.name == "nt":
        candidate = Path(raw)
        if not PureWindowsPath(raw).is_absolute():
            raise ValueError("请输入绝对路径，例如 D:\\OpenHarmony")
    elif drive:
        if not _is_wsl():
            raise ValueError("当前服务运行在 Linux；Windows 盘符路径仅能在 WSL 中使用，请输入 Linux 绝对路径")
        parts = re.split(r"[\\/]", drive.group(2))
        if any(part in {".", ".."} for part in parts):
            raise ValueError("下载目录不能包含 . 或 .. 路径段")
        mount = Path("/mnt") / drive.group(1).lower()
        if not mount.is_dir():
            raise ValueError(f"Windows 磁盘 {drive.group(1)}: 尚未挂载到 WSL（预期位置 {mount}）")
        candidate = mount.joinpath(*[part for part in parts if part])
    else:
        posix = PurePosixPath(raw)
        if not posix.is_absolute():
            raise ValueError("请输入绝对路径，例如 /home/audit/OpenHarmony 或 D:\\OpenHarmony")
        if ".." in posix.parts:
            raise ValueError("下载目录不能包含 .. 路径段")
        candidate = Path(raw).expanduser()

    if ".." in candidate.parts:
        raise ValueError("下载目录不能包含 .. 路径段")
    candidate = Path(os.path.normpath(str(candidate))).absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("下载目录路径不能包含符号链接")
    canonical = candidate.resolve(strict=False)
    if canonical.exists() and not canonical.is_dir():
        raise ValueError("下载位置必须是目录")
    if canonical == Path(canonical.anchor) or (canonical.exists() and os.path.ismount(canonical)):
        raise ValueError("不能把文件系统根目录或磁盘挂载点作为下载目录")

    data_dir = Path(settings.data_dir).resolve(strict=False)
    cache_roots = {Path(item).resolve(strict=False) for item in settings.repository_cache_roots}
    overlaps_data = (canonical == data_dir or canonical.is_relative_to(data_dir)
                     or data_dir.is_relative_to(canonical))
    if overlaps_data and canonical not in cache_roots:
        raise ValueError("下载目录不能与工作台数据库、缓存或产物目录重叠")
    for configured in settings.target_roots:
        root = Path(configured).resolve(strict=False)
        if root.is_relative_to(canonical) and root != canonical:
            raise ValueError("下载目录不能包含已有源码授权根目录；请选择该根目录或其他独立目录")
    return str(canonical)


def load_download_locations(data_dir):
    path = Path(data_dir) / REGISTRY_FILENAME
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("下载目录登记文件不安全或超出大小限制")
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("下载目录登记文件不可读取") from error
    if not isinstance(rows, list) or len(rows) > MAX_LOCATIONS:
        raise ValueError("下载目录登记文件格式无效")
    result = []
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                or not Path(row["path"]).is_absolute()
                or not isinstance(row.get("device"), int) or not isinstance(row.get("inode"), int)
                or row["path"] in seen):
            raise ValueError("下载目录登记项格式无效")
        seen.add(row["path"])
        result.append(row)
    return result


def download_location_is_current(row):
    path = Path(row["path"])
    try:
        if path.is_symlink() or path.resolve(strict=False) != path or not path.is_dir():
            return False
        metadata = path.stat()
        return (metadata.st_dev == row["device"] and metadata.st_ino == row["inode"]
                and os.access(path, os.R_OK | os.W_OK | os.X_OK))
    except OSError:
        return False


@contextmanager
def _locked(data_dir):
    if fcntl is None:
        raise RuntimeError("download location registry requires a supported process lock")
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = data_dir / "download-locations.lock"
    if lock_path.is_symlink():
        raise ValueError("下载目录登记锁不安全")
    with lock_path.open("a", encoding="utf-8") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _write(data_dir, rows):
    path = Path(data_dir) / REGISTRY_FILENAME
    if path.is_symlink():
        raise ValueError("下载目录登记文件不能是符号链接")
    fd, temporary = tempfile.mkstemp(prefix=".download-locations-", dir=data_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(rows, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
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


def ensure_download_dir(settings, raw_path):
    """Create a user-confirmed destination and register it for later audits."""
    canonical = Path(normalize_download_dir(settings, raw_path))
    cursor = Path(canonical.anchor)
    for part in canonical.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("下载目录路径不能包含符号链接")
    canonical.mkdir(parents=True, exist_ok=True, mode=0o700)
    if canonical.is_symlink() or canonical.resolve(strict=True) != canonical:
        raise ValueError("下载目录创建后路径发生变化或包含符号链接")
    if not canonical.is_dir() or not os.access(canonical, os.R_OK | os.W_OK | os.X_OK):
        raise ValueError("服务进程无法读写所选下载目录")
    if canonical == Path(canonical.anchor) or os.path.ismount(canonical):
        raise ValueError("不能把文件系统根目录或磁盘挂载点作为下载目录")
    data_dir = Path(settings.data_dir).resolve(strict=False)
    if (canonical == data_dir or canonical.is_relative_to(data_dir)
            or data_dir.is_relative_to(canonical)):
        if canonical not in {Path(item).resolve(strict=False) for item in settings.repository_cache_roots}:
            raise ValueError("下载目录不能与工作台数据目录重叠")

    allowed = [Path(item).resolve(strict=False) for item in settings.target_roots]
    if any(canonical.is_relative_to(root) for root in allowed):
        return str(canonical)
    if any(root.is_relative_to(canonical) and root != canonical for root in allowed):
        raise ValueError("所选下载目录包含已有源码授权根目录")
    metadata = canonical.stat()
    with _locked(settings.data_dir):
        rows = load_download_locations(settings.data_dir)
        if any(row["path"] == str(canonical) and download_location_is_current(row) for row in rows):
            return str(canonical)
        rows = [row for row in rows if row["path"] != str(canonical)]
        if len(rows) >= MAX_LOCATIONS:
            raise ValueError("已登记下载目录达到上限，请移除旧目录后重试")
        rows.append({"path": str(canonical), "device": metadata.st_dev, "inode": metadata.st_ino})
        _write(settings.data_dir, rows)
    return str(canonical)
