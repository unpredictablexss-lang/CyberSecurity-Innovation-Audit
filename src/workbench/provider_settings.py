"""Per-instance local Agent Provider settings.

The API key is stored outside the repository in a mode-0600 file beneath the
workbench data directory. It is never returned by this module public view.
For multi-user or hosted deployments, replace this local store with an
OS/external secrets manager; filesystem permissions are the local boundary.
"""
import json
import os
from pathlib import Path
import stat
import tempfile
from datetime import datetime, timezone
import uuid

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_API_PROTOCOL = "openai-responses"
SUPPORTED_API_PROTOCOLS = frozenset({"openai-responses", "openai-chat-completions"})
MAX_SETTINGS_BYTES = 16 * 1024

def default_data_dir():
    value = os.environ.get("OHSCANNER_DATA")
    return Path(value).expanduser().resolve() if value else Path.home() / "ohscanner-workbench" / "data"

def settings_path(data_dir=None):
    return (Path(data_dir) if data_dir else default_data_dir()) / "agent-provider.json"

def provider_check_path(data_dir=None):
    return (Path(data_dir) if data_dir else default_data_dir()) / "agent-provider-check.json"

def read_settings(data_dir=None):
    path = settings_path(data_dir)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {"base_url": DEFAULT_BASE_URL, "api_protocol": DEFAULT_API_PROTOCOL,
                "model": "", "proxy_url": "", "api_key": "",
                "config_revision": "", "last_provider_check": None}
    except OSError as exc:
        raise ValueError("无法安全读取本地模型配置") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SETTINGS_BYTES:
            raise ValueError("本地模型配置文件类型或大小无效")
        if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("本地模型配置权限不安全；请将文件权限限制为当前用户可读写")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("本地模型配置文件损坏或无法读取") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict):
        raise ValueError("本地模型配置格式无效")
    api_protocol = value.get("api_protocol", DEFAULT_API_PROTOCOL)
    if not isinstance(api_protocol, str) or api_protocol not in SUPPORTED_API_PROTOCOLS:
        raise ValueError("本地模型接口协议无效")
    return {
        "base_url": value.get("base_url", DEFAULT_BASE_URL),
        "api_protocol": api_protocol,
        "model": value.get("model", ""),
        "proxy_url": value.get("proxy_url", ""),
        "api_key": value.get("api_key", ""),
        "config_revision": value.get("config_revision", "") if isinstance(value.get("config_revision", ""), str) else "",
        "last_provider_check": value.get("last_provider_check") if isinstance(value.get("last_provider_check"), dict) else None,
    }

def _write_settings(settings, data_dir, revision, last_provider_check=None):
    path = settings_path(data_dir)
    api_protocol = settings.get("api_protocol", DEFAULT_API_PROTOCOL)
    if not isinstance(api_protocol, str) or api_protocol not in SUPPORTED_API_PROTOCOLS:
        raise ValueError("模型接口协议无效")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    payload = json.dumps({
        "schema_version": 2,
        "base_url": settings["base_url"],
        "api_protocol": api_protocol,
        "model": settings["model"],
        "proxy_url": settings.get("proxy_url", ""),
        "api_key": settings["api_key"],
        "config_revision": revision,
        "last_provider_check": last_provider_check,
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_SETTINGS_BYTES:
        raise ValueError("模型配置过大")
    fd, temporary = tempfile.mkstemp(prefix=".agent-provider-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

def _safe_provider_check(record, revision):
    if not isinstance(record, dict) or not revision or record.get("config_revision") != revision:
        return None
    checked_at = record.get("checked_at")
    endpoint_host = record.get("endpoint_host")
    model = record.get("model")
    duration_ms = record.get("duration_ms")
    if (not isinstance(checked_at, str) or len(checked_at) > 40
            or not isinstance(endpoint_host, str) or len(endpoint_host) > 253
            or not isinstance(model, str) or len(model) > 200
            or not isinstance(duration_ms, int) or isinstance(duration_ms, bool) or duration_ms < 0):
        return None
    values = {"config_revision": revision, "checked_at": checked_at,
              "endpoint_host": endpoint_host, "model": model, "duration_ms": duration_ms}
    for name in ("input_tokens", "output_tokens"):
        token_count = record.get(name)
        if token_count is not None and (not isinstance(token_count, int) or isinstance(token_count, bool) or token_count < 0):
            return None
        values[name] = token_count
    return values

def read_last_provider_check(data_dir=None, settings=None):
    """Read a sanitized probe record only when it matches the current config revision."""
    current = settings or read_settings(data_dir)
    revision = current.get("config_revision", "")
    if not revision:
        return None
    legacy = _safe_provider_check(current.get("last_provider_check"), revision)
    path = provider_check_path(data_dir)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return {key: value for key, value in legacy.items() if key != "config_revision"} if legacy else None
    except OSError as exc:
        raise ValueError("无法安全读取 Provider 探测记录") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 4096
                or (os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077))):
            raise ValueError("Provider 探测记录权限或大小无效")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Provider 探测记录损坏或无法读取") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    safe = _safe_provider_check(value, revision)
    selected = safe or legacy
    return {key: item for key, item in selected.items() if key != "config_revision"} if selected else None

def _write_provider_check(record, data_dir):
    path = provider_check_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".agent-provider-check-", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

def write_settings(settings, data_dir=None):
    """Save a new configuration revision and invalidate prior probe status."""
    _write_settings(settings, data_dir, uuid.uuid4().hex)

def record_provider_check(data_dir, provider, result):
    """Persist a successful, source-free probe only for the exact local config used."""
    current = read_settings(data_dir)
    if (current["api_protocol"] != provider.provider or current["base_url"] != provider.base_url or current["model"] != provider.model
            or current["proxy_url"] != provider.proxy_url or current["api_key"] != provider.api_key):
        return None
    revision = current["config_revision"] or uuid.uuid4().hex
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    record = {
        "config_revision": revision,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "endpoint_host": str(result.get("endpoint_host", ""))[:253],
        "model": str(result.get("model", ""))[:200],
        "duration_ms": max(0, int(result.get("duration_ms", 0))),
        "input_tokens": usage.get("input_tokens") if isinstance(usage.get("input_tokens"), int) else None,
        "output_tokens": usage.get("output_tokens") if isinstance(usage.get("output_tokens"), int) else None,
    }
    _write_provider_check(record, data_dir)
    return record

def clear_api_key(data_dir=None):
    value = read_settings(data_dir)
    value["api_key"] = ""
    if value["model"]:
        write_settings(value, data_dir)
    else:
        try:
            settings_path(data_dir).unlink()
        except FileNotFoundError:
            pass

def environment_overrides():
    names = ("OHSCANNER_LLM_API_PROTOCOL", "OHSCANNER_LLM_BASE_URL", "OHSCANNER_LLM_MODEL",
             "OHSCANNER_LLM_API_KEY", "OHSCANNER_LLM_PROXY_URL")
    return any(name in os.environ for name in names)
