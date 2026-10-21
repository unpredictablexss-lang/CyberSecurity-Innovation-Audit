"""Reviewed, fixed reproduction tests. Browser input never selects executable code."""
import hashlib
import json
import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
HARNESS_ROOT = PROJECT / "src/ohscanner/poc/harnesses"
AUTH_ID = "auth01_descriptor_bypass"
LIFETIME_ID = "cpp_lifetime_unique_ptr_alias"
SHARED_PTR_ID = "cpp_shared_ptr_delayed_singleton"
CPP_IDS = frozenset({LIFETIME_ID, SHARED_PTR_ID})
TESTS = {
    AUTH_ID: {
        "label": "AUTH-01 描述符边界", "scope": "component_harness",
        "requires_target_support": True,
        "description": "使用固定 inputmethod_imf 版本和 c_utils 支持源码，重放缺陷、修复与补丁控制。",
    },
    LIFETIME_ID: {
        "label": "C++ 生命周期：unique_ptr 借用指针", "scope": "synthetic_harness",
        "requires_target_support": False,
        "description": "自编最小样例：用 AddressSanitizer 检查 4 种失效借用指针行为及 2 种修复/安全控制。关联案例仅用于归档，不代表该候选已复现。",
    },
    SHARED_PTR_ID: {
        "label": "C++ 共享指针竞争：DelayedSingleton", "scope": "component_harness",
        "requires_target_support": False,
        "description": "固定历史 singleton.h 样本：用 ThreadSanitizer 比较缺陷、上游修改和本地全原子修复。只核验留存源码哈希，不证明当前案例候选或 Git 来源已验证。",
    },
}


def manifest_path(harness_id):
    if harness_id not in TESTS:
        raise ValueError("unknown reproduction test")
    return HARNESS_ROOT / harness_id / "manifest.json"


def shared_source_root():
    return Path(os.environ.get("OHSCANNER_SHARED_PTR_SOURCE_ROOT", str(PROJECT))).expanduser().resolve()


def shared_sources():
    """Read only the two manifest-pinned artifacts; no arbitrary source uploads."""
    manifest = json.loads(manifest_path(SHARED_PTR_ID).read_text(encoding="utf-8"))
    root = shared_source_root()
    files = {}
    for revision in ("vulnerable", "upstream_fix"):
        entry = manifest["revisions"][revision]
        path = root / entry["path"]
        if not path.is_file():
            raise ValueError("缺少共享指针测试的固定历史源码；请在服务器配置 OHSCANNER_SHARED_PTR_SOURCE_ROOT。")
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("固定历史源码超过大小限制")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("共享指针固定历史源码 SHA-256 不匹配")
        if any(quote not in raw.decode("utf-8") for quote in entry["required_quotes"]):
            raise ValueError("共享指针固定历史源码引文不匹配")
        files[entry["path"]] = raw
    return files


def catalog():
    items = []
    for harness_id, metadata in TESTS.items():
        item = {"id": harness_id, **metadata, "source_status": "available", "source_reason": None}
        if harness_id == SHARED_PTR_ID:
            try:
                shared_sources()
            except (ValueError, OSError, UnicodeError) as exc:
                item.update(source_status="blocked", source_reason=str(exc))
        items.append(item)
    return items
