"""Versioned policy presets and protected local persistence.

Snapshots are enforced by the progressive L2/L3 Worker ledger. USD remains advisory
without a verified Provider-side spend cap.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any

from .contracts import POLICY_VERSION, content_sha256


class PolicyError(ValueError):
    """The requested policy is malformed or exceeds local service limits."""


class PolicyRevisionConflict(PolicyError):
    """The settings page attempted to overwrite a newer revision."""


class PolicyStoreError(PolicyError):
    """The protected policy sidecar cannot be read or safely replaced."""


_LIMIT_BOUNDS = {
    "quick_screen_groups_per_audit": (1, 10_000),
    "deep_groups_per_audit": (0, 1_000),
    "max_tool_steps_per_group": (1, 32),
    "max_model_concurrency": (1, 8),
    "max_model_calls_per_audit": (1, 10_000),
    "max_input_tokens_per_audit": (1_024, 2_000_000),
    "max_output_tokens_per_audit": (256, 500_000),
    "max_ai_wall_seconds": (60, 14_400),
}
_LIMIT_KEYS = frozenset((*_LIMIT_BOUNDS, "max_cost_usd"))
_COST_RE = re.compile(r"^(?:0|[1-9]\d{0,5})(?:\.\d{1,8})?$")
_STORAGE_SCHEMA = 1
_MAX_STORE_BYTES = 4 * 1024 * 1024
_MAX_HISTORY = 10_000


def _limits(*, quick, deep, steps, concurrency, calls, input_tokens,
            output_tokens, seconds, cost):
    return {
        "quick_screen_groups_per_audit": quick,
        "deep_groups_per_audit": deep,
        "max_tool_steps_per_group": steps,
        "max_model_concurrency": concurrency,
        "max_model_calls_per_audit": calls,
        "max_input_tokens_per_audit": input_tokens,
        "max_output_tokens_per_audit": output_tokens,
        "max_ai_wall_seconds": seconds,
        "max_cost_usd": cost,
    }


# The taskbook marks these as initial product defaults, not measured optima.
PRESETS = {
    "economical": {
        "limits": _limits(
            quick=10, deep=2, steps=6, concurrency=1, calls=40,
            input_tokens=100_000, output_tokens=20_000, seconds=900, cost="5.00",
        ),
        "family_quotas": True,
    },
    "standard": {
        "limits": _limits(
            quick=30, deep=6, steps=8, concurrency=2, calls=120,
            input_tokens=400_000, output_tokens=100_000, seconds=1_800, cost="25.00",
        ),
        "family_quotas": True,
    },
    "deep": {
        "limits": _limits(
            quick=100, deep=20, steps=12, concurrency=3, calls=500,
            input_tokens=2_000_000, output_tokens=500_000, seconds=5_400, cost="100.00",
        ),
        "family_quotas": True,
    },
}
PROFILES = frozenset((*PRESETS, "custom"))


def _strict_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PolicyError(f"{name} must be an integer")
    low, high = _LIMIT_BOUNDS[name]
    if not low <= value <= high:
        raise PolicyError(f"{name} must be between {low} and {high}")
    return value


def _validate_limits(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError("limits must be an object")
    if set(value) != _LIMIT_KEYS:
        missing = sorted(_LIMIT_KEYS - set(value))
        extra = sorted(set(value) - _LIMIT_KEYS)
        raise PolicyError(f"invalid limit fields (missing={missing}, extra={extra})")
    result = {key: _strict_int(value[key], key) for key in _LIMIT_BOUNDS}
    cost = value["max_cost_usd"]
    if not isinstance(cost, str) or not _COST_RE.fullmatch(cost):
        raise PolicyError("max_cost_usd must be a non-negative decimal string")
    try:
        decimal_cost = Decimal(cost)
    except InvalidOperation as error:
        raise PolicyError("max_cost_usd is not a valid decimal") from error
    if not decimal_cost.is_finite() or decimal_cost <= 0 or decimal_cost > Decimal("1000"):
        raise PolicyError("max_cost_usd must be greater than 0 and no more than 1000")
    if result["deep_groups_per_audit"] > result["quick_screen_groups_per_audit"]:
        raise PolicyError("deep group limit cannot exceed quick-screen group limit")
    if result["max_model_calls_per_audit"] < (
        result["quick_screen_groups_per_audit"] + result["deep_groups_per_audit"]
    ):
        raise PolicyError("model-call limit must cover at least one call for each selected group")
    result["max_cost_usd"] = cost
    return result


def build_policy(profile: str = "standard", limits: dict[str, Any] | None = None,
                 family_quotas: bool | None = None) -> dict[str, Any]:
    """Create a strict, JSON-safe policy snapshot from a preset or custom values."""
    if profile not in PROFILES:
        raise PolicyError("profile must be economical, standard, deep, or custom")
    if profile == "custom":
        resolved_limits = _validate_limits(limits if limits is not None else PRESETS["standard"]["limits"])
        resolved_family_quotas = family_quotas if family_quotas is not None else True
    else:
        preset = PRESETS[profile]
        expected_limits = preset["limits"]
        if limits is not None and _validate_limits(limits) != expected_limits:
            raise PolicyError("preset limits are fixed; choose custom to edit them")
        if family_quotas is not None and family_quotas is not preset["family_quotas"]:
            raise PolicyError("preset family quota settings are fixed; choose custom to edit them")
        resolved_limits = dict(expected_limits)
        resolved_family_quotas = preset["family_quotas"]
    if not isinstance(resolved_family_quotas, bool):
        raise PolicyError("family_quotas must be a boolean")
    return {
        "policy_version": POLICY_VERSION,
        "profile": profile,
        "limits": resolved_limits,
        "family_quotas": resolved_family_quotas,
        "preserve_all_candidates": True,
        "consent_required": True,
    }


def validate_policy(value: Any) -> dict[str, Any]:
    """Validate a stored policy, rejecting unknown fields and unsafe coercions."""
    expected = {
        "policy_version", "profile", "limits", "family_quotas",
        "preserve_all_candidates", "consent_required",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise PolicyError("policy fields do not match the supported schema")
    if value["policy_version"] != POLICY_VERSION:
        raise PolicyError("unsupported policy version")
    if value["preserve_all_candidates"] is not True:
        raise PolicyError("preserving every original candidate is mandatory")
    if value["consent_required"] is not True:
        raise PolicyError("task-level consent is mandatory")
    return build_policy(value["profile"], value["limits"], value["family_quotas"])


def policy_envelope(policy: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_policy(policy)
    return {
        "policy": normalized,
        "policy_sha256": content_sha256(normalized),
    }


class PolicyStore:
    """Process-safe JSON settings store with atomic replacement and revisions."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "progressive-triage-policy.json"
        self.lock_path = self.data_dir / ".progressive-triage-policy.lock"

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            envelope = policy_envelope(build_policy())
            return {
                "storage_schema": _STORAGE_SCHEMA,
                "revision": 0,
                "updated_at": None,
                "updated_by": None,
                **envelope,
                "history": [],
            }
        except OSError as error:
            raise PolicyStoreError("policy file cannot be opened safely") from error
        try:
            with os.fdopen(fd, "rb") as source:
                metadata = os.fstat(source.fileno())
                if not stat.S_ISREG(metadata.st_mode):
                    raise PolicyStoreError("policy file must be a regular file")
                if metadata.st_mode & 0o077:
                    raise PolicyStoreError("policy file permissions must be private")
                if metadata.st_size > _MAX_STORE_BYTES:
                    raise PolicyStoreError("policy file exceeds the local size limit")
                payload = source.read(_MAX_STORE_BYTES + 1)
            if len(payload) > _MAX_STORE_BYTES:
                raise PolicyStoreError("policy file exceeds the local size limit")
            stored = json.loads(payload.decode("utf-8"))
        except PolicyStoreError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PolicyStoreError("policy file is unreadable or invalid") from error
        if not isinstance(stored, dict) or stored.get("storage_schema") != _STORAGE_SCHEMA:
            raise PolicyStoreError("unsupported policy storage schema")
        try:
            policy = validate_policy(stored.get("policy"))
        except PolicyError as error:
            raise PolicyStoreError("stored policy failed schema validation") from error
        expected_keys = {
            "storage_schema", "revision", "updated_at", "updated_by",
            "policy", "policy_sha256", "history",
        }
        if set(stored) != expected_keys:
            raise PolicyStoreError("policy store contains unknown or missing fields")
        revision = stored["revision"]
        history = stored["history"]
        if (not isinstance(revision, int) or isinstance(revision, bool) or revision < 0
                or not isinstance(history, list) or len(history) > _MAX_HISTORY):
            raise PolicyStoreError("policy revision history is malformed")
        envelope = policy_envelope(policy)
        if stored["policy_sha256"] != envelope["policy_sha256"]:
            raise PolicyStoreError("policy hash does not match its stored contents")
        return {
            "storage_schema": _STORAGE_SCHEMA,
            "revision": revision,
            "updated_at": stored["updated_at"],
            "updated_by": stored["updated_by"],
            **envelope,
            "history": history,
        }

    def read(self) -> dict[str, Any]:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            return self._read_unlocked()
        except OSError as error:
            raise PolicyStoreError("policy store cannot be locked safely") from error
        finally:
            os.close(lock_fd)

    def update(self, policy: dict[str, Any], expected_revision: int,
               actor: str = "local-workbench") -> dict[str, Any]:
        normalized = validate_policy(policy)
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            raise PolicyError("expected_revision must be a non-negative integer")
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            current = self._read_unlocked()
            if current["revision"] != expected_revision:
                raise PolicyRevisionConflict("policy changed; reload before saving")
            if current["policy"] == normalized:
                return current
            if current["revision"] >= _MAX_HISTORY:
                raise PolicyStoreError("policy history limit reached; archive the local settings first")
            updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            envelope = policy_envelope(normalized)
            event = {
                "revision": current["revision"] + 1,
                "updated_at": updated_at,
                "updated_by": actor,
                "policy_sha256": envelope["policy_sha256"],
                "profile": normalized["profile"],
            }
            stored = {
                "storage_schema": _STORAGE_SCHEMA,
                "revision": event["revision"],
                "updated_at": updated_at,
                "updated_by": actor,
                **envelope,
                "history": [*current["history"], event],
            }
            payload = json.dumps(stored, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
            if len(payload) > _MAX_STORE_BYTES:
                raise PolicyStoreError("policy history would exceed the local size limit")
            temporary = self.data_dir / (".progressive-triage-policy." + uuid.uuid4().hex + ".tmp")
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd, "wb") as target:
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, self.path)
                dir_fd = os.open(self.data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                try:
                    temporary.unlink()
                except OSError:
                    pass
                raise
            return stored
        except PolicyError:
            raise
        except OSError as error:
            raise PolicyStoreError("policy settings could not be replaced atomically") from error
        finally:
            os.close(lock_fd)
