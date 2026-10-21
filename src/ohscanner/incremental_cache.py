"""Bounded cache for explicitly source-Blob-only, per-file detector results.

This cache is not a general detector-result cache. Detectors must opt in with
the reviewed git_blob_single_file_v1 contract and consume only the listed
per-file facts. Cross-file, build, macro, include-resolution, archive, fixture,
and unknown inputs fail closed to normal detector execution.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .ast_cache import parser_fingerprint
from .contracts import DetectorFinding, DetectorRun, EvidenceObligation


CACHE_SCHEMA_VERSION = 1
DEFAULT_MAX_CACHE_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 4 * 1024 * 1024
_CACHE_FILE = re.compile(r"^[0-9a-f]{64}\.json$")


def _engine_fingerprint() -> str | None:
    """Hash the scanner engine source once per cache instance.

    Detector result reuse must be invalidated by implementation changes, even
    when a detector's manually maintained version string was not bumped. The
    conservative package-wide digest also covers local helper modules and
    normalization code that detector-specific module hashing would miss.
    """
    root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    try:
        files = sorted(root.rglob("*.py"))
        if not files:
            return None
        for path in files:
            if "__pycache__" in path.parts or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(hashlib.sha256(content).digest())
    except (OSError, UnicodeError, ValueError):
        return None
    return digest.hexdigest()


def _valid_blob_oid(data: bytes, oid: str) -> bool:
    algo = {40: hashlib.sha1, 64: hashlib.sha256}.get(len(oid))
    if algo is None or re.fullmatch(r"[0-9a-f]+", oid) is None:
        return False
    return algo(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest() == oid


def _finding_from_dict(row):
    if not isinstance(row, dict):
        raise ValueError("invalid cached detector finding")
    item = dict(row)
    obligations = item.get("evidence_obligations", [])
    if not isinstance(obligations, list):
        raise ValueError("invalid cached evidence obligations")
    item["evidence_obligations"] = tuple(EvidenceObligation(**value) for value in obligations)
    return DetectorFinding(**item)


class PerFileDetectorResultCache:
    def __init__(self, directory: Path, max_bytes: int = DEFAULT_MAX_CACHE_BYTES):
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.stats = {"hits": 0, "misses": 0, "bypassed": 0, "invalid": 0,
                      "writes": 0, "write_skipped": 0, "read_errors": 0,
                      "hit_paths": []}
        self._engine_sha256 = _engine_fingerprint()
        self.directory.mkdir(parents=True, exist_ok=True)
        # Count existing cache-owned files once. Re-scanning the directory on
        # every file write would turn a cold fill into quadratic filesystem work.
        self._cache_bytes = 0
        try:
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    if not _CACHE_FILE.fullmatch(entry.name):
                        continue
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISREG(metadata.st_mode):
                        self._cache_bytes += metadata.st_size
        except OSError:
            # A best-effort size estimate may skip writes, never detector work.
            self._cache_bytes = self.max_bytes

    def identity(self, detector, context, unit):
        if (getattr(detector, "incremental_cache_policy", None) != "git_blob_single_file_v1"
                or getattr(detector, "ast_scope", None) != "per_file"
                or unit.language not in ("c", "cpp") or unit.parse_status != "complete"):
            return None
        if not isinstance(self._engine_sha256, str):
            self.stats["bypassed"] += 1
            return None
        declared = getattr(detector, "incremental_cache_facts", None)
        if (not isinstance(declared, tuple) or set(declared) != set(detector.required_facts)
                or not declared or "ast" not in declared):
            return None
        blob_map = context.shared_facts.get("source_blob_oid")
        oid = blob_map.get(unit.path) if isinstance(blob_map, dict) else None
        data = unit.text.encode("utf-8")
        if not isinstance(oid, str) or not _valid_blob_oid(data, oid):
            return None
        parser = parser_fingerprint(unit.language)
        if parser is None:
            return None
        inputs = {}
        for name in declared:
            facts = context.shared_facts.get(name)
            if not isinstance(facts, dict) or unit.path not in facts:
                return None
            inputs[name] = facts[unit.path]
        try:
            facts_digest = hashlib.sha256(json.dumps(
                inputs, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")).hexdigest()
        except (TypeError, ValueError, UnicodeError):
            return None
        identity = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "policy": detector.incremental_cache_policy,
            "detector_id": detector.detector_id,
            "detector_version": detector.version,
            "cache_contract_version": getattr(detector, "incremental_cache_version", None),
            "repository": context.request.repository,
            "profile_id": context.request.profile_id,
            "path": unit.path,
            "language": unit.language,
            "blob_oid": oid,
            "source_sha256": unit.sha256,
            "parser_fingerprint": parser,
            "engine_sha256": self._engine_sha256,
            "fact_inputs_sha256": facts_digest,
        }
        if not identity["cache_contract_version"]:
            return None
        key = hashlib.sha256(json.dumps(
            identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        return key, identity

    def load(self, detector, context, unit):
        bound = self.identity(detector, context, unit)
        if bound is None:
            self.stats["bypassed"] += 1
            return None
        key, identity = bound
        path = self.directory / (key + ".json")
        try:
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                self.stats["misses"] += 1
                return None
            if metadata.st_size > MAX_ENTRY_BYTES:
                self.stats["invalid"] += 1
                self.stats["misses"] += 1
                return None
            envelope = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError("invalid cache envelope")
            payload = envelope.get("payload")
            encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                 separators=(",", ":")).encode("utf-8")
            if (envelope.get("schema_version") != CACHE_SCHEMA_VERSION
                    or envelope.get("identity") != identity
                    or envelope.get("payload_sha256") != hashlib.sha256(encoded).hexdigest()
                    or not isinstance(payload, dict)
                    or payload.get("status") != "completed"
                    or payload.get("analyzed_files") != [unit.path]):
                raise ValueError("cache entry binding or schema mismatch")
            raw_findings = payload.get("findings", [])
            limitations = payload.get("limitations", [])
            if not isinstance(raw_findings, list) or not isinstance(limitations, list) or not all(
                    isinstance(value, str) for value in limitations):
                raise ValueError("invalid cached run contents")
            findings = tuple(_finding_from_dict(row) for row in raw_findings)
            if any(row.file != unit.path for row in findings):
                raise ValueError("cached finding is outside its source unit")
            run = DetectorRun(
                detector.detector_id, detector.version, "completed",
                analyzed_files=(unit.path,), findings=findings,
                limitations=tuple(payload.get("limitations", ())),
                file_outcomes=((unit.path, "complete"),),
            )
        except FileNotFoundError:
            self.stats["misses"] += 1
            return None
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.stats["invalid"] += 1
            self.stats["misses"] += 1
            self.stats["read_errors"] += 1
            try:
                if not path.is_symlink():
                    path.unlink(missing_ok=True)
            except OSError:
                pass
            return None
        self.stats["hits"] += 1
        if unit.path not in self.stats["hit_paths"]:
            self.stats["hit_paths"].append(unit.path)
        return run

    def store(self, detector, context, unit, run):
        bound = self.identity(detector, context, unit)
        if (bound is None or not isinstance(run, DetectorRun)
                or run.detector_id != detector.detector_id
                or run.version != detector.version or run.status != "completed"
                or run.analyzed_files != (unit.path,)
                or any(item.file != unit.path for item in run.findings)):
            self.stats["bypassed"] += 1
            return False
        key, identity = bound
        payload = {
            "status": run.status,
            "analyzed_files": [unit.path],
            "limitations": list(run.limitations),
            "findings": [asdict(item) for item in run.findings],
        }
        payload_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                   separators=(",", ":")).encode("utf-8")
        encoded = json.dumps({
            "schema_version": CACHE_SCHEMA_VERSION,
            "identity": identity,
            "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "payload": payload,
        }, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_ENTRY_BYTES:
            self.stats["write_skipped"] += 1
            return False
        try:
            destination = self.directory / (key + ".json")
            previous_size = 0
            try:
                metadata = destination.stat(follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode):
                    previous_size = metadata.st_size
            except FileNotFoundError:
                pass
            if self._cache_bytes - previous_size + len(encoded) > self.max_bytes:
                self.stats["write_skipped"] += 1
                return False
            fd, temporary_name = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=self.directory)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                    # This is disposable cache data, not scan evidence. Atomic
                    # replace plus envelope validation is sufficient: a crash
                    # may lose the entry, in which case the next run reparses.
                os.replace(temporary, destination)
                self._cache_bytes = self._cache_bytes - previous_size + len(encoded)
                self.stats["writes"] += 1
                return True
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
        except OSError:
            self.stats["write_skipped"] += 1
            return False
