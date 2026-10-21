"""Durable, identity-bound checkpoints for completed detector shards.

Only normalized ``completed`` detector runs are stored. Raw AST/parser objects
and failed, blocked, or partial detector executions are never resumed.
"""

from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import pickle
import tempfile

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult


SCHEMA_VERSION = 1
MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def checkpoint_key(context, detector, engine_sha256):
    """Bind a shard to every source/fact/config input and its implementation."""
    try:
        facts_digest = hashlib.sha256(pickle.dumps(context.shared_facts, protocol=5)).hexdigest()
    except Exception:
        return None
    try:
        module_path = Path(__import__(detector.__class__.__module__, fromlist=["__file__"]).__file__)
        implementation_digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
    except Exception:
        return None
    record = {
        "schema": SCHEMA_VERSION,
        "engine_sha256": engine_sha256,
        "repository": context.request.repository,
        "commit": context.request.commit,
        "snapshot_sha256": context.request.snapshot_sha256,
        "profile_id": context.request.profile_id,
        "provenance": context.request.provenance,
        "facts_sha256": facts_digest,
        "detector_id": detector.detector_id,
        "detector_version": detector.version,
        "detector_implementation_sha256": implementation_digest,
        "ast_scope": getattr(detector, "ast_scope", "per_file"),
        "required_facts": list(detector.required_facts),
        "supported_languages": list(detector.supported_languages),
        "units": [
            {"path": u.path, "language": u.language, "sha256": u.sha256,
             "parse_status": u.parse_status, "parse_issues": list(u.parse_issues)}
            for u in context.units
        ],
    }
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


def _diagnostic_from_dict(value):
    allowed = {item.name for item in fields(ToolDiagnostic)}
    return ToolDiagnostic(**{key: item for key, item in value.items() if key in allowed})


def _result_from_dict(value):
    if value.get("status") != "completed":
        return None
    allowed = {item.name for item in fields(ToolRunResult)}
    data = {key: item for key, item in value.items() if key in allowed}
    data["diagnostics"] = [_diagnostic_from_dict(item) for item in value.get("diagnostics", ())]
    return ToolRunResult(**data)


class DetectorCheckpointStore:
    def __init__(self, directory, engine_sha256):
        self.directory = Path(directory)
        self.engine_sha256 = engine_sha256
        self._keys = {}
        self.stats = {"hits": 0, "misses": 0, "writes": 0, "invalid": 0,
                      "read_errors": 0, "write_errors": 0, "oversize": 0}

    def _path(self, key):
        return self.directory / (key + ".json")

    def _key(self, context, detector):
        ident = (detector.detector_id, detector.version)
        if ident not in self._keys:
            self._keys[ident] = checkpoint_key(context, detector, self.engine_sha256)
        return self._keys[ident]

    @staticmethod
    def _matches_current_scope(result, sidecar, context, detector, applicable):
        paths = [unit.path for unit in applicable]
        units = {unit.path: unit for unit in applicable}
        if (result.status != "completed" or result.tool != detector.detector_id
                or result.tool_version != detector.version
                or result.commit != context.request.commit
                or result.target_id != context.request.target_id
                or [row.get("file") for row in result.parsing] != paths
                or any(row.get("status") != units[row["file"]].parse_status
                       or row.get("issues") != list(units[row["file"]].parse_issues)
                       or row.get("analysis_status") not in
                       ("analyzed", "partial", "failed", "not_analyzed")
                       for row in result.parsing)):
            return False
        hashes = {u.path: u.sha256 for u in applicable}
        if (sidecar.get("source_sha256") != hashes
                or sidecar.get("applicable_files") != len(paths)):
            return False
        analyzed = {row["file"] for row in result.parsing
                    if row["analysis_status"] == "analyzed"}
        partial = {row["file"] for row in result.parsing
                   if row["analysis_status"] == "partial"}
        not_analyzed = {row["file"] for row in result.parsing
                        if row["analysis_status"] == "not_analyzed"}
        if (set(sidecar.get("analyzed_files", ())) != analyzed
                or set(sidecar.get("partially_inspected_files", ())) != partial
                or set(sidecar.get("not_analyzed_files", ())) != not_analyzed
                or set(sidecar.get("inspected_files", ())) != analyzed | partial
                or sidecar.get("coverage_counts") != {
                    "complete": len(analyzed), "partial": len(partial),
                    "not_analyzed": len(not_analyzed),
                    "failed": sum(row["analysis_status"] == "failed" for row in result.parsing),
                }):
            return False
        expected_status = (
            "partial" if len(analyzed) != len(paths) or partial else "complete"
        )
        if sidecar.get("status") != expected_status:
            return False
        findings = {item.diagnostic_id: item for item in result.diagnostics}
        obligations = sidecar.get("evidence_obligations")
        if not isinstance(obligations, list) or {item.get("diagnostic_id") for item in obligations} != set(findings):
            return False
        for item in obligations:
            finding = findings[item["diagnostic_id"]]
            source = item.get("source_binding", {})
            if (item.get("file") != finding.file
                    or item.get("source_sha256") != hashes.get(finding.file)
                    or source.get("repository") != context.request.repository
                    or source.get("commit") != context.request.commit
                    or source.get("snapshot_sha256") != context.request.snapshot_sha256
                    or source.get("detector_id") != detector.detector_id
                    or source.get("detector_version") != detector.version
                    or source.get("source_sha256") != hashes.get(finding.file)):
                return False
        return all(item.file in units and item.source_sha256 == units[item.file].sha256
                   for item in result.diagnostics)

    def load(self, context, detector, applicable):
        key = self._key(context, detector)
        if key is None:
            self.stats["misses"] += 1
            return None
        path = self._path(key)
        if not path.exists():
            self.stats["misses"] += 1
            return None
        try:
            if path.stat().st_size > MAX_CHECKPOINT_BYTES:
                self.stats["oversize"] += 1
                self.stats["misses"] += 1
                return None
            raw = json.loads(path.read_text(encoding="utf-8"))
            payload = raw["payload"]
            if (raw.get("schema_version") != SCHEMA_VERSION
                    or raw.get("key") != key
                    or hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
                    != raw.get("payload_sha256")):
                raise ValueError("checkpoint integrity mismatch")
            result = _result_from_dict(payload["result"])
            sidecar = payload["coverage"]
            if (result is None or not isinstance(sidecar, dict)
                    or not self._matches_current_scope(
                        result, sidecar, context, detector, applicable)):
                raise ValueError("checkpoint does not match current detector scope")
            result.elapsed_seconds = 0.0
            self.stats["hits"] += 1
            return result, sidecar
        except Exception:
            self.stats["invalid"] += 1
            self.stats["misses"] += 1
            return None

    def store(self, context, detector, result, sidecar):
        if result.status != "completed":
            return False
        key = self._key(context, detector)
        if key is None:
            return False
        payload = {"result": result.to_dict(), "coverage": sidecar}
        body = {"schema_version": SCHEMA_VERSION, "key": key,
                "payload_sha256": hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest(),
                "payload": payload}
        try:
            encoded = (_canonical(body) + "\n").encode("utf-8")
            if len(encoded) > MAX_CHECKPOINT_BYTES:
                self.stats["oversize"] += 1
                return False
            self.directory.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=key + ".", suffix=".tmp", dir=self.directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write(encoded.decode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp_name, self._path(key))
                try:
                    dir_fd = os.open(self.directory, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            self.stats["writes"] += 1
            return True
        except Exception:
            self.stats["write_errors"] += 1
            return False
