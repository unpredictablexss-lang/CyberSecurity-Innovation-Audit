"""Versioned cache for source-only C/C++ light AST summaries.

Only verified, real Git blob inputs are cacheable. This deliberately does not
cache cross-file facts, compiler/preprocessor results, detector results, or
archive members.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from importlib import metadata
from functools import lru_cache

from src.parser.ast import AstIndex, CallSite, FunctionDef, VariableDecl


CACHE_SCHEMA_VERSION = 1
AST_PARSER_SPEC_VERSION = "light-ast-v1"
NORMALIZATION_SPEC_VERSION = "member-pointer-and-empty-linkage-v1"
DEFAULT_MAX_CACHE_BYTES = 512 * 1024 * 1024
_CACHE_FILE = re.compile(r"^[0-9a-f]{64}\.json$")
_TEMP_FILE = re.compile(r"^\.[0-9a-f]{64}\.[A-Za-z0-9_-]+\.tmp$")


@lru_cache(maxsize=2)
def parser_fingerprint(language: str) -> dict | None:
    if language not in ("c", "cpp"):
        return None
    package = "tree-sitter-c" if language == "c" else "tree-sitter-cpp"
    try:
        return {
            "tree-sitter": metadata.version("tree-sitter"),
            package: metadata.version(package),
            "parse_profile": "light-ast",
            "ast_parser_spec": AST_PARSER_SPEC_VERSION,
            "normalization_spec": NORMALIZATION_SPEC_VERSION,
        }
    except metadata.PackageNotFoundError:
        return None


def _git_blob_oid(data: bytes, oid: str) -> bool:
    try:
        algo = {40: hashlib.sha1, 64: hashlib.sha256}[len(oid)]
    except KeyError:
        return False
    digest = algo(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    return digest == oid


def cache_identity(oid: str, language: str, data: bytes) -> dict | None:
    versions = parser_fingerprint(language)
    if versions is None or not _git_blob_oid(data, oid):
        return None
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "blob_oid": oid,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "language": language,
        "versions": versions,
    }


def _ast_from_dict(value: dict) -> AstIndex:
    if not isinstance(value, dict) or value.get("language") not in ("c", "cpp"):
        raise ValueError("invalid cached AST")
    if value.get("parse_status") not in ("complete", "partial"):
        raise ValueError("invalid cached parse status")
    issues = value.get("parse_issues")
    functions, calls, variables = value.get("functions"), value.get("calls"), value.get("variables")
    if not all(isinstance(items, list) for items in (issues, functions, calls, variables)):
        raise ValueError("invalid cached AST collections")
    return AstIndex(
        language=value["language"], parse_status=value["parse_status"],
        parse_issues=issues,
        functions=[FunctionDef(**item) for item in functions],
        calls=[CallSite(**item) for item in calls],
        variables=[VariableDecl(**item) for item in variables],
    )


class AstSummaryCache:
    """Best-effort disk cache; all read/write faults degrade to parse normally."""

    def __init__(self, directory: Path, max_bytes: int = DEFAULT_MAX_CACHE_BYTES):
        if not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("AST cache max_bytes must be a non-negative integer")
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self.stats = {
            "hits": 0, "misses": 0, "bypassed": 0, "invalid": 0,
            "writes": 0, "evictions": 0, "oversize_not_stored": 0,
            "cleared_entries": 0, "cleared_bytes": 0, "cleanup_errors": 0,
        }
        self._size_bytes = None
        self._enforce_limit()

    def _managed_files(self, include_temporary=False):
        try:
            entries = self.directory.iterdir()
        except OSError:
            return
        for path in entries:
            if path.is_symlink():
                continue
            if _CACHE_FILE.fullmatch(path.name) or (
                include_temporary and _TEMP_FILE.fullmatch(path.name)
            ):
                try:
                    if path.is_file():
                        yield path
                except OSError:
                    continue

    def _measure_size(self):
        total = 0
        try:
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    if not _CACHE_FILE.fullmatch(entry.name):
                        continue
                    try:
                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        self.stats["cleanup_errors"] += 1
        except OSError:
            return 0
        return total

    def _enforce_limit(self):
        if not self.directory.exists():
            self._size_bytes = 0
            return
        files = []
        total = 0
        try:
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    if not _CACHE_FILE.fullmatch(entry.name):
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        stat = entry.stat(follow_symlinks=False)
                        total += stat.st_size
                        files.append((stat.st_mtime_ns, entry.name,
                                      self.directory / entry.name, stat.st_size))
                    except OSError:
                        self.stats["cleanup_errors"] += 1
        except OSError:
            self.stats["cleanup_errors"] += 1
            self._size_bytes = 0
            return
        if total > self.max_bytes:
            for _, _, path, size in sorted(files):
                if total <= self.max_bytes:
                    break
                try:
                    path.unlink()
                    total -= size
                    self.stats["evictions"] += 1
                except OSError:
                    self.stats["cleanup_errors"] += 1
        self._size_bytes = total

    def clear(self):
        """Remove only cache-owned flat entries; leave unrelated files untouched."""
        removed = entries = 0
        for path in self._managed_files(include_temporary=True):
            try:
                size = path.stat().st_size
                path.unlink()
                removed += size
                entries += 1
            except OSError:
                self.stats["cleanup_errors"] += 1
        self._size_bytes = 0
        self.stats["cleared_entries"] += entries
        self.stats["cleared_bytes"] += removed
        return {"entries": entries, "bytes": removed}

    def report_stats(self):
        # The directory was measured/enforced at construction, and in-process
        # writes/evictions/clears keep this counter current. Avoid a second
        # full directory stat walk just to build the report.
        cache_bytes = self._size_bytes
        if cache_bytes is None:
            cache_bytes = self._measure_size()
        lookups = self.stats["hits"] + self.stats["misses"] + self.stats["invalid"]
        return {
            **self.stats,
            "cache_bytes": cache_bytes,
            "max_bytes": self.max_bytes,
            "hit_rate": self.stats["hits"] / lookups if lookups else None,
        }

    def _path(self, identity: dict) -> Path:
        key = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        return self.directory / (hashlib.sha256(key).hexdigest() + ".json")

    def load(self, oid: str, language: str, data: bytes) -> AstIndex | None:
        identity = cache_identity(oid, language, data)
        if identity is None:
            self.stats["bypassed"] += 1
            return None
        path = self._path(identity)
        if path.is_symlink():
            self.stats["invalid"] += 1
            return None
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self.stats["misses"] += 1
            return None
        except OSError:
            self.stats["invalid"] += 1
            return None
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise ValueError("invalid cache entry")
            if entry.get("identity") != identity:
                raise ValueError("cache identity mismatch")
            encoded_ast = json.dumps(entry["ast"], ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")
            if entry.get("ast_sha256") != hashlib.sha256(encoded_ast).hexdigest():
                raise ValueError("cached AST checksum mismatch")
            ast = _ast_from_dict(entry["ast"])
            if ast.language != language:
                raise ValueError("cached AST language mismatch")
        except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
            self.stats["invalid"] += 1
            return None
        self.stats["hits"] += 1
        return ast

    def bypass(self) -> None:
        self.stats["bypassed"] += 1

    def store(self, oid: str, language: str, data: bytes, ast: AstIndex) -> None:
        identity = cache_identity(oid, language, data)
        if identity is None or ast.language != language or ast.parse_status not in ("complete", "partial"):
            return
        path = self._path(identity)
        ast_data = ast.to_dict()
        encoded_ast = json.dumps(ast_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        entry = {"identity": identity, "ast": ast_data,
                 "ast_sha256": hashlib.sha256(encoded_ast).hexdigest()}
        temporary = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.directory,
                                             prefix=f".{path.stem}.", suffix=".tmp",
                                             delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(entry, stream, ensure_ascii=False, separators=(",", ":"))
                stream.write("\n")
            old_size = 0
            if path.exists() and not path.is_symlink():
                try:
                    old_size = path.stat().st_size
                except OSError:
                    pass
            temporary.replace(path)
            self.stats["writes"] += 1
            new_size = path.stat().st_size
            if self._size_bytes is None:
                self._size_bytes = self._measure_size()
            else:
                self._size_bytes += new_size - old_size
            if new_size > self.max_bytes:
                path.unlink()
                self._size_bytes -= new_size
                self.stats["oversize_not_stored"] += 1
            elif self._size_bytes > self.max_bytes:
                self._enforce_limit()
        except OSError:
            self.stats["cleanup_errors"] += 1
            try:
                temporary.unlink(missing_ok=True)
            except (OSError, AttributeError):
                pass
