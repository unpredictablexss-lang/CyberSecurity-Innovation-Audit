"""Resolve saved diagnostic locations against immutable Git source snapshots.

Never checkout a revision or infer dataflow. A complete syntax tree and exactly
one enclosing function are required for symbol mapping. Partial parsing keeps
the benchmark cell unknown, including an empty diagnostic list.
"""

import hashlib
import os
import subprocess
from dataclasses import replace
from pathlib import Path

from src.parser.ast import parse_source


def map_snapshot_candidates(repo: Path, sample, commit: str, files: tuple, candidates: list):
    def git(*args):
        try:
            return subprocess.run(["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
                                  capture_output=True, check=False, timeout=20,
                                  env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""})
        except subprocess.TimeoutExpired as error:
            raise ValueError("Local pinned-source Git read timed out") from error

    remote = git("remote", "get-url", "origin")
    origin = remote.stdout.decode("utf-8", errors="replace").strip().rstrip("/").lower()
    if origin.endswith(".git"):
        origin = origin[:-4]
    identity = sample.repository.lower()
    if remote.returncode or not (origin.endswith("/" + identity) or origin.endswith(":" + identity)):
        raise ValueError("source_repo origin does not match the sample repository")
    resolved = git("rev-parse", "--verify", f"{commit}^{{commit}}")
    if resolved.returncode or resolved.stdout.decode().strip() != commit:
        raise ValueError("source_repo does not contain the exact pinned commit")

    indices = {}
    snapshots = []
    incomplete = False
    for file in files:
        source = git("show", f"{commit}:{file}")
        snapshot = {"repository": sample.repository, "commit": commit, "file": file,
                    "sha256": hashlib.sha256(source.stdout).hexdigest() if not source.returncode else None}
        suffix = Path(file).suffix.lower()
        language = "c" if suffix == ".c" else "cpp" if suffix in {".h", ".hpp", ".hh", ".cc", ".cpp", ".cxx"} else None
        try:
            if source.returncode or language is None:
                raise ValueError("Pinned source unavailable or unsupported language")
            index = parse_source(source.stdout.decode("utf-8"), language)
            indices[file] = index
            snapshot.update(status=index.parse_status, issues=index.parse_issues)
            incomplete = incomplete or index.parse_status != "complete"
        except (UnicodeError, RuntimeError, ValueError) as error:
            snapshot.update(status="failed", reason=str(error))
            incomplete = True
        snapshots.append(snapshot)

    mapped = []
    for candidate in candidates:
        index = indices.get(candidate.file)
        if candidate.symbol is None and candidate.line is not None and index and index.parse_status == "complete":
            functions = [function for function in index.functions
                         if function.start_line <= candidate.line <= function.end_line
                         and function.name != "<unknown>"]
            if len(functions) == 1:
                candidate = replace(candidate, symbol=functions[0].name)
        mapped.append(candidate)
    return mapped, tuple(snapshots), incomplete
