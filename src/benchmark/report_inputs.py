"""Load saved runs for reporting; never execute scanners or infer verdicts.

A manifest binds normalized tool reports (or the own-text historical replay
report) to sample/revision. Symbol-less diagnostics stay unresolved rather than
being guessed into an affected region. Artifact paths are manifest-relative.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import List

from src.benchmark.historical import HistoricalSample
from src.benchmark.root_cause_matrix import NOT_APPLICABLE, SampleToolRun, ToolCandidate
from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult


DEFAULT_TOOLS = ["own_text", "own_ast", "semgrep", "semgrep_oh", "codeql",
                 "clang_sa", "cppcheck", "joern"]


def _relative_file(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("candidate file must be a string")
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ":" in value or ".." in path.parts:
        raise ValueError(f"candidate file must be repository-relative: {value}")
    return path.as_posix()


def _locations(diagnostics: list) -> list:
    if not isinstance(diagnostics, list):
        raise ValueError("candidates must be a list")
    candidates = []
    for item in diagnostics:
        if not isinstance(item, dict):
            raise ValueError("candidate must be a JSON object")
        line = item.get("line")
        if line is not None and (type(line) is not int or line < 1):
            raise ValueError("candidate line must be a positive integer")
        symbol = item.get("symbol", item.get("function"))
        if symbol is not None and (not isinstance(symbol, str) or not symbol.strip()):
            raise ValueError("candidate symbol must be a non-empty string or null")
        candidates.append(ToolCandidate(
            file=_relative_file(item.get("file", "")), symbol=symbol, line=line,
        ))
    return candidates


def load_report_runs(path: Path, samples: List[HistoricalSample]) -> List[SampleToolRun]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("benchmark input manifest requires schema_version 1")
    entries = data.get("runs")
    if not isinstance(entries, list):
        raise ValueError("benchmark input manifest runs must be a list")
    by_sample = {sample.sample_id: sample for sample in samples}
    if len(by_sample) != len(samples):
        raise ValueError("duplicate historical sample_id")
    runs = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("benchmark input run must be a JSON object")
        sample_id = entry.get("sample_id")
        if not isinstance(sample_id, str) or sample_id not in by_sample:
            raise ValueError(f"unknown sample_id: {sample_id}")
        sample = by_sample[sample_id]
        revision = entry.get("revision")
        if not isinstance(revision, str) or revision not in {"vulnerable", "fixed"}:
            raise ValueError(f"unsupported revision: {revision}")
        report_name = entry.get("report")
        if not isinstance(report_name, str) or not report_name.strip():
            raise ValueError("run requires a saved report path")
        report_path = (path.parent / report_name).resolve()
        raw = report_path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("saved report must be a JSON object")
        digest = hashlib.sha256(raw).hexdigest()
        expected_digest = entry.get("sha256")
        if expected_digest is not None and digest != expected_digest:
            raise ValueError(f"report sha256 mismatch: {report_name}")
        expected_commit = getattr(sample, f"{revision}_commit")
        reason = ""
        tool_version = "unknown"
        scope_files = scope_loc = None
        analyzed_files = ()
        run_status = "completed"
        limitations = ()
        report_format = entry.get("format", "normalized")
        if report_format == "historical":
            recorded = payload.get("sample", {})
            if not isinstance(recorded, dict):
                raise ValueError("historical report sample must be an object")
            for field in ("sample_id", "repository", "vulnerable_commit", "fixed_commit",
                          "affected_files", "affected_symbols"):
                if recorded.get(field) != getattr(sample, field):
                    raise ValueError(f"historical report sample mismatch: {field}")
            if payload.get("replay_status") != "metadata_and_static_replay_verified":
                raise ValueError("historical replay is not verified")
            revision_data = payload.get(revision, {})
            if not isinstance(revision_data, dict):
                raise ValueError("historical revision must be an object")
            if revision_data.get("commit") != expected_commit:
                raise ValueError("historical report commit mismatch")
            if "candidates" not in revision_data:
                raise ValueError("historical report requires saved candidates")
            candidates = _locations(revision_data["candidates"])
            if revision_data.get("candidate_count") != len(candidates):
                raise ValueError("historical candidate_count mismatch")
            tool = "own_text"
            analyzed_files = tuple(sample.affected_files)
            scope_files = len(analyzed_files)
            limitations = ("Historical text replay; syntax-based function context only.",)
            run_id = f"historical:{sample_id}:{revision}"
            if entry.get("not_applicable_reason") is not None:
                raise ValueError("completed historical replay cannot be not_applicable")
        elif report_format == "normalized":
            diagnostics = payload.get("diagnostics")
            if not isinstance(diagnostics, list):
                raise ValueError("normalized report diagnostics must be a list")
            if not all(isinstance(item, dict) for item in diagnostics):
                raise ValueError("normalized diagnostic must be an object")
            not_applicable_reason = entry.get("not_applicable_reason")
            if not_applicable_reason is not None and (
                not isinstance(not_applicable_reason, str) or not not_applicable_reason.strip()
            ):
                raise ValueError("not_applicable_reason must be non-empty")
            try:
                run = ToolRunResult(
                    **{key: payload[key] for key in (
                        "schema_version", "run_id", "tool", "tool_version", "target_id",
                        "commit", "scope_files", "scope_loc", "status", "elapsed_seconds")},
                    diagnostics=[ToolDiagnostic(**{key: value for key, value in item.items()
                                                  if key in ToolDiagnostic.__dataclass_fields__})
                                 for item in diagnostics],
                    peak_memory_mb=payload.get("peak_memory_mb"),
                    limitations=payload.get("limitations", []),
                )
            except (KeyError, TypeError) as error:
                raise ValueError(f"malformed normalized report: {report_name}") from error
            if run.target_id != sample_id:
                raise ValueError("normalized report target_id must equal sample_id")
            if run.commit != expected_commit:
                raise ValueError(f"normalized report commit mismatch: {sample_id}/{revision}")
            tool, run_id = run.tool, run.run_id
            tool_version, scope_files, scope_loc = run.tool_version, run.scope_files, run.scope_loc
            run_status = run.status
            if not isinstance(run.limitations, list) or not all(isinstance(item, str) for item in run.limitations):
                raise ValueError("normalized report limitations must be a string list")
            limitations = tuple(run.limitations)
            if run.status == "completed":
                if entry.get("not_applicable_reason") is not None:
                    raise ValueError("completed tool run cannot be not_applicable")
                if run.scope_files == 0:
                    raise ValueError("completed tool run requires a non-empty analysis scope")
                files = entry.get("analyzed_files")
                if not isinstance(files, list) or not files:
                    raise ValueError("completed normalized run requires analyzed_files")
                analyzed_files = tuple(_relative_file(file) for file in files)
                if len(set(analyzed_files)) != len(analyzed_files):
                    raise ValueError("duplicate analyzed_files")
                if len(analyzed_files) != run.scope_files:
                    raise ValueError("analyzed_files must match normalized scope_files")
                candidates = _locations(diagnostics)
                if any(candidate.file not in analyzed_files for candidate in candidates):
                    raise ValueError("candidate file is outside analyzed_files")
                if not set(sample.affected_files).issubset(analyzed_files):
                    candidates = None
                    reason = "Analysis scope does not cover all affected files."
            else:
                reason = entry.get("not_applicable_reason") or entry.get("reason")
                if not isinstance(reason, str) or not reason.strip():
                    raise ValueError("failed/blocked run requires an explicit reason")
                candidates = NOT_APPLICABLE if entry.get("not_applicable_reason") else None
        else:
            raise ValueError(f"unsupported benchmark report format: {report_format}")
        runs.append(SampleToolRun(
            sample_id=sample_id, revision=revision, tool=tool, commit=expected_commit,
            candidates=candidates, run_id=run_id, source_report=str(report_path),
            source_sha256=digest, reason=reason,
            tool_version=tool_version, scope_files=scope_files, scope_loc=scope_loc,
            analyzed_files=analyzed_files, run_status=run_status, limitations=limitations,
        ))
    return runs
