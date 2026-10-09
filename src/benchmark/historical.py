import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence

from src.core.scanner import scan_directory
from src.parser.ast import parse_source


@dataclass(frozen=True)
class HistoricalSample:
    schema_version: int
    sample_id: str
    title: str
    repository: str
    repo_url: str
    vulnerable_commit: str
    fixed_commit: str
    weakness: str
    affected_files: List[str]
    affected_symbols: List[str]
    root_cause: str
    source_refs: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    notes: str = ""
    label_status: str = "historical_candidate"
    root_cause_group: str = ""
    evidence_level: str = ""
    runtime_replay_status: str = "not_run"


@dataclass
class RevisionScan:
    commit: str
    candidate_count: int
    candidates: List[Dict[str, Any]]
    ast_function_count: int
    ast_call_count: int
    ast_variable_count: int
    affected_symbols_present: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HistoricalBenchmarkResult:
    sample: HistoricalSample
    repo_dir: str
    repository_head: str
    vulnerable_commit_exists: bool
    fixed_commit_exists: bool
    direct_parent_match: bool
    changed_files: List[str]
    affected_files_changed: List[str]
    fix_commit_message: str
    vulnerable: RevisionScan
    fixed: RevisionScan
    text_candidate_overlap_in_vulnerable: bool
    text_candidate_overlap_in_fixed: bool
    elapsed_seconds: float
    replay_status: str = "metadata_and_static_replay_verified"
    runtime_validation: str = "not_run"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample": asdict(self.sample),
            "repo_dir": self.repo_dir,
            "repository_head": self.repository_head,
            "vulnerable_commit_exists": self.vulnerable_commit_exists,
            "fixed_commit_exists": self.fixed_commit_exists,
            "direct_parent_match": self.direct_parent_match,
            "changed_files": self.changed_files,
            "affected_files_changed": self.affected_files_changed,
            "fix_commit_message": self.fix_commit_message,
            "vulnerable": self.vulnerable.to_dict(),
            "fixed": self.fixed.to_dict(),
            "text_candidate_overlap_in_vulnerable": self.text_candidate_overlap_in_vulnerable,
            "text_candidate_overlap_in_fixed": self.text_candidate_overlap_in_fixed,
            "elapsed_seconds": self.elapsed_seconds,
            "replay_status": self.replay_status,
            "runtime_validation": self.runtime_validation,
            "interpretation": (
                "Historical ground truth only. Static overlap measures whether the current "
                "candidate generator touches the published affected file or symbol region; "
                "it does not prove exploitability, safety, precision, or a new vulnerability."
            ),
        }


_REQUIRED_FIELDS = {
    "schema_version",
    "sample_id",
    "title",
    "repository",
    "repo_url",
    "vulnerable_commit",
    "fixed_commit",
    "weakness",
    "affected_files",
    "affected_symbols",
    "root_cause",
}


def load_sample(path: Path) -> HistoricalSample:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = sorted(_REQUIRED_FIELDS - set(data))
    if missing:
        raise ValueError(f"historical sample missing fields: {', '.join(missing)}")
    if data["schema_version"] != 1:
        raise ValueError(
            f"unsupported historical sample schema_version: {data['schema_version']}"
        )
    # These fields are also used as on-disk paths in replay/experiment scripts.
    # Validate before any Git read or temporary source materialization.
    sample_id = data["sample_id"]
    if not isinstance(sample_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", sample_id):
        raise ValueError("historical sample_id must be a safe filename token")
    affected_files = data["affected_files"]
    if not isinstance(affected_files, list) or not affected_files:
        raise ValueError("historical sample affected_files must be a non-empty list")
    for filename in affected_files:
        if (
            not isinstance(filename, str) or not filename or
            chr(92) in filename or ":" in filename or
            PurePosixPath(filename).is_absolute() or
            ".." in PurePosixPath(filename).parts or
            PurePosixPath(filename).as_posix() == "."
        ):
            raise ValueError(f"historical affected file must be repository-relative: {filename}")

    return HistoricalSample(
        schema_version=int(data["schema_version"]),
        sample_id=str(data["sample_id"]),
        title=str(data["title"]),
        repository=str(data["repository"]),
        repo_url=str(data["repo_url"]),
        vulnerable_commit=str(data["vulnerable_commit"]),
        fixed_commit=str(data["fixed_commit"]),
        weakness=str(data["weakness"]),
        affected_files=[str(item) for item in data["affected_files"]],
        affected_symbols=[str(item) for item in data["affected_symbols"]],
        root_cause=str(data["root_cause"]),
        source_refs=[str(item) for item in data.get("source_refs", [])],
        cve=data.get("cve"),
        notes=str(data.get("notes", "")),
        label_status=str(data.get("label_status", "historical_candidate")),
        root_cause_group=str(data.get("root_cause_group", "")),
        evidence_level=str(data.get("evidence_level", "")),
        runtime_replay_status=str(data.get("runtime_replay_status", "not_run")),
    )


def validate_sample_label(sample: HistoricalSample) -> List[str]:
    """Return warnings for missing/weak label fields; never raises.

    A historical sample may lack a public CVE, so cve is not required. This
    only surfaces labeling gaps so a future curator can fill them in.
    """
    warnings: List[str] = []
    if not sample.label_status.strip():
        warnings.append("label_status is empty")
    if not sample.root_cause_group.strip():
        warnings.append("root_cause_group is empty")
    if not sample.evidence_level.strip():
        warnings.append("evidence_level is empty")
    if not sample.source_refs:
        warnings.append("source_refs is empty")
    return warnings


def _git(
    repo_dir: Path,
    args: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess:
    try:
        process = subprocess.run(
            ["git", "-c", "remote.origin.promisor=false", "-C", str(repo_dir), *args],
            text=True, capture_output=True, check=False, timeout=20,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""},
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Local historical Git read timed out") from error
    if check and process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip() or "unknown git error"
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return process


def _commit_exists(repo_dir: Path, commit: str) -> bool:
    return (
        _git(repo_dir, ["cat-file", "-e", f"{commit}^{{commit}}"], check=False).returncode
        == 0
    )


def _show_file(repo_dir: Path, commit: str, relative_path: str) -> str:
    return _git(repo_dir, ["show", f"{commit}:{relative_path}"]).stdout


def _language_for_path(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    if suffix == ".c":
        return "c"
    if suffix in {".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
        return "cpp"
    return None


def _scan_revision(
    repo_dir: Path,
    commit: str,
    affected_files: Sequence[str],
    affected_symbols: Sequence[str],
) -> RevisionScan:
    with tempfile.TemporaryDirectory(prefix="oh-historical-") as directory:
        root = Path(directory)
        ast_function_count = 0
        ast_call_count = 0
        ast_variable_count = 0
        symbols_present = set()

        for relative_path in affected_files:
            code = _show_file(repo_dir, commit, relative_path)
            output_path = root / relative_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(code, encoding="utf-8")

            language = _language_for_path(relative_path)
            if language is not None:
                index = parse_source(code, language=language)
                ast_function_count += len(index.functions)
                ast_call_count += len(index.calls)
                ast_variable_count += len(index.variables)
                function_names = {item.name for item in index.functions}
                for symbol in affected_symbols:
                    if symbol in function_names or symbol in code:
                        symbols_present.add(symbol)

        scan_result = scan_directory(root)
        candidates: List[Dict[str, Any]] = []
        for finding in scan_result.findings:
            finding_path = Path(finding.file_path).resolve()
            try:
                relative = finding_path.relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = finding_path.name
            candidates.append(
                {
                    "file": relative,
                    "line": finding.line,
                    "function": finding.function,
                    "rule_id": finding.rule_id,
                    "evidence": finding.evidence,
                    "status": finding.status,
                }
            )

        return RevisionScan(
            commit=commit,
            candidate_count=len(candidates),
            candidates=candidates,
            ast_function_count=ast_function_count,
            ast_call_count=ast_call_count,
            ast_variable_count=ast_variable_count,
            affected_symbols_present=sorted(symbols_present),
        )


def _candidate_overlap(revision: RevisionScan, sample: HistoricalSample) -> bool:
    affected_files = set(sample.affected_files)
    affected_symbols = set(sample.affected_symbols)
    for candidate in revision.candidates:
        if candidate["file"] not in affected_files:
            continue
        if not affected_symbols:
            return True
        if candidate.get("function") in affected_symbols:
            return True
        evidence = str(candidate.get("evidence", ""))
        if any(symbol in evidence for symbol in affected_symbols):
            return True
    return False


def run_historical_benchmark(
    sample_path: Path,
    repo_dir: Path,
) -> HistoricalBenchmarkResult:
    started = time.perf_counter()
    sample = load_sample(sample_path)
    repo_dir = repo_dir.resolve()
    worktree_check = _git(
        repo_dir,
        ["rev-parse", "--is-inside-work-tree"],
        check=False,
    )
    if worktree_check.returncode != 0 or worktree_check.stdout.strip() != "true":
        raise ValueError(f"repo_dir is not a Git working tree: {repo_dir}")

    vulnerable_exists = _commit_exists(repo_dir, sample.vulnerable_commit)
    fixed_exists = _commit_exists(repo_dir, sample.fixed_commit)
    if not vulnerable_exists:
        raise ValueError(
            f"vulnerable commit is not available locally: {sample.vulnerable_commit}"
        )
    if not fixed_exists:
        raise ValueError(f"fixed commit is not available locally: {sample.fixed_commit}")

    repository_head = _git(repo_dir, ["rev-parse", "HEAD"]).stdout.strip()
    parent = _git(repo_dir, ["rev-parse", f"{sample.fixed_commit}^"]).stdout.strip()
    direct_parent_match = parent == sample.vulnerable_commit

    changed_files = [
        line.strip()
        for line in _git(
            repo_dir,
            ["diff", "--name-only", sample.vulnerable_commit, sample.fixed_commit],
        ).stdout.splitlines()
        if line.strip()
    ]
    changed_set = set(changed_files)
    affected_files_changed = [
        path for path in sample.affected_files if path in changed_set
    ]
    fix_commit_message = _git(
        repo_dir,
        ["show", "-s", "--format=%B", sample.fixed_commit],
    ).stdout.strip()

    vulnerable = _scan_revision(
        repo_dir,
        sample.vulnerable_commit,
        sample.affected_files,
        sample.affected_symbols,
    )
    fixed = _scan_revision(
        repo_dir,
        sample.fixed_commit,
        sample.affected_files,
        sample.affected_symbols,
    )

    return HistoricalBenchmarkResult(
        sample=sample,
        repo_dir=str(repo_dir),
        repository_head=repository_head,
        vulnerable_commit_exists=vulnerable_exists,
        fixed_commit_exists=fixed_exists,
        direct_parent_match=direct_parent_match,
        changed_files=changed_files,
        affected_files_changed=affected_files_changed,
        fix_commit_message=fix_commit_message,
        vulnerable=vulnerable,
        fixed=fixed,
        text_candidate_overlap_in_vulnerable=_candidate_overlap(vulnerable, sample),
        text_candidate_overlap_in_fixed=_candidate_overlap(fixed, sample),
        elapsed_seconds=time.perf_counter() - started,
    )


def render_markdown(result: HistoricalBenchmarkResult) -> str:
    sample = result.sample
    lines = [
        "# Historical Vulnerability Benchmark Replay",
        "",
        "> Published historical ground truth only. This report measures tool behavior "
        "on a known fix pair; it does not claim a new vulnerability.",
        "",
        "## Sample",
        "",
        f"- ID: {sample.sample_id}",
        f"- Title: {sample.title}",
        f"- Repository: {sample.repository}",
        f"- Weakness: {sample.weakness}",
        f"- Vulnerable commit: {sample.vulnerable_commit}",
        f"- Fixed commit: {sample.fixed_commit}",
        f"- Direct parent match: {result.direct_parent_match}",
        f"- Affected files changed: {', '.join(result.affected_files_changed) or '(none)'}",
        f"- Runtime validation: {result.runtime_validation}",
        "",
        "## Current Text Candidate Generator",
        "",
        f"- Vulnerable revision candidates: {result.vulnerable.candidate_count}",
        f"- Fixed revision candidates: {result.fixed.candidate_count}",
        (
            "- Vulnerable affected-region overlap: "
            f"{result.text_candidate_overlap_in_vulnerable}"
        ),
        f"- Fixed affected-region overlap: {result.text_candidate_overlap_in_fixed}",
        "",
        "These overlap values are descriptive. A miss can expose a tool blind spot; "
        "a hit is not automatically a true-positive security verdict.",
        "",
        "## AST Index Sanity",
        "",
        (
            "- Vulnerable functions/calls/variables: "
            f"{result.vulnerable.ast_function_count} / "
            f"{result.vulnerable.ast_call_count} / "
            f"{result.vulnerable.ast_variable_count}"
        ),
        (
            "- Fixed functions/calls/variables: "
            f"{result.fixed.ast_function_count} / "
            f"{result.fixed.ast_call_count} / "
            f"{result.fixed.ast_variable_count}"
        ),
        (
            "- Vulnerable affected symbols present: "
            f"{', '.join(result.vulnerable.affected_symbols_present) or '(none)'}"
        ),
        (
            "- Fixed affected symbols present: "
            f"{', '.join(result.fixed.affected_symbols_present) or '(none)'}"
        ),
        "",
        "## Fix Commit Message",
        "",
        result.fix_commit_message,
        "",
        "## Boundaries",
        "",
        "- No precision is computed from this positive-only sample.",
        "- No runtime exploitability or system reachability is inferred.",
        "- A historical replay is tooling evidence, not a new vulnerability discovery.",
        f"- Replay elapsed seconds: {result.elapsed_seconds:.6f}",
        "",
    ]
    return "\n".join(lines)


def write_reports(
    result: HistoricalBenchmarkResult,
    json_output: Path,
    markdown_output: Path,
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(result), encoding="utf-8")
