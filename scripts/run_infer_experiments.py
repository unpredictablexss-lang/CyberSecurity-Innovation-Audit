"""Run Infer/Pulse in an isolated prepared worktree and bind raw evidence.

This is a research orchestrator, not a production Detector dependency. The
caller must prepare a disposable checkout outside this repository. Commands use
argument arrays without a shell and the scanner core never invokes this script.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import List, Optional, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_capture_command(
    infer: Path,
    results_dir: Path,
    compile_commands: Path,
) -> List[str]:
    return [
        str(infer), "capture",
        "--results-dir", str(results_dir),
        "--compilation-database", str(compile_commands),
    ]


def build_build_command(
    infer: Path,
    results_dir: Path,
    build_command: Sequence[str],
) -> List[str]:
    if not build_command:
        raise ValueError("build_command must not be empty")
    return [str(infer), "run", "--results-dir", str(results_dir), "--", *build_command]


def build_analyze_command(infer: Path, results_dir: Path) -> List[str]:
    return [str(infer), "analyze", "--results-dir", str(results_dir)]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _find_report(results_dir: Path) -> Optional[Path]:
    for relative in ("infer-out/report.json", "report.json", "infer-report.json"):
        path = results_dir / relative
        if path.is_file():
            return path
    return None


def _run(command: Sequence[str], *, cwd: Path, timeout: int) -> dict:
    started = time.monotonic()
    try:
        process = subprocess.run(
            list(command),
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        return {
            "command": list(command),
            "exit_code": process.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "stdout": process.stdout.decode("utf-8", "replace"),
            "stderr": process.stderr.decode("utf-8", "replace"),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": list(command),
            "exit_code": None,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "stdout": (error.stdout or b"").decode("utf-8", "replace"),
            "stderr": (error.stderr or b"").decode("utf-8", "replace"),
            "timeout": True,
        }


def _safe_output_dir(path: Path) -> Path:
    resolved = path.resolve()
    output_root = (PROJECT_ROOT / "outputs" / "reports").resolve()
    if not resolved.is_relative_to(output_root):
        raise ValueError("output directory must remain under outputs/reports")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--infer", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--scope-files", type=int, required=True)
    parser.add_argument("--scope-loc", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--compile-commands", type=Path)
    source.add_argument(
        "--build-command",
        nargs=argparse.REMAINDER,
        help="Command after --build-command runs inside the isolated work root.",
    )
    args = parser.parse_args()

    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", args.commit):
        raise ValueError("commit must be a full lowercase Git SHA")
    if args.scope_files < 1 or args.scope_loc < 0:
        raise ValueError("invalid analysis scope")
    infer = args.infer.resolve()
    if not infer.is_file():
        raise ValueError("Infer executable does not exist")
    work_root = args.work_root.resolve()
    if work_root.is_relative_to(PROJECT_ROOT) or not work_root.is_dir():
        raise ValueError("work-root must be an existing isolated directory outside the project")
    output_dir = _safe_output_dir(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results_dir = (output_dir / "infer-results").resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    steps = []
    version = _run([str(infer), "--version"], cwd=work_root, timeout=30)
    steps.append(version)
    if version["exit_code"] != 0:
        status = "failed"
    elif args.compile_commands is not None:
        compile_commands = args.compile_commands.resolve()
        if not compile_commands.is_file():
            raise ValueError("compile_commands JSON does not exist")
        capture = _run(
            build_capture_command(infer, results_dir, compile_commands),
            cwd=work_root,
            timeout=args.timeout,
        )
        steps.append(capture)
        analyze = (
            _run(build_analyze_command(infer, results_dir), cwd=work_root, timeout=args.timeout)
            if capture["exit_code"] == 0 else None
        )
        if analyze is not None:
            steps.append(analyze)
        status = "completed" if analyze and analyze["exit_code"] == 0 else "failed"
    else:
        build = _run(
            build_build_command(infer, results_dir, args.build_command or ()),
            cwd=work_root,
            timeout=args.timeout,
        )
        steps.append(build)
        status = "completed" if build["exit_code"] == 0 else "failed"

    report = _find_report(results_dir)
    execution = {
        "schema_version": 1,
        "experiment_kind": "infer_research_run",
        "target_id": args.target_id,
        "commit": args.commit,
        "scope_files": args.scope_files,
        "scope_loc": args.scope_loc,
        "status": status,
        "work_root": str(work_root),
        "infer_executable": str(infer),
        "results_dir": str(results_dir),
        "steps": steps,
        "report": None if report is None else {
            "path": str(report),
            "sha256": _sha256(report),
        },
        "limitations": [
            "Research-only Infer run; no production OHScanner dependency.",
            "A clean report is not proof of safety when capture/analysis coverage is incomplete.",
        ],
    }
    (output_dir / "execution.json").write_text(
        json.dumps(execution, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0 if status == "completed" and report is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
