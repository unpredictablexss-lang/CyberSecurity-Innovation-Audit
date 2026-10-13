"""Collect a deterministic Clang/CodeQL build-context sidecar.

The script records compilation-unit and macro facts for fair offline tool
experiments. It does not run a compiler, scanner or network operation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
from typing import Any, Dict, Iterable, List

from src.ohscanner.analysis import AnalysisRunContext


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entries(payload: Any) -> List[dict]:
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict) and isinstance(payload.get("commands"), list):
        entries = payload["commands"]
    else:
        raise ValueError("compile_commands must be a list or an object with 'commands'")
    result = []
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"compile command #{index} must be an object")
        if not isinstance(item.get("file"), str) or not item["file"].strip():
            raise ValueError(f"compile command #{index} needs a file")
        result.append(item)
    return result


def _arguments(item: dict) -> List[str]:
    values = item.get("arguments")
    if isinstance(values, list) and all(isinstance(value, str) for value in values):
        return values
    command = item.get("command")
    if isinstance(command, str) and command.strip():
        return shlex.split(command)
    raise ValueError("compile command needs 'arguments' or 'command'")


def _macro_profile(entries: Iterable[dict]) -> str:
    values = set()
    for item in entries:
        args = _arguments(item)
        for index, value in enumerate(args):
            if value in {"-D", "-U", "-include"} and index + 1 < len(args):
                values.add(f"{value} {args[index + 1]}")
            elif value.startswith(("-D", "-U", "-include")) and len(value) > 2:
                values.add(value)
    return hashlib.sha256("\n".join(sorted(values)).encode("utf-8")).hexdigest()


def collect_build_context(
    *,
    compile_commands: Path,
    source_root: Path,
    analysis_mode: str,
    revision_role: str,
    analysis_unit: str,
    build_profile: str,
    include_status: str,
) -> Dict[str, Any]:
    compile_commands = compile_commands.resolve()
    source_root = source_root.resolve()
    if not compile_commands.is_file():
        raise ValueError("compile_commands file does not exist")
    if not source_root.is_dir():
        raise ValueError("source_root must be an existing directory")
    payload = json.loads(compile_commands.read_text(encoding="utf-8"))
    entries = _entries(payload)
    analyzed_files = []
    for item in entries:
        path = Path(item["file"])
        if not path.is_absolute():
            path = source_root / path
        path = path.resolve()
        if not path.is_relative_to(source_root):
            raise ValueError("compile command file must remain under source_root")
        analyzed_files.append(path.relative_to(source_root).as_posix())
    context = AnalysisRunContext(
        analysis_mode=analysis_mode,
        revision_role=revision_role,
        analysis_unit=analysis_unit,
        build_profile=build_profile,
        include_status=include_status,
        analyzed_files=tuple(sorted(set(analyzed_files))),
        compile_commands_sha256=_sha256(compile_commands),
        macro_profile_sha256=_macro_profile(entries),
        source_snapshot_sha256=None,
        limitations=() if include_status != "not_applicable" else (
            "Build context explicitly marked not_applicable.",
        ),
    )
    return {
        "schema_version": 1,
        "experiment_kind": "build_context_sidecar",
        "compile_commands": str(compile_commands),
        "tu_count": len(entries),
        "context": context.to_dict(),
        "interpretation": (
            "Compilation inputs are recorded for fair tool comparison; this does "
            "not prove complete preprocessing, macro expansion or semantic analysis."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-commands", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--analysis-mode", choices=("snapshot", "revision_range", "cross_version"), default="snapshot")
    parser.add_argument("--revision-role", choices=("baseline", "endpoint", "target"), default="target")
    parser.add_argument("--analysis-unit", choices=("translation_unit", "file", "component_slice", "header_only", "unknown"), default="translation_unit")
    parser.add_argument("--build-profile", required=True)
    parser.add_argument("--include-status", choices=("complete", "partial", "failed", "not_run", "not_applicable"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output_root = (PROJECT_ROOT / "outputs" / "reports").resolve()
    if not output.is_relative_to(output_root):
        raise ValueError("output must remain under outputs/reports")
    output.parent.mkdir(parents=True, exist_ok=True)
    result = collect_build_context(
        compile_commands=args.compile_commands,
        source_root=args.source_root,
        analysis_mode=args.analysis_mode,
        revision_role=args.revision_role,
        analysis_unit=args.analysis_unit,
        build_profile=args.build_profile,
        include_status=args.include_status,
    )
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
