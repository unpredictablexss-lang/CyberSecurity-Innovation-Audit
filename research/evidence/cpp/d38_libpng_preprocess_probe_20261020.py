"""Summarize exact-source libpng preprocessing and parser outcomes for D38."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector


REPO = Path(__file__).resolve().parents[3]
T61 = REPO / "research/evidence/cpp/t61_libpng_independent_acceptance_20261020.json"
TARGETS = {
    "png.c": {"png_free_data"},
    "pngset.c": {"png_set_PLTE"},
    "pngrtran.c": {"png_do_expand_palette"},
    "pngrutil.c": {"png_decompress_chunk", "png_handle_iCCP", "png_read_IDAT_data"},
}
VARIANTS = {
    "33416-vuln": ("33416", "vulnerable"),
    "33416-fixed": ("33416", "fixed"),
    "46675-vuln": ("46675", "vulnerable"),
    "46675-fixed": ("46675", "fixed"),
}
PROBED_FILES = {"33416": {"png.c", "pngset.c", "pngread.c", "pngrtran.c"},
                "46675": {"pngrutil.c"}}
BUILD_FLAGS = [
    "-DHAVE_CONFIG_H", "-I<snapshot-root>", "-g", "-O1", "-fsanitize=address",
    "-fno-omit-frame-pointer", "-E",
]


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def source_line_map(lines: list[str], line_number: int) -> tuple[str, int] | None:
    active: tuple[int, int, str] | None = None
    for generated, line in enumerate(lines[:line_number], start=1):
        match = re.match(r'^#\s+(\d+)\s+"([^"]+)"', line)
        if match:
            active = (generated, int(match.group(1)), match.group(2))
    if active is None:
        return None
    marker_line, source_line, source_path = active
    return source_path, source_line + line_number - marker_line - 1


def build_report(probe_root: Path) -> dict:
    identities = json.loads(T61.read_text(encoding="utf-8"))["sources"]
    detector = CppResourceLifetimeDetector()
    runs = []
    for variant, (case, side) in VARIANTS.items():
        source_info = identities[case][side]
        source_root = probe_root / variant
        for filename, expected in source_info["files"].items():
            if filename not in PROBED_FILES[case]:
                continue
            source = source_root / filename
            if not source.is_file():
                raise ValueError(f"pinned source file missing: {variant}/{filename}")
            data = source.read_bytes()
            actual_source_sha = hashlib.sha256(data).hexdigest()
            actual_blob = git_blob_sha(data)
            if actual_source_sha != expected["sha256"] or actual_blob != expected["blob"]:
                raise ValueError(f"pinned source identity mismatch: {variant}/{filename}")
            preprocessed = probe_root / "preprocessed" / f"{variant}-{Path(filename).stem}.i"
            text = preprocessed.read_text(encoding="utf-8")
            index = parse_source(text, language="c")
            unit = SourceUnit(
                path=f"{variant}/{Path(filename).stem}.c", language="c", text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                parse_status=index.parse_status,
                parse_issues=tuple(str(issue) for issue in index.parse_issues),
            )
            result = detector.detect(None, (unit,))
            if index.parse_status != "partial" or result.status != "blocked" or result.findings:
                raise ValueError(f"unexpected parser/detector result: {variant}/{filename}")
            lines = text.splitlines()
            function_locations = []
            for function in index.functions:
                if function.name not in TARGETS.get(filename, set()):
                    continue
                mapped = source_line_map(lines, function.start_line)
                if mapped is None or Path(mapped[0]).name != filename or mapped[1] < 1:
                    raise ValueError(f"line marker did not map to pinned source: {variant}/{function.name}")
                function_locations.append({
                    "function": function.name,
                    "preprocessed_line": function.start_line,
                    "mapped_location": (
                        {"file": mapped[0], "line": mapped[1]} if mapped else None
                    ),
                })
            marker_count = sum(
                1 for line in lines if re.match(r'^#\s+\d+\s+"[^"]+\.c"', line)
            )
            if marker_count == 0:
                raise ValueError(f"preprocessed input has no source line markers: {variant}/{filename}")
            runs.append({
                "case": f"CVE-2026-{case}", "variant": side, "file": filename,
                "source_commit": source_info["commit"], "source_tree": source_info["tree"],
                "source_blob": expected["blob"], "source_sha256": actual_source_sha,
                "source_bytes": len(data),
                "preprocessed_sha256": hashlib.sha256(preprocessed.read_bytes()).hexdigest(),
                "preprocessed_bytes": preprocessed.stat().st_size,
                "line_marker_count": marker_count,
                "parse_status": index.parse_status, "parse_issue_count": len(index.parse_issues),
                "detector_status": result.status, "finding_count": len(result.findings),
                "findings": [
                    {"rule_id": finding.rule_id, "symbol": finding.symbol,
                     "file": finding.file, "line": finding.line}
                    for finding in result.findings
                ],
                "target_function_locations": function_locations,
            })
    if len(runs) != 10:
        raise ValueError(f"expected 10 source/preprocessor pairs, found {len(runs)}")
    cli_runs = []
    for variant in VARIANTS:
        cli_path = probe_root / "cli-output" / f"{variant}.json"
        cli = json.loads(cli_path.read_text(encoding="utf-8"))
        detector_runs = [
            run for run in cli.get("detector_runs", [])
            if run.get("tool") == "ohscanner.cpp.resource_lifetime"
        ]
        if len(detector_runs) != 1:
            raise ValueError(f"expected one production resource_lifetime run for {variant}")
        cli_runs.append({
            "variant": variant,
            "synthetic_input_commit": cli.get("commit"),
            "synthetic_input_tree": cli.get("git_tree"),
            "cli_artifact_sha256": hashlib.sha256(cli_path.read_bytes()).hexdigest(),
            "selected_source_files": cli.get("scope", {}).get("selected_source_files"),
            "parse_summary": cli.get("source_parsing", {}).get("parsing_status"),
            "detector_status": detector_runs[0].get("status"),
            "diagnostic_count": detector_runs[0].get("diagnostic_count"),
            "parse_limitations": cli.get("parse_limitations", []),
        })
        if (cli_runs[-1]["detector_status"] != "blocked"
                or cli_runs[-1]["diagnostic_count"] != 0):
            raise ValueError(f"unexpected production CLI result for {variant}")
    return {
        "schema_version": 1,
        "task": "D38 exact-pinned libpng preprocessor probe",
        "scanner_head": "efa09aaaa c01f81084034ea0994c310007ba1dbf".replace(" ", ""),
        "compiler": "gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1)",
        "build_configuration": {
            "makefile_values": {
                "CC": "gcc", "CPP": "gcc -E", "DEFS": "-DHAVE_CONFIG_H",
                "DEFAULT_INCLUDES": "-I.",
                "CFLAGS": "-g -O1 -fsanitize=address -fno-omit-frame-pointer",
            },
            "preprocessor_flags": BUILD_FLAGS,
            "configuration_method": "pinned commit archive; ./configure with CC=gcc and the recorded CFLAGS; make pnglibconf.h pngprefix.h",
        },
        "result": "ALL_PREPROCESSED_INPUTS_PARTIAL_NO_CANDIDATES",
        "runs": runs,
        "production_cli": cli_runs,
        "conclusion": (
            "Line markers map target function starts back to the pinned original files, but the current parser "
            "reports every preprocessed translation unit partial (174-401 issues) and the lifecycle detector "
            "returns blocked with zero findings. Preprocessed .i is not a valid completeness or detection fix."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.probe_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"D38 probe evidence written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
