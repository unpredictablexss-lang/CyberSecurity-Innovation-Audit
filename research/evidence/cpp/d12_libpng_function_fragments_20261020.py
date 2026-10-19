"""Replay exact-source libpng function fragments without upgrading TU coverage.

The caller supplies local source snapshots already bound by the evidence ledger.
Only target function byte ranges are parsed as isolated fragments. A complete
fragment syntax result is not a complete translation-unit or semantic result.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source


EXPECTED = {
    "33416": {
        "vulnerable": {
            "pngset.c": "9bd59a79669db37b2ecc481439481eb5f49bf77bee0de4b1aba649915609b3d0",
            "png.c": "0d8e45e9039cf04088764a09dcda7b24695f199288a44e11dba54ebfaca1c730",
            "pngread.c": "feee8bdd4c553cc4f01bb288a868d4b83e1ce0f75014a96163a49eb32119cba6",
            "pngrtran.c": "4df05c2e5db00911817d7f125c862524205895f34a65106e016d351f7e6edb53",
        },
        "fixed": {
            "pngset.c": "d3a203e40b6a6000a7cb78a61e0fd9664b0c39a65d82260efedb0f0184a8bc19",
            "png.c": "29a37cedb5be5597aafa3cab62a223c0accbd6016edfff97386471a6e118100c",
            "pngread.c": "2a2c02673c7dcd6853f3efe8cc16c893df3f7bdffe7b53abde835e7c6e4c6fc3",
            "pngrtran.c": "6b724ff0047cced71884176296aac10a6fc1d2592477034bbd622222ded3373f",
        },
    },
    "46675": {
        "vulnerable": {"pngrutil.c": "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e"},
        "fixed": {"pngrutil.c": "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e"},
    },
}

TARGETS = {
    "33416": {
        "pngset.c": {"png_set_PLTE", "png_set_tRNS"},
        "png.c": {"png_free_data"},
        "pngrtran.c": {"png_do_expand_palette"},
    },
    "46675": {
        "pngrutil.c": {
            "png_inflate_claim", "png_inflate", "png_decompress_chunk", "png_inflate_read",
            "png_handle_iCCP", "png_handle_zTXt", "png_read_IDAT_data",
        }
    },
}


def fragment(source: str, first_line: int, last_line: int) -> str:
    """Keep exact selected lines and blank other lines to preserve line numbers."""
    lines = source.splitlines(keepends=True)
    return "".join(line if first_line <= i <= last_line else "\n" for i, line in enumerate(lines, 1))


def replay(case: str, variant: str, root: Path) -> dict:
    detector = CppResourceLifetimeDetector()
    rows = []
    for filename, expected_sha in EXPECTED[case][variant].items():
        path = root / filename
        raw = path.read_bytes()
        actual_sha = sha256(raw).hexdigest()
        if actual_sha != expected_sha:
            raise ValueError(f"source hash mismatch: {path} {actual_sha} != {expected_sha}")
        source = raw.decode("utf-8")
        whole_index = parse_source(source, language="c")
        selected_names = TARGETS[case].get(filename, set())
        whole_functions = [item for item in whole_index.functions if item.name in selected_names]
        found = {item.name for item in whole_functions}
        missing = sorted(selected_names - found)
        for item in whole_functions:
            sliced = fragment(source, item.start_line, item.end_line)
            slice_index = parse_source(sliced, language="c")
            fragment_hash = sha256(sliced.encode("utf-8")).hexdigest()
            unit = SourceUnit(
                path=f"{case}/{variant}/{filename}#{item.name}",
                language="c",
                text=sliced,
                sha256=fragment_hash,
                parse_status=slice_index.parse_status,
                parse_issues=tuple(json.dumps(issue, sort_keys=True) for issue in slice_index.parse_issues),
            )
            request = ScanRequest(
                request_id=f"d12:{case}:{variant}:{filename}:{item.name}",
                repository="pnggroup/libpng",
                commit=("c3e304954a9cfd154bc0dfbfea2b01cd61d6546d" if variant == "vulnerable" else
                        "d5515b5b8be3901aac04e5bd8bd5c89f287bcd33" if case == "33416" else
                        "aa77ef38c17ab2fc1b41bec09fb973c6a386641d"),
                snapshot_sha256=fragment_hash,
                target_id="current-component:pnggroup/libpng",
                profile_id="exact-function-fragment-light-ast",
                provenance="fixture",
            )
            context = ScanContext(request=request, units=(unit,))
            started = time.perf_counter()
            run = detector.detect(context, (unit,))
            elapsed = time.perf_counter() - started
            rows.append({
                "path": filename,
                "source_sha256": actual_sha,
                "whole_translation_unit_parse_status": whole_index.parse_status,
                "whole_translation_unit_issue_count": len(whole_index.parse_issues),
                "fragment_sha256": fragment_hash,
                "fragment_parse_status": unit.parse_status,
                "fragment_issue_count": len(unit.parse_issues),
                "fragment_parse_issues": list(unit.parse_issues),
                "function": item.name,
                "start_line": item.start_line,
                "end_line": item.end_line,
                "missing_functions": missing,
                "detector": detector.detector_id,
                "detector_version": detector.version,
                "run_status": run.status,
                "finding_count": len(run.findings),
                "findings": [asdict(finding) for finding in run.findings],
                "elapsed_seconds": elapsed,
                "interpretation": "fragment-only syntax experiment; not a whole-file coverage result or semantic proof",
            })
    return {"case": f"CVE-2026-{case}", "variant": variant, "source_root": str(root), "files": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--33416-vulnerable", type=Path, required=True)
    parser.add_argument("--33416-fixed", type=Path, required=True)
    parser.add_argument("--46675-vulnerable", type=Path, required=True)
    parser.add_argument("--46675-fixed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {
        "schema_version": 1,
        "experiment": "exact_source_function_fragment_resource_lifetime_replay",
        "baseline": "983afb846ceaa34daf690c39e4918703c4ac99a7",
        "detector": "ohscanner.cpp.resource_lifetime",
        "detector_version": CppResourceLifetimeDetector.version,
        "source_identities": {
            "CVE-2026-33416": {
                "vulnerable_commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
                "vulnerable_tree": "e01f5780f93eaa6d74cca003bb39b427c8f1e910",
                "fixed_commit": "d5515b5b8be3901aac04e5bd8bd5c89f287bcd33",
                "fixed_tree": "a28bb962645843af84063c77f574f6d88da79f76",
            },
            "CVE-2026-46675": {
                "vulnerable_commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
                "vulnerable_blob": "a4eda54c8cb3d36cf1651dba159067b65030e3aa",
                "vulnerable_sha256": EXPECTED["46675"]["vulnerable"]["pngrutil.c"],
                "fixed_commit": "aa77ef38c17ab2fc1b41bec09fb973c6a386641d",
                "fixed_blob": "482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a",
                "fixed_sha256": EXPECTED["46675"]["fixed"]["pngrutil.c"],
                "tree_identity": "not available in prior verified evidence",
            },
        },
        "runs": [
            replay("33416", "vulnerable", args.__dict__["33416_vulnerable"]),
            replay("33416", "fixed", args.__dict__["33416_fixed"]),
            replay("46675", "vulnerable", args.__dict__["46675_vulnerable"]),
            replay("46675", "fixed", args.__dict__["46675_fixed"]),
        ],
        "limitations": [
            "Function fragments are extracted from hash-pinned source bytes; their complete syntax does not repair the parent translation unit's partial parse status.",
            "Fragment boundaries do not supply declarations, macros, type identity, control-flow feasibility, alias proofs, or product call paths.",
            "No new detector rule is justified unless the same root-cause candidate is demonstrated on vulnerable fragments and quiet on source-bound fixed plus safe/unrelated controls.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "runs": [
        {"case": run["case"], "variant": run["variant"], "files": [
            {"path": f["path"], "whole_parse": f["whole_translation_unit_parse_status"],
             "fragment_parse": f["fragment_parse_status"], "findings": f["finding_count"],
             "elapsed_seconds": f["elapsed_seconds"]} for f in run["files"]]
        } for run in result["runs"]]}, indent=2))


if __name__ == "__main__":
    main()
