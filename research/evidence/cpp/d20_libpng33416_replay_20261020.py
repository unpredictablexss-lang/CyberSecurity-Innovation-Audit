"""Replay the D12 hash-bound CVE-2026-33416 slices under resource rule 0.4.2."""
from __future__ import annotations

import json
from pathlib import Path

from d12_libpng_function_fragments_20261020 import replay
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector


BASE = Path(r"D:\openHarmonyScanner\tmp\libpng-runtime-cve-2026-33416-20261019")
OUT = Path(__file__).with_name("d20_libpng33416_replay_20261020.json")


def main() -> None:
    runs = [replay("33416", variant, BASE / variant) for variant in ("vulnerable", "fixed")]
    result = {
        "schema_version": 1,
        "experiment": "D20_hash_bound_libpng_33416_function_slice_replay",
        "baseline": "b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e",
        "detector": CppResourceLifetimeDetector.detector_id,
        "detector_version": CppResourceLifetimeDetector.version,
        "source_identities": {
            "repository": "pnggroup/libpng",
            "vulnerable_commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
            "vulnerable_tree": "e01f5780f93eaa6d74cca003bb39b427c8f1e910",
            "fixed_commit": "d5515b5b8be3901aac04e5bd8bd5c89f287bcd33",
            "fixed_tree": "a28bb962645843af84063c77f574f6d88da79f76",
        },
        "runs": runs,
        "assessment": {
            "rule_change": "none",
            "case_status": "PARTIAL/BLOCK",
            "reason": "All target function slices and parent translation units are partial; no source-visible cross-file alias/release/use root is exposed to the current local lexical model.",
            "limitations": [
                "Fragment slices retain original file positions but omit surrounding declarations, preprocessor context, and type identity.",
                "Adding hand-selected declarations would create a synthetic parse context and cannot establish full source coverage or field alias semantics.",
                "Current detector does not join png_info/png_struct field aliases or release state across functions/files.",
                "Zero findings on either partial variant is inconclusive; the fixed result is not a fixed PASS.",
            ],
        },
    }
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUT), "detector_version": result["detector_version"], "runs": [
        {"variant": run["variant"], "files": [
            {"path": file["path"], "source_sha256": file["source_sha256"],
             "function": file["function"], "lines": [file["start_line"], file["end_line"]],
             "tu_parse": file["whole_translation_unit_parse_status"],
             "fragment_parse": file["fragment_parse_status"], "findings": file["finding_count"]}
            for file in run["files"]]
         } for run in runs]}, indent=2))


if __name__ == "__main__":
    main()
