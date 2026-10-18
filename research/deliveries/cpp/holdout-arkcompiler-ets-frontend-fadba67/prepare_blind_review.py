"""Rebuild the post-freeze, output-blind applicability packet.

This script parses only the pinned source file to choose function excerpts. It
does not import or invoke the C-line detector or its analysis/model modules.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = HERE / "symbol_reference_index.cpp"
MANIFEST = HERE / "blind_manifest.json"
PACKET = HERE / "blind_packet.md"
LABELS = HERE / "reviewer_labels.csv"
EXPECTED_SHA256 = "b9809fd39fe3f3b058e19008f51968b3d6f5ba56a0ed3203d4f08e7104f36847"
SAMPLE_COUNT = 20

sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.syntax import parse_functions  # noqa: E402


def main() -> None:
    data = SOURCE.read_bytes()
    source_sha256 = hashlib.sha256(data).hexdigest()
    if source_sha256 != EXPECTED_SHA256:
        raise SystemExit(f"pinned source SHA-256 mismatch: {source_sha256}")
    tree, functions = parse_functions(data)
    if tree.root_node.has_error:
        raise SystemExit("pinned translation unit no longer parses completely")
    if len(functions) < SAMPLE_COUNT:
        raise SystemExit("insufficient function definitions for deterministic frame")

    # Evenly spaced interior positions in declaration order; endpoints are
    # excluded. This is a source-frame applicability set, not a recall set.
    indexes = [((i + 1) * len(functions)) // (SAMPLE_COUNT + 1) for i in range(SAMPLE_COUNT)]
    if len(set(indexes)) != SAMPLE_COUNT:
        raise SystemExit("sampling formula produced duplicate function indexes")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest["source"]["sha256"] != EXPECTED_SHA256:
        raise SystemExit("manifest/source digest mismatch")
    samples = []
    excerpts = [
        "# Blind applicability holdout: official ETS Frontend\n\n"
        "This packet contains pinned source excerpts only. It contains no C-line detector output, "
        "developer labels, or product-impact conclusions. Label each sample independently. "
        "For each, record whether the exact Ark Runtime TypeSafety model is in scope and choose "
        "`candidate`, `partial`, `blocked`, `safe`, or `unknown`; cite evidence lines and a root cause. "
        "Use `unknown` when the excerpt and pinned source do not support a decision. Do not infer "
        "runtime behavior or product impact from source text.\n\n"
        "This is a clustered applicability/false-match frame from one production translation unit, "
        "not a semantic recall set; do not derive component-wide precision or recall.\n\n"
    ]
    first = next((function for function in functions
                  if function.qualified_name.endswith("::NormalizePathForExportFilter")), None)
    if first is None:
        raise SystemExit("original F001 symbol no longer resolves in pinned source")
    first_excerpt = first.text(first.node)
    first_start, first_end = first.node.start_point[0] + 1, first.node.end_point[0] + 1
    excerpts.extend((f"## F001\n\nSymbol: `{first.qualified_name}`. Source-relative lines: "
                     f"{first_start}–{first_end}.\n\n```cpp\n{first_excerpt}\n```\n\n",))
    for serial, function_index in enumerate(indexes, start=2):
        function = functions[function_index]
        sample_id = f"F{serial:03d}"
        excerpt = function.text(function.node)
        start_line, end_line = function.node.start_point[0] + 1, function.node.end_point[0] + 1
        samples.append({
            "sample_id": sample_id,
            "function_index_zero_based": function_index,
            "symbol": function.qualified_name,
            "source_lines": [start_line, end_line],
            "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
        })
        excerpts.extend((
            f"## {sample_id}\n\n"
            f"Symbol: `{function.qualified_name}`. Source-relative lines: {start_line}–{end_line}.\n\n"
            "```cpp\n" + excerpt + "\n```\n\n"
        ,))

    manifest["schema"] = "c-line-same-name-holdout-v2"
    selection = manifest["selection"]
    selection["source_lines"] = [first_start, first_end]
    selection["matcher_version_at_selection"] = "0.3.1"
    selection["additional_frame_matcher_version"] = "0.3.2"
    selection["additional_frame_rule"] = (
        "from the same pinned production translation unit, select 20 function definitions at evenly spaced "
        "interior declaration-order indexes using floor((i+1)*N/21), i=0..19; no detector output consulted"
    )
    selection["frame_kind"] = "clustered_applicability_false_match_only"
    selection["translation_unit_function_count"] = len(functions)
    selection["additional_samples"] = samples
    selection["sample_count_total"] = 1 + len(samples)
    manifest["review"] = {
        "sample_count": 1 + len(samples),
        "reviewed": 0,
        "unknown": None,
        "root_cause_results": None,
        "labels_present": False,
    }
    PACKET.write_text("".join(excerpts), encoding="utf-8", newline="\n")
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    with LABELS.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("sample_id", "model_scope", "evidence_label", "root_cause",
                         "unknown_reason", "evidence_lines", "reviewer_notes"))
        writer.writerow(("F001", "", "", "", "", "", ""))
        for sample in samples:
            writer.writerow((sample["sample_id"], "", "", "", "", "", ""))
    print(f"samples={len(samples) + 1}; functions={len(functions)}; parse=complete; detector_invoked=false")


if __name__ == "__main__":
    main()
