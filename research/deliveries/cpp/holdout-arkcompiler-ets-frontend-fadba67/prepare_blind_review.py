"""Rebuild the post-freeze, output-blind applicability packet.

This script parses only the pinned source file to choose function excerpts. It
does not import or invoke the C-line detector or its analysis/model modules.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = HERE / "symbol_reference_index.cpp"
MANIFEST = HERE / "blind_manifest.json"
FREEZE = HERE.parent / "ark-runtime-c-line-algorithm-freeze-20261018.json"
PACKET = HERE / "blind_packet.md"
LABELS = HERE / "reviewer_labels.csv"
CENSUS = HERE / "component_census.json"
EXPECTED_SHA256 = "b9809fd39fe3f3b058e19008f51968b3d6f5ba56a0ed3203d4f08e7104f36847"
SAMPLE_COUNT = 20
SOURCE_PREFIX = "ets2panda/lsp/src/"

sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.syntax import parse_functions  # noqa: E402


def freeze_mismatches(freeze: dict, manifest: dict, *, root: Path = ROOT) -> list[str]:
    """Return reasons the blind packet is no longer tied to its algorithm freeze."""
    expected_freeze = str(FREEZE.relative_to(ROOT)).replace("\\", "/")
    if manifest.get("algorithm_freeze") != expected_freeze:
        return ["holdout manifest does not reference the expected algorithm freeze"]
    freeze_sha256 = hashlib.sha256(FREEZE.read_bytes()).hexdigest()
    if manifest.get("algorithm_freeze_sha256") != freeze_sha256:
        return ["holdout manifest algorithm freeze SHA-256 is missing or stale"]
    if manifest.get("current_binding_version") != freeze.get("detector_version"):
        return ["holdout binding version differs from the frozen detector version"]
    frozen_files = {
        **freeze.get("implementation_sha256", {}),
        **freeze.get("implementation_support_sha256", {}),
    }
    if not frozen_files:
        return ["algorithm freeze has no implementation hash set"]
    drift = []
    for relative_path, expected in frozen_files.items():
        path = root / relative_path
        if not path.is_file():
            drift.append(f"missing:{relative_path}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected.lower():
            drift.append(f"sha256:{relative_path}")
    return drift


def packet_issues(manifest: dict, census: dict, label_rows: list[dict], packet: str,
                  *, require_blank_labels: bool = True) -> list[str]:
    """Validate sample coverage, source identity, excerpt bytes and blank labels."""
    issues = []
    samples = manifest["selection"].get("additional_samples", [])
    expected_ids = ["F001"] + [row["sample_id"] for row in samples]
    if len(expected_ids) != len(set(expected_ids)):
        issues.append("duplicate_sample_ids")
    label_ids = [row.get("sample_id", "") for row in label_rows]
    if label_ids != expected_ids:
        issues.append("label_csv_sample_ids_mismatch")
    if require_blank_labels and any(value for row in label_rows for key, value in row.items()
                                    if key != "sample_id"):
        issues.append("review_labels_are_not_blank")

    census_rows = {row["path"]: row for row in census["files"]}
    source_meta = manifest["source"]
    sampled = [{
        "sample_id": "F001",
        "source_path": source_meta["path"],
        "source_blob_oid": source_meta["blob_oid"],
        "source_sha256": source_meta["sha256"],
        "excerpt_sha256": manifest["selection"].get("first_excerpt_sha256"),
    }] + samples
    paths = [row["source_path"] for row in sampled]
    if len(paths) != len(set(paths)):
        issues.append("sample_translation_units_not_unique")
    if manifest["component_census"].get("sampled_translation_units") != len(set(paths)):
        issues.append("sampled_translation_unit_count_mismatch")
    for row in sampled:
        pinned = census_rows.get(row["source_path"])
        if pinned is None or pinned["parse_status"] != "complete":
            issues.append("sample_source_not_complete:" + row["sample_id"])
            continue
        if (pinned["blob_oid"], pinned["sha256"]) != (row["source_blob_oid"], row["source_sha256"]):
            issues.append("sample_source_pin_mismatch:" + row["sample_id"])

    sections = re.split(r"(?m)^## (F\d{3})\s*$", packet)
    rendered = {sections[i]: sections[i + 1] for i in range(1, len(sections) - 1, 2)}
    if set(rendered) != set(expected_ids):
        issues.append("packet_sample_headings_mismatch")
    for row in sampled:
        body = rendered.get(row["sample_id"], "")
        if "```cpp\n" not in body or "\n```" not in body:
            issues.append("packet_excerpt_missing:" + row["sample_id"])
            continue
        excerpt = body.split("```cpp\n", 1)[1].split("\n```", 1)[0]
        digest = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
        if digest != row.get("excerpt_sha256"):
            issues.append("packet_excerpt_hash_mismatch:" + row["sample_id"])
    return issues


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python prepare_blind_review.py <local-git-repository>")
    repo = Path(sys.argv[1]).resolve()
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    drift = freeze_mismatches(freeze, manifest)
    if drift:
        raise SystemExit("algorithm/manifest freeze mismatch; re-freeze before holdout generation: " + ",".join(drift))

    data = SOURCE.read_bytes()
    source_sha256 = hashlib.sha256(data).hexdigest()
    if source_sha256 != EXPECTED_SHA256:
        raise SystemExit(f"pinned source SHA-256 mismatch: {source_sha256}")
    tree, functions = parse_functions(data)
    if tree.root_node.has_error:
        raise SystemExit("pinned translation unit no longer parses completely")
    source_meta = manifest["source"]
    if source_meta["sha256"] != EXPECTED_SHA256:
        raise SystemExit("manifest/source digest mismatch")
    try:
        resolved_tree = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", f"{source_meta['commit']}^{{tree}}"],
            stderr=subprocess.PIPE, text=True,
        ).strip()
    except subprocess.CalledProcessError as error:
        raise SystemExit("cannot resolve the pinned holdout commit/tree") from error
    if resolved_tree != source_meta["tree"]:
        raise SystemExit("holdout repository does not resolve to the pinned tree")
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
    if hashlib.sha256(CENSUS.read_bytes()).hexdigest() != manifest["component_census"].get("census_sha256"):
        raise SystemExit("component census content hash differs from the manifest")
    if (census["provenance"]["commit"], census["provenance"]["tree"]) != (
            source_meta["commit"], source_meta["tree"]):
        raise SystemExit("component census does not match the pinned holdout commit/tree")
    eligible = [row for row in census["files"]
                if row["parse_status"] == "complete" and row["function_definitions"] > 0
                and row["path"] != source_meta["path"]]
    if len(eligible) < SAMPLE_COUNT:
        raise SystemExit("insufficient complete translation units for cross-file sample frame")
    file_indexes = [((i + 1) * len(eligible)) // (SAMPLE_COUNT + 1) for i in range(SAMPLE_COUNT)]
    if len(set(file_indexes)) != SAMPLE_COUNT:
        raise SystemExit("sampling formula produced duplicate translation-unit indexes")
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
    selection = manifest["selection"]
    selection["first_excerpt_sha256"] = hashlib.sha256(first_excerpt.encode("utf-8")).hexdigest()
    excerpts.extend((f"## F001\n\nSymbol: `{first.qualified_name}`. Source-relative lines: "
                     f"{first_start}–{first_end}.\n\n```cpp\n{first_excerpt}\n```\n\n",))
    sampled_paths = [source_meta["path"]]
    for serial, file_index in enumerate(file_indexes, start=2):
        source_row = eligible[file_index]
        try:
            source_data = subprocess.check_output(
                ["git", "-C", str(repo), "cat-file", "blob", source_row["blob_oid"]],
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as error:
            raise SystemExit("cannot read pinned source blob: " + source_row["path"]) from error
        if hashlib.sha256(source_data).hexdigest() != source_row["sha256"]:
            raise SystemExit("source census SHA-256 mismatch: " + source_row["path"])
        computed_oid = hashlib.sha1(b"blob " + str(len(source_data)).encode() + b"\0" + source_data).hexdigest()
        if computed_oid != source_row["blob_oid"]:
            raise SystemExit("source census Git blob mismatch: " + source_row["path"])
        source_tree, source_functions = parse_functions(source_data)
        if source_tree.root_node.has_error or len(source_functions) != source_row["function_definitions"]:
            raise SystemExit("source parse census mismatch: " + source_row["path"])
        function_index = len(source_functions) // 2
        function = source_functions[function_index]
        sample_id = f"F{serial:03d}"
        excerpt = function.text(function.node)
        start_line, end_line = function.node.start_point[0] + 1, function.node.end_point[0] + 1
        samples.append({
            "sample_id": sample_id,
            "source_path": source_row["path"],
            "source_blob_oid": source_row["blob_oid"],
            "source_sha256": source_row["sha256"],
            "function_index_zero_based": function_index,
            "symbol": function.qualified_name,
            "source_lines": [start_line, end_line],
            "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
        })
        sampled_paths.append(source_row["path"])
        excerpts.extend((
            f"## {sample_id}\n\n"
            f"Source: `{source_row['path']}`; symbol: `{function.qualified_name}`. "
            f"Source-relative lines: {start_line}–{end_line}.\n\n"
            "```cpp\n" + excerpt + "\n```\n\n"
        ,))

    manifest["schema"] = "c-line-same-name-holdout-v2"
    manifest["current_binding_version"] = freeze["detector_version"]
    selection["source_lines"] = [first_start, first_end]
    selection["matcher_version_at_selection"] = "0.3.1"
    selection["additional_frame_matcher_version"] = "0.3.2"
    selection["current_binding_version"] = freeze["detector_version"]
    selection["additional_frame_rule"] = (
        "from the pinned ets2panda/lsp/src subtree, select 20 complete source files at evenly spaced "
        "interior lexical-path indexes using floor((i+1)*N/21), i=0..19, excluding the F001 file; "
        "select the middle function definition in each file; no detector output consulted"
    )
    selection["frame_kind"] = "cross_file_clustered_applicability_false_match_only"
    selection["translation_unit_function_count"] = len(functions)
    selection["additional_frame_translation_unit_count"] = len(eligible)
    selection["additional_samples"] = samples
    selection["sample_count_total"] = 1 + len(samples)
    manifest["review"] = {
        "sample_count": 1 + len(samples),
        "reviewed": 0,
        "unknown": None,
        "root_cause_results": None,
        "labels_present": False,
    }
    manifest["component_census"].update({
        "sampled_translation_units": len(set(sampled_paths)),
        "sampled_complete_cpp_files": len(set(sampled_paths)),
        "sampled_function_excerpts": 1 + len(samples),
        "sampled_source_paths": sampled_paths,
        "complete_file_coverage_fraction": round(
            len(set(sampled_paths)) / census["summary"]["complete_files"], 6
        ),
        "frame_interpretation": "one F001 same-name control plus 20 stratified translation units; no semantic recall claim",
    })
    PACKET.write_text("".join(excerpts), encoding="utf-8", newline="\n")
    manifest["packet_sha256"] = hashlib.sha256(PACKET.read_bytes()).hexdigest()
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    with LABELS.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("sample_id", "model_scope", "evidence_label", "root_cause",
                         "unknown_reason", "evidence_lines", "reviewer_notes"))
        writer.writerow(("F001", "", "", "", "", "", ""))
        for sample in samples:
            writer.writerow((sample["sample_id"], "", "", "", "", "", ""))
    with LABELS.open("r", encoding="utf-8", newline="") as handle:
        label_rows = list(csv.DictReader(handle))
    issues = packet_issues(manifest, census, label_rows, PACKET.read_text(encoding="utf-8"))
    if issues:
        raise SystemExit("blind packet integrity failure: " + ",".join(issues))
    print(f"samples={len(samples) + 1}; sampled_files={len(set(sampled_paths))}; "
          f"eligible_files={len(eligible) + 1}; parse=complete; detector_invoked=false")


if __name__ == "__main__":
    main()
