"""Build a reproducible, prediction-free function sample for external review.

The script never imports or invokes the C-line detector. It selects excerpts
from one pinned official source file so a reviewer can label applicability and
unknowns without seeing scanner output.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "escompat_TypedArrays.cpp"
FREEZE = ROOT.parent / "ark-runtime-c-line-algorithm-freeze-20261018.json"
SEED = "openharmony/arkcompiler_runtime_core@a053abc44c608b11d9f9dd10bd681dc222b9d4a9"
SAMPLE_COUNTS = {"buffer_lifetime": 2, "mutating_copy": 6, "typedarray_transfer": 12}
REQUIRED_NAMES = {
    "mutating_copy": ("CopyWithin", "ReverseImpl", "FillInternal"),
    "typedarray_transfer": ("SetValuesImpl", "SetValueFromArrayAt", "SetValuesFromArraySlowPath"),
}


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def compact(text: str) -> str:
    return " ".join(text.split())


def category(name: str) -> str | None:
    if "GetTypedArrayByteRange" in name or "GetNativeData" in name:
        return "buffer_lifetime"
    if any(word in name for word in ("Fill", "CopyWithin", "Reverse")):
        return "mutating_copy"
    if any(word in name for word in ("SetValues", "SetValueFromArrayAt")):
        return "typedarray_transfer"
    return None


def main() -> None:
    raw = SOURCE.read_bytes()
    data = raw.decode("utf-8")
    freeze_raw = FREEZE.read_bytes()
    freeze = json.loads(freeze_raw)
    lines = data.splitlines()
    tree = Parser(Language(tree_sitter_cpp.language())).parse(raw)
    frames = []
    for node in walk(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        signature = compact(declarator.text.decode("utf-8", errors="replace"))
        label = category(signature)
        if label is None:
            continue
        start, end = node.start_point[0], node.end_point[0] + 1
        rank = hashlib.sha256(f"{SEED}\0{label}\0{start}\0{signature}".encode()).hexdigest()
        frames.append({"category": label, "signature": signature, "start": start,
                       "end": end, "rank": rank, "node_has_error": node.has_error})

    selected = []
    for label, count in SAMPLE_COUNTS.items():
        group = sorted((row for row in frames if row["category"] == label),
                       key=lambda row: (row["rank"], row["start"]))
        required = []
        for needle in REQUIRED_NAMES.get(label, ()):
            matches = [row for row in group if needle in row["signature"]]
            if matches:
                required.append(min(matches, key=lambda row: row["start"]))
        by_start = {row["start"]: row for row in required}
        for row in group:
            if len(by_start) >= count:
                break
            by_start.setdefault(row["start"], row)
        selected.extend(by_start.values())
    selected.sort(key=lambda row: (row["category"], row["rank"], row["start"]))
    for index, row in enumerate(selected, 1):
        row["sample_id"] = f"H{index:03d}"
        row["source_lines"] = [row["start"] + 1, row["end"]]
        row["code"] = "\n".join(lines[row["start"]:row["end"]])

    manifest = {
        "schema": "c-line-cross-component-review-frame-v1",
        "algorithm_freeze": {
            "detector_version": freeze["detector_version"],
            "model_sha256": freeze["model_sha256"],
            "freeze_manifest_sha256": hashlib.sha256(freeze_raw).hexdigest(),
            "sample_regenerated_after_freeze": True,
            "developer_inspected_source_before_freeze": True,
            "counts_as_independent_holdout": False,
        },
        "algorithm_seed": SEED,
        "selection": {
            "frame": "function_definition nodes whose declarator names contain the fixed keywords in category()",
            "sample_counts": SAMPLE_COUNTS,
            "required_name_strata": REQUIRED_NAMES,
            "ranking": "ascending SHA-256(seed || NUL || category || NUL || start-line-zero-based || NUL || compact declarator)",
            "detector_invoked": False,
            "labels_present": False,
            "previous_full_scan_c_status": "missing",
            "developer_inspected_source_for_sampling": True,
        },
        "source": {
            "repository": "openharmony/arkcompiler_runtime_core",
            "commit": "a053abc44c608b11d9f9dd10bd681dc222b9d4a9",
            "tree": "96c955e45cae52cd03fe9b5c33407ef119047aef",
            "path": "static_core/plugins/ets/runtime/intrinsics/escompat_TypedArrays.cpp",
            "git_blob_oid": "e748456cb94ef3b012254bcd345e548d9d1b54e6",
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "coverage": {
            "source_lines": len(lines),
            "function_definition_nodes": sum(n.type == "function_definition" for n in walk(tree.root_node)),
            "selected_frame_nodes": len(frames),
            "selected_for_review": len(selected),
            "selected_node_errors": sum(bool(row["node_has_error"]) for row in selected),
            "translation_unit_parse_status": "partial" if tree.root_node.has_error else "complete",
            "reviewed": 0,
            "unknown": None,
            "root_cause_results": None,
        },
        "samples": [{key: value for key, value in row.items() if key != "code"} for row in selected],
    }
    (ROOT / "blind_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (ROOT / "blind_packet.md").write_text(
        "# Independent C-line holdout review packet\n\n"
        "Review the source excerpts below without access to detector predictions. "
        "For each ID, label model applicability (`in_scope`, `out_of_scope`, or `unknown`), "
        "behavior/evidence (`candidate`, `repair`, `safe`, `blocked`, or `unknown`), and root cause. "
        "Cite source lines and mark unknown when type/build/runtime dependencies are insufficient. "
        "These excerpts alone cannot establish product impact.\n\n"
        + "\n\n".join(
            f"## {row['sample_id']}\n\n````cpp\n{row['code']}\n````"
            for row in selected
        ) + "\n",
        encoding="utf-8",
    )
    with (ROOT / "reviewer_labels.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("sample_id", "applicability", "evidence_label", "root_cause",
                         "unknown_reason", "source_lines", "reviewer_notes"))
        for row in selected:
            writer.writerow((row["sample_id"], "", "", "", "", "", ""))
    print(json.dumps(manifest["coverage"], sort_keys=True))


if __name__ == "__main__":
    main()
