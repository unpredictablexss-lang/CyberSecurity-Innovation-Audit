from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
DEFAULT_QUEUE = ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/function_stratified_pilot_20261019/reviewer/blind_review_queue.csv"
DEFAULT_SCAN = WORKSPACE / "openharmony-abcd-full-scan-20261018-final"
DEFAULT_SOURCE = WORKSPACE / "openharmony"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_parts(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    if path.is_absolute() or not value or "\\" in value or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    return path.parts


def main() -> int:
    parser = argparse.ArgumentParser(description="Recheck that the blind review queue remains source-bound and context-ready")
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--scan-root", type=Path, default=DEFAULT_SCAN)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    projects = {}
    with (args.scan_root / "project_summary.csv").open(encoding="utf-8-sig", newline="") as source:
        projects = {row["repository"]: row for row in csv.DictReader(source)}
    candidate_index: dict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    with (args.scan_root / "candidate_results.csv").open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("detector") != "ohscanner.cpp.unsafe_memory_call":
                continue
            key = (row["repository"], row["manifest_commit"], row["file"], row["line"])
            candidate_index[key].append(row)

    with args.queue.open(encoding="utf-8-sig", newline="") as source:
        queue_rows = list(csv.DictReader(source))
    sample_ids = [row.get("review_sample_id", "") for row in queue_rows]
    if len(queue_rows) != 160 or any(not value for value in sample_ids) or len(set(sample_ids)) != len(sample_ids):
        raise ValueError("review queue must contain exactly 160 unique, nonempty sample IDs")

    failures: Counter[str] = Counter()
    candidate_rows_bound = 0
    unique_candidate_row_bindings = 0
    source_hashes_matched = 0
    contexts_matched = 0
    label_fields = ("reviewer_disposition", "reviewer_rationale", "evidence_reference", "confidence", "reviewer_id")
    labels_filled = 0
    result_cache: dict[Path, dict[str, dict]] = {}
    for row in queue_rows:
        repo, commit, relative, line, expected_hash = (
            row["repository"], row["commit"], row["file"], row["line"], row["source_sha256"]
        )
        project = projects.get(repo)
        if project is None or project.get("manifest_commit") != commit:
            failures["repository_commit_not_in_scan_manifest"] += 1
            continue
        candidate_key = (repo, commit, relative, line)
        candidate_rows = candidate_index.get(candidate_key, [])
        candidate_matches = 0
        for candidate in candidate_rows:
            result_value = candidate["result_path"]
            prefix = "/mnt/d/openHarmonyScanner/"
            if not result_value.startswith(prefix):
                continue
            result_path = Path("D:/openHarmonyScanner") / Path(result_value[len(prefix):].replace("/", "\\"))
            diagnostics = result_cache.get(result_path)
            if diagnostics is None:
                document = json.loads(result_path.read_text(encoding="utf-8"))
                diagnostics = {
                    diagnostic["diagnostic_id"]: diagnostic
                    for detector_run in document["detector_runs"]
                    if detector_run.get("tool") == "ohscanner.cpp.unsafe_memory_call"
                    for diagnostic in detector_run.get("diagnostics", [])
                }
                result_cache[result_path] = diagnostics
            diagnostic = diagnostics.get(candidate["diagnostic_id"])
            if diagnostic and diagnostic.get("source_sha256") == expected_hash and int(diagnostic["line"]) == int(line):
                candidate_matches += 1
        if candidate_matches == 0:
            failures["not_bound_to_candidate_row"] += 1
        elif candidate_matches > 1:
            failures["ambiguous_candidate_row_binding"] += 1
        else:
            candidate_rows_bound += 1
            unique_candidate_row_bindings += 1

        path_parts = (*safe_parts(project["project_path"]), *safe_parts(relative))
        root = args.source_root.resolve()
        source_path = root.joinpath(*path_parts).resolve()
        if not source_path.is_relative_to(root) or not source_path.is_file():
            failures["source_file_missing_or_escaped"] += 1
            continue
        data = source_path.read_bytes()
        if sha256(data) != expected_hash:
            failures["source_hash_mismatch"] += 1
            continue
        source_hashes_matched += 1
        lines = data.decode("utf-8", errors="replace").splitlines()
        line_number = int(line)
        if line_number < 1 or line_number > len(lines):
            failures["line_out_of_range"] += 1
            continue
        start, end = max(1, line_number - 4), min(len(lines), line_number + 4)
        current_context = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
        if current_context != row.get("source_context", ""):
            failures["source_context_mismatch"] += 1
        else:
            contexts_matched += 1
        labels_filled += any(row.get(field, "").strip() for field in label_fields)

    if failures:
        status = "partial"
    elif candidate_rows_bound == source_hashes_matched == contexts_matched == len(queue_rows):
        status = "ready_for_reviewer"
    else:
        status = "partial"
    if labels_filled:
        raise ValueError("reviewer labels are already present; do not overwrite them")

    report = {
        "schema_version": "ohscanner.a-unsafe-blind-queue-readiness-v1",
        "status": status,
        "audit_script_sha256": sha256(Path(__file__).read_bytes()),
        "queue_sha256": sha256(args.queue.read_bytes()),
        "source_run_signature": json.loads((args.scan_root / "run_config.json").read_text(encoding="utf-8"))["run_signature"],
        "source_root": str(args.source_root.resolve()),
        "counts": {
            "queue_rows": len(queue_rows),
            "candidate_rows_bound": candidate_rows_bound,
            "unique_candidate_row_bindings": unique_candidate_row_bindings,
            "source_hashes_matched": source_hashes_matched,
            "source_contexts_matched": contexts_matched,
            "reviewed_rows": labels_filled,
            "pending_rows": len(queue_rows) - labels_filled,
        },
        "failures": dict(sorted(failures.items())),
        "scope_limit": "This checks queue/source readiness only. It does not provide human labels or prove vulnerability truth.",
    }
    output = args.output or args.queue.parent.parent / "queue_readiness_audit_20261019.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, **report["counts"], "failures": report["failures"], "output": str(output)}, ensure_ascii=False))
    return 0 if status == "ready_for_reviewer" else 1


if __name__ == "__main__":
    raise SystemExit(main())
