"""Validate the research evidence sidecars without importing public schemas.

The validator is intentionally research-local. It rejects mixed revisions,
wrong commits/scopes, incomplete runs recorded as misses, unsupported
not_applicable cells, duplicate run IDs and broken evidence binding hashes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
CORPUS_DIR = ROOT / "research/corpus/native"
OUTPUT_DIR = ROOT / "outputs/reports/static_baselines"
EVIDENCE_PATH = OUTPUT_DIR / "evidence_units.json"
BASELINE_PATH = OUTPUT_DIR / "baseline_status.json"

INTERFACE_BASELINE = {
    "branch": "feat/ohscanner-core",
    "head": "108494bfe392ae62394ea82cd44d28cc03ebb163",
    "contract_path": "src/ohscanner/contracts.py",
    "contract_sha256": "b1a9658d700b73604ca358e80a65e04df4dd1bb8c5edbb85307f1038af865aeb",
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_EXECUTION = {"completed", "failed", "blocked", "not_run"}
ALLOWED_RESULT = {"possible_hit", "miss", "unknown", "not_applicable"}
ALLOWED_PARSING = {
    "complete",
    "complete_unresolved_symbol",
    "partial_cast_problem",
    "partial_macro_context",
    "partial_missing_includes",
    "partial_parser_problems",
    "failed",
    "not_applicable_no_translation_unit",
    "not_applicable_no_source_files",
    "not_run",
}


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON evidence {path}: {error}") from error


PARSING_COVERAGE_FIELDS = (
    "files_complete",
    "files_partial",
    "files_failed",
    "files_not_applicable",
    "files_not_run",
)


def _expected_parsing_coverage(status: str, scope_files: int) -> dict:
    counts = {field: 0 for field in PARSING_COVERAGE_FIELDS}
    if status == "complete":
        counts["files_complete"] = scope_files
    elif status == "complete_unresolved_symbol" or status.startswith("partial"):
        counts["files_partial"] = scope_files
    elif status.startswith("failed"):
        counts["files_failed"] = scope_files
    elif status.startswith("not_applicable"):
        counts["files_not_applicable"] = scope_files
    elif status == "not_run":
        counts["files_not_run"] = scope_files
    else:
        raise ValueError("unsupported parsing status")
    return {"status": status, **counts}


def _validate_parsing_coverage(record: dict, where: str) -> None:
    parsing = record.get("parsing_coverage")
    scope = record.get("scope")
    if not isinstance(parsing, dict) or not isinstance(scope, dict):
        raise ValueError(f"{where} unsupported parsing_coverage")
    status = parsing.get("status")
    if status not in ALLOWED_PARSING:
        raise ValueError(f"{where} unsupported parsing_coverage")
    if set(parsing) != {"status", *PARSING_COVERAGE_FIELDS}:
        raise ValueError(f"{where} parsing coverage fields mismatch")
    scope_files = scope.get("scope_files")
    if type(scope_files) is not int or scope_files < 1:
        raise ValueError(f"{where} parsing coverage requires positive scope_files")
    expected = _expected_parsing_coverage(status, scope_files)
    if parsing != expected:
        raise ValueError(f"{where} parsing coverage counts do not match status")
    for field in PARSING_COVERAGE_FIELDS:
        if type(parsing[field]) is not int or parsing[field] < 0:
            raise ValueError(f"{where} parsing coverage counts must be non-negative integers")


def _binding_digest(record: dict) -> str:
    fields = {key: value for key, value in record.items() if key != "binding_sha256"}
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_digest(units: list) -> str:
    manifest = [(unit["path"], unit["language"], unit["sha256"]) for unit in units]
    raw = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_relative_path(value: str, where: str) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or value.startswith("/")
            or value.endswith("/") or any(part in {"", ".", ".."} for part in value.split("/"))
            or ":" in value):
        raise ValueError(f"{where} requires a canonical repository-relative path")
    return value


def _require_string(record: dict, field: str, where: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where} requires non-empty {field}")
    return value


def _validate_interface_baseline(package: dict, root: Path, where: str) -> None:
    baseline = package.get("interface_baseline")
    if baseline != INTERFACE_BASELINE:
        raise ValueError(f"{where} interface_baseline must bind PR #5 head 108494bfe392ae62394ea82cd44d28cc03ebb163")
    contract_path = root / INTERFACE_BASELINE["contract_path"]
    try:
        contract_sha256 = hashlib.sha256(contract_path.read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(f"{where} cannot read interface contract: {error}") from error
    if contract_sha256 != INTERFACE_BASELINE["contract_sha256"]:
        raise ValueError(f"{where} interface contract hash mismatch")


def _corpus_index(corpus_dir: Path = CORPUS_DIR) -> dict:
    indexed = {}
    for path in sorted(corpus_dir.glob("*_uaf.json")) + sorted(corpus_dir.glob("*_write.json")):
        data = _load(path)
        if data.get("schema_version") != 1 or not isinstance(data.get("sample"), dict):
            raise ValueError(f"unsupported corpus record: {path}")
        sample = data["sample"]
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or sample_id in indexed:
            raise ValueError(f"invalid or duplicate corpus sample_id: {sample_id}")
        indexed[sample_id] = (path, data)
    return indexed


def _validate_source_binding(record: dict, where: str) -> None:
    source = record.get("source_artifact")
    if not isinstance(source, dict):
        raise ValueError(f"{where} requires source_artifact")
    source_sha = _require_string(record, "source_file_sha256", where)
    blob = _require_string(record, "git_blob_sha1", where)
    if not HEX64.fullmatch(source_sha):
        raise ValueError(f"{where} source_file_sha256 must be lowercase SHA-256")
    if not HEX40.fullmatch(blob):
        raise ValueError(f"{where} git_blob_sha1 must be lowercase Git blob SHA-1")
    tree = _require_string(source, "git_tree_sha1", where)
    commit = _require_string(source, "git_commit", where)
    if not HEX40.fullmatch(tree):
        raise ValueError(f"{where} git_tree_sha1 must be lowercase Git tree SHA-1")
    if not HEX40.fullmatch(commit):
        raise ValueError(f"{where} source git_commit must be a full commit SHA")
    if (source.get("source_file_sha256") != source_sha or source.get("git_blob_sha1") != blob
            or source.get("git_tree_sha1") != tree):
        raise ValueError(f"{where} source artifact hash binding mismatch")
    if record.get("git_tree_sha1") != tree:
        raise ValueError(f"{where} git_tree_sha1 binding mismatch")
    path = _safe_relative_path(_require_string(source, "repository_path", where), where)
    canonical_url = _require_string(source, "canonical_url", where)
    if not canonical_url.endswith(f"{commit}/{path}"):
        raise ValueError(f"{where} canonical URL is not bound to commit/path")
    if not isinstance(source.get("bytes"), int) or source["bytes"] <= 0:
        raise ValueError(f"{where} source artifact requires positive bytes")
    if not isinstance(source.get("lines"), int) or source["lines"] <= 0:
        raise ValueError(f"{where} source artifact requires positive lines")


def _validate_scan_context_identity(record: dict, where: str) -> None:
    identity = record.get("scan_context_identity")
    if not isinstance(identity, dict) or set(identity) != {"request", "units", "shared_facts"}:
        raise ValueError(f"{where} requires ScanRequest/SourceUnit/ScanContext identity")
    request = identity["request"]
    expected_request_fields = {
        "request_id", "repository", "commit", "snapshot_sha256", "target_id",
        "profile_id", "provenance",
    }
    if not isinstance(request, dict) or set(request) != expected_request_fields:
        raise ValueError(f"{where} ScanRequest identity fields mismatch")
    for field in expected_request_fields:
        _require_string(request, field, where)
    if request["repository"] != record["repository"]:
        raise ValueError(f"{where} ScanRequest repository mismatch")
    if request["commit"] != record["exact_commit"]:
        raise ValueError(f"{where} ScanRequest commit mismatch")
    if request["target_id"] != "current-component:" + request["repository"]:
        raise ValueError(f"{where} wrong target_id")
    if request["profile_id"] != "light-ast":
        raise ValueError(f"{where} wrong profile_id")
    if request["provenance"] != "git_object":
        raise ValueError(f"{where} wrong provenance")
    if not HEX64.fullmatch(request["snapshot_sha256"]):
        raise ValueError(f"{where} invalid snapshot_sha256")

    units = identity["units"]
    if not isinstance(units, list) or not units:
        raise ValueError(f"{where} ScanContext units must be non-empty")
    expected_unit_fields = {"path", "language", "sha256", "parse_status", "parse_issues"}
    paths = []
    for index, unit in enumerate(units):
        unit_where = f"{where} source unit[{index}]"
        if not isinstance(unit, dict) or set(unit) != expected_unit_fields:
            raise ValueError(f"{unit_where} SourceUnit identity fields mismatch")
        path = _safe_relative_path(unit.get("path"), unit_where)
        paths.append(path)
        if unit["language"] != "cpp":
            raise ValueError(f"{unit_where} wrong language")
        if not isinstance(unit["sha256"], str) or not HEX64.fullmatch(unit["sha256"]):
            raise ValueError(f"{unit_where} invalid source hash")
        if unit["parse_status"] != "not_run" or unit["parse_issues"] != []:
            raise ValueError(f"{unit_where} identity projection must retain not_run parse state")
    if len(paths) != len(set(paths)):
        raise ValueError(f"{where} duplicate source unit")
    if paths != sorted(paths):
        raise ValueError(f"{where} source units must be sorted")

    source = record["source_artifact"]
    expected_units = [{
        "path": source["repository_path"],
        "language": "cpp",
        "sha256": source["source_file_sha256"],
        "parse_status": "not_run",
        "parse_issues": [],
    }]
    if units != expected_units:
        raise ValueError(f"{where} source unit path/hash mismatch")
    if request["snapshot_sha256"] != _snapshot_digest(units):
        raise ValueError(f"{where} wrong snapshot_sha256")

    facts = identity["shared_facts"]
    expected_facts = {
        "sample_id": record["sample_id"],
        "revision": record["revision"],
        "control_role": record["control_role"],
        "analysis_unit_id": record["scope"]["analysis_unit_id"],
        "scope": record["scope"],
        "source_artifact": source,
    }
    if facts != expected_facts:
        raise ValueError(f"{where} ScanContext shared facts mismatch scope/source")


def _validate_run_binding(record: dict, where: str) -> None:
    binding = record.get("run_binding")
    expected_fields = {
        "run_id", "tool", "tool_version", "target_id", "commit",
        "scope_files", "scope_loc",
    }
    if not isinstance(binding, dict) or set(binding) != expected_fields:
        raise ValueError(f"{where} run binding fields mismatch")
    request = record["scan_context_identity"]["request"]
    scope = record["scope"]
    tool = record["tool"]
    expected = {
        "run_id": record["run_id"],
        "tool": tool["name"],
        "tool_version": tool["version"],
        "target_id": request["target_id"],
        "commit": request["commit"],
        "scope_files": scope["scope_files"],
        "scope_loc": scope["scope_loc"],
    }
    if binding != expected:
        raise ValueError(f"{where} run/request/scope binding mismatch")


def _validate_tool(record: dict, where: str) -> str:
    tool = record.get("tool")
    if not isinstance(tool, dict):
        raise ValueError(f"{where} requires tool")
    name = _require_string(tool, "name", where)
    _require_string(tool, "version", where)
    config = tool.get("configuration")
    if not isinstance(config, dict):
        raise ValueError(f"{where} requires tool configuration")
    _require_string(config, "config_id", where)
    if "config_artifact" not in config:
        raise ValueError(f"{where} requires config_artifact")
    digest = config.get("config_sha256")
    if digest is None:
        _require_string(config, "config_sha256_status", where)
    elif not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise ValueError(f"{where} config_sha256 must be lowercase SHA-256 or null with status")
    return name


def _validate_unit(record: dict, corpus: dict, where: str) -> None:
    if record.get("schema_version") != 1 or record.get("record_type") != "evidence_unit":
        raise ValueError(f"{where} requires schema_version 1 evidence_unit")
    evidence_unit_id = _require_string(record, "evidence_unit_id", where)
    sample_id = _require_string(record, "sample_id", where)
    repository = _require_string(record, "repository", where)
    exact_commit = _require_string(record, "exact_commit", where)
    revision = _require_string(record, "revision", where)
    control_role = _require_string(record, "control_role", where)
    if not HEX40.fullmatch(exact_commit):
        raise ValueError(f"{where} exact_commit must be a 40-character commit")
    if revision not in {"vulnerable", "fixed"}:
        raise ValueError(f"{where} unsupported revision")
    if control_role not in {"vulnerable", "fixed", "safe"}:
        raise ValueError(f"{where} unsupported control_role")
    if control_role in {"vulnerable", "fixed"} and control_role != revision:
        raise ValueError(f"{where} mixes vulnerable/fixed evidence")
    if control_role == "safe" and revision != "fixed":
        raise ValueError(f"{where} safe control must bind only to its pinned fixed source")

    scope = record.get("scope")
    if not isinstance(scope, dict):
        raise ValueError(f"{where} requires scope")
    analysis_unit_id = _require_string(scope, "analysis_unit_id", where)
    files = scope.get("files")
    if not isinstance(files, list) or not files or not all(isinstance(item, str) and item for item in files):
        raise ValueError(f"{where} requires non-empty scope.files")
    if len(set(files)) != len(files):
        raise ValueError(f"{where} duplicate scope.files")
    if not isinstance(scope.get("symbols"), list) or not scope["symbols"]:
        raise ValueError(f"{where} requires scope.symbols")
    if not isinstance(scope.get("scope_files"), int) or scope["scope_files"] != len(files):
        raise ValueError(f"{where} scope_files must match scope.files")
    _validate_source_binding(record, where)
    _validate_scan_context_identity(record, where)

    tool_name = _validate_tool(record, where)
    _validate_run_binding(record, where)
    run_id = record.get("run_id")
    if run_id is not None and (not isinstance(run_id, str) or not run_id.strip()):
        raise ValueError(f"{where} run_id must be non-empty or null")
    execution_status = record.get("execution_status")
    if execution_status not in ALLOWED_EXECUTION:
        raise ValueError(f"{where} unsupported execution_status")
    _validate_parsing_coverage(record, where)
    parsing = record["parsing_coverage"]
    result_status = record.get("result_status")
    if result_status not in ALLOWED_RESULT:
        raise ValueError(f"{where} unsupported result_status")
    evidence_count = record.get("result_evidence_count")
    if type(evidence_count) is not int or evidence_count < 0:
        raise ValueError(f"{where} result_evidence_count must be a non-negative integer")
    limitations = record.get("limitations")
    if not isinstance(limitations, list) or not limitations or not all(isinstance(item, str) and item for item in limitations):
        raise ValueError(f"{where} requires non-empty limitations")
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError(f"{where} requires provenance")
    for field in ("source", "source_license", "rule_provenance"):
        _require_string(provenance, field, where)
    if provenance.get("third_party_source_committed") is not False:
        raise ValueError(f"{where} must not commit third-party target source")
    artifacts = record.get("artifact_bindings")
    if not isinstance(artifacts, dict):
        raise ValueError(f"{where} requires artifact_bindings")
    for field in ("normalized_result_reference", "native_output_reference"):
        item = artifacts.get(field)
        if not isinstance(item, dict) or not isinstance(item.get("sha256_status"), str):
            raise ValueError(f"{where} requires explicit {field} hash status")

    expected_id = f"{analysis_unit_id}:{tool_name}:{run_id or 'not_run'}"
    if evidence_unit_id != expected_id:
        raise ValueError(f"{where} evidence_unit_id does not bind scope/tool/run_id")

    if execution_status == "not_run":
        if run_id is not None or result_status != "unknown":
            raise ValueError(f"{where} not_run must remain unknown with null run_id")
    else:
        if run_id is None:
            raise ValueError(f"{where} executed run requires run_id")
        if result_status in {"miss", "possible_hit"}:
            if execution_status != "completed" or parsing["status"] != "complete":
                raise ValueError(f"{where} failed/incomplete analysis cannot be miss or possible_hit")
            if result_status == "miss" and evidence_count != 0:
                raise ValueError(f"{where} miss cannot carry evidence")
            if result_status == "possible_hit" and evidence_count < 1:
                raise ValueError(f"{where} possible_hit requires candidate evidence")
        elif result_status == "not_applicable":
            reason = record.get("not_applicable_reason")
            if execution_status not in {"failed", "blocked"}:
                raise ValueError(f"{where} not_applicable requires failed/blocked incompatible analysis")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"{where} not_applicable requires explicit reason")
            if not str(parsing["status"]).startswith("not_applicable"):
                raise ValueError(f"{where} not_applicable parsing coverage must state incompatibility")
            if parsing["files_not_applicable"] != scope["scope_files"] or parsing["files_failed"] != 0:
                raise ValueError(f"{where} not_applicable cannot be represented as failed parsing coverage")
        elif result_status == "unknown" and evidence_count != 0:
            raise ValueError(f"{where} unknown cannot carry classified evidence count")

    if record.get("binding_sha256") != _binding_digest(record):
        raise ValueError(f"{where} evidence binding digest mismatch")

    if sample_id in corpus:
        _, family = corpus[sample_id]
        sample = family["sample"]
        if repository != sample["repository"]:
            raise ValueError(f"{where} repository mismatch")
        expected_scope = sample["pair_analysis_unit"] if control_role in {"vulnerable", "fixed"} else None
        if expected_scope is not None:
            if analysis_unit_id != expected_scope["analysis_unit_id"] + ":" + revision:
                # Baseline IDs add revision after the pair ID to preserve run isolation.
                expected_baseline_id = f"{sample['pair_analysis_unit']['analysis_unit_id']}:{revision}"
                if analysis_unit_id != expected_baseline_id:
                    raise ValueError(f"{where} pair scope mismatch")
            if files != expected_scope["files"]:
                raise ValueError(f"{where} pair scope file mismatch")
        revision_record = sample["revisions"][revision]
        if exact_commit != revision_record["exact_commit"]:
            raise ValueError(f"{where} exact commit mismatch")
        if record["source_file_sha256"] != revision_record["source_artifact"]["source_file_sha256"]:
            raise ValueError(f"{where} source_file_sha256 mismatch")
        if record["git_blob_sha1"] != revision_record["source_artifact"]["git_blob_sha1"]:
            raise ValueError(f"{where} git_blob_sha1 mismatch")
        if record["git_tree_sha1"] != revision_record["source_artifact"].get("git_tree_sha1"):
            raise ValueError(f"{where} git_tree_sha1 mismatch")
        if control_role == "safe":
            control = next(
                (item for item in sample["safe_controls"] if item["analysis_unit_id"] == analysis_unit_id),
                None,
            )
            if control is None:
                raise ValueError(f"{where} unknown safe control scope")
            if files != control["files"] or scope["symbols"] != control["symbols"]:
                raise ValueError(f"{where} safe control scope mismatch")


def validate_package(
    root: Path = ROOT,
    evidence_path: Path | None = None,
    baseline_path: Path | None = None,
) -> dict:
    corpus = _corpus_index(root / "research/corpus/native")
    evidence_path = evidence_path or root / "outputs/reports/static_baselines/evidence_units.json"
    baseline_path = baseline_path or root / "outputs/reports/static_baselines/baseline_status.json"
    evidence = _load(evidence_path)
    if evidence.get("schema_version") != 1 or not isinstance(evidence.get("units"), list):
        raise ValueError("evidence_units.json requires schema_version 1 units")
    _validate_interface_baseline(evidence, root, "evidence_units.json")
    units = evidence["units"]
    ids = set()
    run_ids = set()
    baseline_keys = set()
    baseline_units = []
    for index, record in enumerate(units):
        where = f"unit[{index}]"
        if not isinstance(record, dict):
            raise ValueError(f"{where} must be an object")
        _validate_unit(record, corpus, where)
        evidence_id = record["evidence_unit_id"]
        if evidence_id in ids:
            raise ValueError(f"duplicate evidence_unit_id: {evidence_id}")
        ids.add(evidence_id)
        run_id = record.get("run_id")
        if run_id is not None:
            if run_id in run_ids:
                raise ValueError(f"duplicate run_id: {run_id}")
            run_ids.add(run_id)
        if record["control_role"] in {"vulnerable", "fixed"}:
            key = (record["sample_id"], record["revision"], record["tool"]["name"])
            if key in baseline_keys:
                raise ValueError(f"duplicate baseline cell: {key}")
            baseline_keys.add(key)
            baseline_units.append(record)

    if len(baseline_units) != 64:
        raise ValueError(f"baseline requires 64 cells, found {len(baseline_units)}")
    baseline = _load(baseline_path)
    _validate_interface_baseline(baseline, root, "baseline_status.json")
    if baseline.get("source_of_truth") != "outputs/reports/static_baselines/evidence_units.json":
        raise ValueError("baseline_status source_of_truth mismatch")
    expected_counts = Counter(record["result_status"] for record in baseline_units)
    counts = baseline.get("counts")
    if not isinstance(counts, dict) or any(counts.get(key) != expected_counts.get(key, 0) for key in
                                           ("possible_hit", "miss", "unknown", "not_applicable")):
        raise ValueError("baseline status counts mismatch")
    cells = baseline.get("cells")
    if not isinstance(cells, list) or len(cells) != 64:
        raise ValueError("baseline_status requires 64 cells")
    by_id = {record["evidence_unit_id"]: record for record in baseline_units}
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("evidence_unit_id") not in by_id:
            raise ValueError("baseline_status contains unknown cell")
        record = by_id[cell["evidence_unit_id"]]
        for field in ("sample_id", "revision", "result_status", "result_evidence_count", "binding_sha256"):
            if cell.get(field) != record[field]:
                raise ValueError(f"baseline_status projection mismatch: {cell['evidence_unit_id']}/{field}")
        request = record["scan_context_identity"]["request"]
        if cell.get("tool") != record["tool"]["name"] or cell.get("run_id") != record["run_id"]:
            raise ValueError(f"baseline_status tool/run mismatch: {cell['evidence_unit_id']}")
        for field in ("request_id", "target_id", "commit", "snapshot_sha256", "profile_id", "provenance"):
            if cell.get(field) != request[field]:
                raise ValueError(
                    f"baseline_status request identity mismatch: {cell['evidence_unit_id']}/{field}"
                )
    return {
        "unit_count": len(units),
        "baseline_cell_count": len(baseline_units),
        "safe_control_cell_count": len(units) - len(baseline_units),
        "counts": {key: expected_counts.get(key, 0) for key in
                   ("possible_hit", "miss", "unknown", "not_applicable")},
    }


def main() -> None:
    summary = validate_package()
    print("[OK] evidence package valid: " + json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
