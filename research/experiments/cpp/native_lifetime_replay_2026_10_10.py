"""Replay one pinned native lifetime corpus sample with the narrow cpp detector.

The vulnerable, fixed and safe analysis units are executed independently. The
current detector covers only same-function unique_ptr/get/reset raw aliases; the
selected historical sample is shared_ptr/static-reference lifetime code, so its
benchmark cells are explicitly not_applicable rather than misses.

Generated raw sources, native stdout/stderr and normalized artifacts are written
only under ignored outputs/logs. The committed manifest binds their hashes and
the exact source/tool/config identities without committing third-party source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = ROOT / "research" / "corpus" / "native" / "lifetime_uaf.json"
MANIFEST_PATH = ROOT / "research" / "corpus" / "native" / "lifetime_uaf_native_run_2026-10-10.json"
OUTPUT_DIR = ROOT / "outputs" / "logs" / "native_lifetime_replay_2026_10_10"
RUN_DATE = "2026-10-10"
DETECTOR_ID = "ohscanner.cpp.lifetime"
DETECTOR_VERSION = "0.2.0-proposed"
RULE_ID = "ohcpp-lifetime-unique-raw-alias-reset-001"
COMMAND = (
    "C:\\Users\\work_work\\.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\python\\python.exe "
    "-m research.experiments.cpp.native_lifetime_replay_2026_10_10 --write"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_corpus() -> Dict[str, Any]:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    if corpus.get("schema_version") != 1 or corpus.get("family_id") != "lifetime_uaf":
        raise ValueError("unsupported native lifetime corpus")
    return corpus


def _revision(corpus: Mapping[str, Any], revision: str) -> Mapping[str, Any]:
    value = corpus["sample"]["revisions"].get(revision)
    if not isinstance(value, Mapping):
        raise ValueError(f"missing corpus revision: {revision}")
    return value


def _source_spec(
    corpus: Mapping[str, Any],
    role: str,
    revision: str,
    analysis_unit_id: str,
    symbols: Sequence[str],
    line_ranges: Sequence[Sequence[int]],
) -> Dict[str, Any]:
    revision_data = _revision(corpus, revision)
    artifact = revision_data["source_artifact"]
    return {
        "run_id": f"native-lifetime-2026-10-10:{role}",
        "evidence_unit_id": (
            "c_utils-singleton-uaf-2026-01:"
            f"{role}:base/include/singleton.h:{','.join(symbols)}"
        ),
        "root_cause_instance_id": "c_utils-singleton-uaf-2026-01",
        "analysis_unit_id": analysis_unit_id,
        "control_role": role,
        "revision": revision,
        "repository": corpus["sample"]["repository"],
        "repo_url": corpus["sample"]["repo_url"],
        "commit": revision_data["exact_commit"],
        "source_artifact": dict(artifact),
        "symbols": list(symbols),
        "line_ranges": [list(item) for item in line_ranges],
    }


def _run_specs(corpus: Mapping[str, Any]) -> tuple[Dict[str, Any], ...]:
    pair = corpus["sample"]["pair_analysis_unit"]
    safe = corpus["sample"]["safe_controls"][0]
    return (
        _source_spec(
            corpus,
            "vulnerable",
            "vulnerable",
            pair["analysis_unit_id"],
            pair["symbols"],
            pair["line_ranges"]["vulnerable"],
        ),
        _source_spec(
            corpus,
            "fixed",
            "fixed",
            pair["analysis_unit_id"],
            pair["symbols"],
            pair["line_ranges"]["fixed"],
        ),
        _source_spec(
            corpus,
            "safe",
            "fixed",
            safe["analysis_unit_id"],
            safe["symbols"],
            safe["line_ranges"],
        ),
    )


def _build_source_unit(spec: Mapping[str, Any], source_path: Path) -> tuple[SourceUnit, bytes]:
    raw = source_path.read_bytes()
    expected = spec["source_artifact"]
    if len(raw) != expected["bytes"]:
        raise ValueError(f"{spec['run_id']}: source byte count mismatch")
    if _sha256_bytes(raw) != expected["source_file_sha256"]:
        raise ValueError(f"{spec['run_id']}: source SHA-256 mismatch")
    text = raw.decode("utf-8")
    unit = SourceUnit(
        path=expected["repository_path"],
        language="cpp",
        text=text,
        sha256=_sha256_bytes(raw),
        parse_status="complete",
        parse_issues=(
            "Detector regex slice accepted balanced source; full template/build/macro context remains unknown.",
        ),
    )
    return unit, raw


def _emit_run(spec_path: Path) -> None:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    unit, _raw = _build_source_unit(spec, Path(spec["source_path"]))
    request = ScanRequest(
        request_id=spec["run_id"],
        repository=spec["repository"],
        commit=spec["commit"],
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + spec["repository"],
        profile_id="light-ast",
        provenance="git_object",
    )
    context = ScanContext(request=request, units=(unit,))
    run = LifetimeOwnershipGuardDetector(LifetimeAnalysisOptions()).detect(context, (unit,))
    payload = {
        "schema_version": 1,
        "run_id": spec["run_id"],
        "evidence_unit_id": spec["evidence_unit_id"],
        "analysis_unit_id": spec["analysis_unit_id"],
        "control_role": spec["control_role"],
        "revision": spec["revision"],
        "request": {
            "request_id": request.request_id,
            "repository": request.repository,
            "commit": request.commit,
            "target_id": request.target_id,
            "snapshot_sha256": request.snapshot_sha256,
            "profile_id": request.profile_id,
            "provenance": request.provenance,
        },
        "source_unit": {
            "path": unit.path,
            "language": unit.language,
            "sha256": unit.sha256,
            "parse_status": unit.parse_status,
            "parse_issues": list(unit.parse_issues),
        },
        "detector": {
            "detector_id": run.detector_id,
            "version": run.version,
            "status": run.status,
            "analyzed_files": list(run.analyzed_files),
            "findings": [
                {
                    "file": finding.file,
                    "line": finding.line,
                    "column": finding.column,
                    "rule_id": finding.rule_id,
                    "evidence_type": finding.evidence_type,
                    "candidate_cwe": finding.candidate_cwe,
                    "symbol": finding.symbol,
                    "message": finding.message,
                }
                for finding in run.findings
            ],
            "limitations": list(run.limitations),
        },
        "method_compatibility": {
            "benchmark_result_status": "not_applicable",
            "reason": (
                "Incompatible analysis unit: the historical root cause is concurrent "
                "std::shared_ptr publication/destruction (or static-reference control), "
                "while ohscanner.cpp.lifetime v0.2.0-proposed only models same-function "
                "std::unique_ptr owner.get()/reset() raw aliases."
            ),
            "is_explicit_incompatible_unit": True,
            "is_miss": False,
        },
        "interpretation": (
            "candidate/unassessed only; completed is scoped detector execution, "
            "not safe, and not_applicable is an explicit method/analysis-unit mismatch."
        ),
    }
    print(_canonical_json(payload))


def _fetch_source(spec: Mapping[str, Any], output_dir: Path) -> Path:
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    target = raw_dir / f"{spec['control_role']}_{spec['revision']}_{Path(spec['source_artifact']['repository_path']).name}"
    request = urllib.request.Request(
        spec["source_artifact"]["canonical_url"],
        headers={"User-Agent": "OHScanner-research-evidence/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    target.write_bytes(data)
    _build_source_unit(spec, target)
    return target


def _write_run(spec: Mapping[str, Any], source_path: Path, output_dir: Path) -> Dict[str, Any]:
    spec_path = output_dir / f"{spec['control_role']}_spec.json"
    source_spec = dict(spec)
    source_spec["source_path"] = str(source_path)
    spec_path.write_bytes((_canonical_json(source_spec) + "\n").encode("utf-8"))
    started = _utc_now()
    clock = time.perf_counter()
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "research.experiments.cpp.native_lifetime_replay_2026_10_10",
            "--emit-run",
            str(spec_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        check=False,
    )
    elapsed = time.perf_counter() - clock
    stdout_path = output_dir / f"{spec['control_role']}_native_stdout.json"
    stderr_path = output_dir / f"{spec['control_role']}_native_stderr.txt"
    stdout_path.write_bytes(process.stdout)
    stderr_path.write_bytes(process.stderr)
    if process.returncode != 0:
        raise RuntimeError(
            f"{spec['run_id']} child failed rc={process.returncode}: "
            + process.stderr.decode("utf-8", errors="replace")
        )
    normalized = json.loads(process.stdout.decode("utf-8"))
    normalized_path = output_dir / f"{spec['control_role']}_normalized.json"
    normalized_text = _canonical_json(normalized) + "\n"
    normalized_path.write_bytes(normalized_text.encode("utf-8"))
    source_bytes = source_path.read_bytes()
    config = {
        "detector_id": DETECTOR_ID,
        "detector_version": DETECTOR_VERSION,
        "rule_id": RULE_ID,
        "options": {
            "suppress_rebound_alias": True,
            "classify_sync_scope": True,
            "timeout_check": None,
        },
        "profile_id": "light-ast",
        "source_repository_path": spec["source_artifact"]["repository_path"],
        "commit": spec["commit"],
        "analysis_unit_id": spec["analysis_unit_id"],
    }
    return {
        "run_id": spec["run_id"],
        "evidence_unit_id": spec["evidence_unit_id"],
        "root_cause_instance_id": spec["root_cause_instance_id"],
        "analysis_unit_id": spec["analysis_unit_id"],
        "control_role": spec["control_role"],
        "revision": spec["revision"],
        "repository": spec["repository"],
        "repo_url": spec["repo_url"],
        "commit": spec["commit"],
        "source_artifact": {
            **spec["source_artifact"],
            "retrieval_observed": "raw bytes fetched from canonical_url at exact commit",
            "line_count_observation": {
                "metadata_lines": spec["source_artifact"]["lines"],
                "raw_splitlines": len(source_bytes.decode("utf-8").splitlines()),
                "raw_newlines": source_bytes.count(b"\n"),
                "status": (
                    "matches"
                    if len(source_bytes.decode("utf-8").splitlines())
                    == spec["source_artifact"]["lines"]
                    else "metadata_mismatch_preserved"
                ),
            },
        },
        "symbols": spec["symbols"],
        "line_ranges": spec["line_ranges"],
        "command": COMMAND,
        "child_command": (
            f"{sys.executable} -m research.experiments.cpp."
            "native_lifetime_replay_2026_10_10 --emit-run <run-spec>"
        ),
        "tool": {
            "detector_id": DETECTOR_ID,
            "version": DETECTOR_VERSION,
            "rule_id": RULE_ID,
            "query": None,
            "external_scanner": None,
        },
        "runtime": {
            "started_utc": started,
            "finished_utc": _utc_now(),
            "elapsed_seconds": round(elapsed, 6),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "config": config,
        "config_sha256": _sha256_text(_canonical_json(config)),
        "input_sha256": _sha256_bytes(source_bytes),
        "snapshot_sha256": normalized["request"]["snapshot_sha256"],
        "native_stdout": {
            "path": str(stdout_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": _sha256_bytes(process.stdout),
            "bytes": len(process.stdout),
        },
        "native_stderr": {
            "path": str(stderr_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": _sha256_bytes(process.stderr),
            "bytes": len(process.stderr),
        },
        "normalized_artifact": {
            "path": str(normalized_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": _sha256_text(normalized_text),
            "bytes": len(normalized_text.encode("utf-8")),
        },
        "coverage": {
            "source_retrieval": "complete",
            "source_bytes_verified": True,
            "detector_parse_status": normalized["source_unit"]["parse_status"],
            "detector_analyzed_files": normalized["detector"]["analyzed_files"],
            "full_build_macro_template_context": "unknown",
            "method_scope": "unique_ptr_owner_get_reset_raw_alias_only",
        },
        "execution_status": normalized["detector"]["status"],
        "result_status": "not_applicable",
        "result_evidence_count": len(normalized["detector"]["findings"]),
        "failure_status": {
            "completed": "none",
            "blocked": "blocked",
            "failed": "failed",
        }[normalized["detector"]["status"]],
        "failure_reason": (
            "The vulnerable shared_ptr.reset() shape is outside the unique_ptr/get/reset "
            "rule-symbol binding and the scoped detector run is blocked/unknown."
            if normalized["detector"]["status"] == "blocked"
            else None
        ),
        "not_applicable_reason": (
            "Explicitly evidenced incompatible analysis unit: this historical root cause "
            "models concurrent shared_ptr/static-reference lifetime semantics, not the "
            "detector's unique_ptr/get/reset raw-alias shape."
        ),
        "status_semantics": {
            "candidate": "not a vulnerability verdict",
            "completed": "scoped detector execution only, not safe",
            "not_applicable": "explicit method/analysis-unit incompatibility",
            "miss": "not assigned",
            "unknown": "full product build/macro/template context remains unknown",
        },
    }


def _manifest(corpus: Mapping[str, Any], records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "run_kind": "native_lifetime_replay",
        "run_date": RUN_DATE,
        "family_id": corpus["family_id"],
        "sample_id": corpus["sample"]["sample_id"],
        "source_corpus": "research/corpus/native/lifetime_uaf.json",
        "separate_runs": True,
        "vulnerable_fixed_safe_not_substitutable": True,
        "records": list(records),
        "limitations": [
            "No external scanner was invoked; only the self-built cpp lifetime detector ran.",
            "The selected historical unit is shared_ptr/static-reference lifetime code and is outside this detector's method scope.",
            "The raw source retrieval and detector regex slice are complete; full template instantiation, product macros and build dependencies remain unknown.",
            "No runtime trigger, TSan replay, PoC, exploitability or vulnerability verdict was produced.",
            "No Precision/Recall, false-positive or false-negative claim is computed.",
        ],
        "provenance": {
            "source_license": corpus["sample"]["provenance"]["source_license"],
            "attribution": corpus["sample"]["provenance"]["attribution"],
            "third_party_source_committed": False,
            "generated_outputs_are_ignored": True,
        },
    }


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema_version") != 1 or manifest.get("run_kind") != "native_lifetime_replay":
        raise ValueError("unsupported native run manifest")
    records = manifest.get("records")
    if not isinstance(records, list) or len(records) != 3:
        raise ValueError("native run manifest requires three independent records")
    expected_roles = ["vulnerable", "fixed", "safe"]
    if [item.get("control_role") for item in records] != expected_roles:
        raise ValueError("native run roles must be vulnerable, fixed, safe in order")
    seen = set()
    for record in records:
        for key in ("run_id", "evidence_unit_id", "analysis_unit_id", "commit", "input_sha256", "config_sha256"):
            if not isinstance(record.get(key), str) or not record[key]:
                raise ValueError(f"missing native run binding: {key}")
        if record["run_id"] in seen:
            raise ValueError("duplicate native run id")
        seen.add(record["run_id"])
        if record.get("result_status") != "not_applicable":
            raise ValueError("native shared_ptr control must remain explicit not_applicable")
        if record.get("result_evidence_count") != 0:
            raise ValueError("incompatible unit must not import detector findings")
        if record.get("execution_status") not in {"completed", "failed", "blocked"}:
            raise ValueError("invalid native execution status")
        if record.get("failure_status") not in {"none", "unknown", "blocked", "failed"}:
            raise ValueError("invalid failure status")
        expected_failure_status = {
            "completed": "none",
            "blocked": "blocked",
            "failed": "failed",
        }[record["execution_status"]]
        if record.get("failure_status") != expected_failure_status:
            raise ValueError("native execution/failure status mismatch")
        if expected_failure_status == "none":
            if record.get("failure_reason") is not None:
                raise ValueError("successful scoped execution cannot carry a failure reason")
        elif not isinstance(record.get("failure_reason"), str) or not record["failure_reason"]:
            raise ValueError("blocked/failed native execution requires a failure reason")
        for artifact_key in ("native_stdout", "native_stderr", "normalized_artifact"):
            artifact = record.get(artifact_key)
            if not isinstance(artifact, Mapping) or not artifact.get("path") or not artifact.get("sha256"):
                raise ValueError(f"missing {artifact_key} hash")


def _write_manifest() -> None:
    corpus = _load_corpus()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for spec in _run_specs(corpus):
        source_path = _fetch_source(spec, OUTPUT_DIR)
        records.append(_write_run(spec, source_path, OUTPUT_DIR))
    manifest = _manifest(corpus, records)
    _validate_manifest(manifest)
    MANIFEST_PATH.write_bytes((json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    print(f"[OK] wrote {MANIFEST_PATH.relative_to(ROOT)} and ignored native outputs under {OUTPUT_DIR.relative_to(ROOT)}")


def _check_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    _validate_manifest(manifest)
    for record in manifest["records"]:
        for key in ("native_stdout", "native_stderr", "normalized_artifact"):
            artifact = record[key]
            path = ROOT / artifact["path"]
            if not path.exists():
                raise FileNotFoundError(path)
            if _sha256_bytes(path.read_bytes()) != artifact["sha256"]:
                raise ValueError(f"artifact hash mismatch: {artifact['path']}")
        raw = ROOT / "outputs" / "logs" / "native_lifetime_replay_2026_10_10" / "raw" / (
            f"{record['control_role']}_{record['revision']}_{Path(record['source_artifact']['repository_path']).name}"
        )
        if not raw.exists() or _sha256_bytes(raw.read_bytes()) != record["input_sha256"]:
            raise ValueError(f"raw source hash mismatch: {record['run_id']}")
    print("[OK] native lifetime replay manifest and ignored artifacts match")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="fetch exact raw sources and write ignored run artifacts")
    parser.add_argument("--check", action="store_true", help="verify committed manifest against existing ignored artifacts")
    parser.add_argument("--emit-run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.emit_run:
        _emit_run(args.emit_run)
        return
    if args.write:
        _write_manifest()
        return
    if args.check:
        _check_manifest()
        return
    parser.error("choose --write or --check")


if __name__ == "__main__":
    main()
