"""Replay current A memory-safety detectors over existing pinned manifests.

The caller supplies local Git object stores and acquisition metadata. This
script verifies each manifest's full commit/tree identity, reads exact pinned
blobs, rechecks the inventory, and writes source-bound candidate reports.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.contracts import DetectorRun
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.indexing import environment_fingerprint, prepare_git_context


DEFAULT_COMPONENTS = (
    "communication_dsoftbus",
    "distributeddatamgr_kv_store",
    "security_access_token",
    "update_updateservice",
    "window_window_manager",
)
BASELINE_COMMIT = "4593a7c9b6977eb81172d01b46cc59daf46f5d45"
UNSAFE_DETECTOR_PATH = "src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py"
MEMORY_HELPER_PATH = "src/ohscanner/detectors/cpp/memory_safety.py"


def _load_baseline_unsafe_detector() -> Tuple[Any, Dict[str, str]]:
    def source_at(path: str) -> bytes:
        return subprocess.run(
            ["git", "show", f"{BASELINE_COMMIT}:{path}"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout

    sources = {
        "memory_safety": source_at(MEMORY_HELPER_PATH),
        "unsafe_memory_call_detector": source_at(UNSAFE_DETECTOR_PATH),
    }
    hashes = {name: hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
              for name, data in sources.items()}
    package_name = "src.ohscanner.detectors.cpp_pinned_baseline"
    package = types.ModuleType(package_name)
    package.__path__ = [str((PROJECT_ROOT / "src/ohscanner/detectors/cpp").resolve())]
    package.__package__ = package_name
    sys.modules[package_name] = package
    for short_name, source in sources.items():
        name = f"{package_name}.{short_name}"
        spec = importlib.util.spec_from_loader(name, loader=None)
        if spec is None:
            raise RuntimeError(f"could not create pinned baseline module: {name}")
        module = importlib.util.module_from_spec(spec)
        module.__file__ = f"{BASELINE_COMMIT}:{MEMORY_HELPER_PATH if short_name == 'memory_safety' else UNSAFE_DETECTOR_PATH}"
        sys.modules[name] = module
        exec(compile(source.decode("utf-8"), module.__file__, "exec"), module.__dict__)
    module = sys.modules[f"{package_name}.unsafe_memory_call_detector"]
    return module.CppUnsafeMemoryCallDetector, hashes


def _finding_key(item: Mapping[str, Any]) -> Tuple[Any, ...]:
    return (item["file"], item["line"], item["column"], item["rule_id"], item["symbol"], item["message"])


def _json_finding(finding: Any) -> Dict[str, Any]:
    return {
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "evidence_type": finding.evidence_type,
        "candidate_cwe": finding.candidate_cwe,
        "symbol": finding.symbol,
        "consequence_impact": finding.consequence_impact,
        "consequence_cwe": finding.consequence_cwe,
        "source_sha256": finding.source_sha256,
        "rule_version": finding.rule_version,
        "rule_lineage_id": finding.rule_lineage_id,
        "identity_quality": finding.identity_quality,
        "evidence_obligations": [
            {"kind": item.kind, "description": item.description, "status": item.status}
            for item in finding.evidence_obligations
        ],
    }


def _json_run(run: DetectorRun) -> Dict[str, Any]:
    return {
        "detector_id": run.detector_id,
        "version": run.version,
        "status": run.status,
        "analyzed_files": list(run.analyzed_files),
        "findings": [_json_finding(item) for item in run.findings],
        "limitations": list(run.limitations),
        "file_outcomes": [list(item) for item in run.file_outcomes],
    }


def _resolve_source_root(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    match = re.fullmatch(r"([A-Za-z]):\\(.*)", value)
    if match and os.name != "nt":
        converted = Path("/mnt") / match.group(1).lower() / match.group(2).replace("\\", "/")
        if converted.exists():
            return converted
    return path


def _load_manifest(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest_paths(manifest: Mapping[str, Any]) -> Tuple[str, ...]:
    paths: List[str] = []
    for shard in manifest.get("shards", []):
        paths.extend(shard.get("paths", []))
    return tuple(sorted(set(paths)))


def _verify_manifest_identity(manifest: Mapping[str, Any], source_root: Path) -> None:
    if manifest.get("kind") != "pinned_component_scan_manifest":
        raise ValueError("unsupported manifest kind")
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported manifest schema")
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("mapped source root must be an existing non-symlink directory")
    expected_commit = manifest["commit"]
    expected_tree = manifest["git_tree"]
    _commit, _tree, sources, _inventory = load_git_sources(
        source_root, expected_commit, _manifest_paths(manifest)
    )
    if _commit != expected_commit or _tree != expected_tree:
        raise ValueError("manifest commit/tree mismatch")


def _run_component(
    manifest_path: Path,
    out_dir: Path,
    source_roots: Mapping[str, str],
    baseline_detector_type: Any,
    baseline_hashes: Mapping[str, str],
) -> Dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    repository = manifest["repository"]
    commit = manifest["commit"]
    source_entry = source_roots.get(manifest["component"], manifest["source_repo_path"])
    source_root = Path(source_entry["path"] if isinstance(source_entry, dict) else source_entry)
    _verify_manifest_identity(manifest, source_root)
    includes = _manifest_paths(manifest)
    started = time.perf_counter()
    context, tree, inventory, coverage, sources = prepare_git_context(
        source_root, repository, commit, includes
    )
    commit2, tree2, sources2, inventory2 = load_git_sources(source_root, commit, includes)
    if (
        commit2 != context.request.commit
        or tree != tree2
        or tuple((item.path, item.oid, item.data) for item in sources)
        != tuple((item.path, item.oid, item.data) for item in sources2)
        or inventory2 != inventory
    ):
        raise ValueError("pinned Git object inventory changed during analysis")
    baseline_unsafe_run = _json_run(baseline_detector_type().detect(context, context.units))
    detector_runs = [
        _json_run(CppBoundsDetector().detect(context, context.units)),
        _json_run(CppIntegerBoundsDetector().detect(context, context.units)),
        _json_run(CppResourceLifetimeDetector().detect(context, context.units)),
        _json_run(CppUnsafeMemoryCallDetector().detect(context, context.units)),
    ]
    wall = time.perf_counter() - started
    findings = [item for run in detector_runs for item in run["findings"]]
    component = manifest["component"]
    json_path = out_dir / f"{component}.json"
    md_path = out_dir / f"{component}.md"
    report = {
        "schema_version": 1,
        "experiment_kind": "a_memory_safety_pinned_component_scan",
        "status": "completed_with_limitations",
        "component": component,
        "repository": repository,
        "source_repo_path": str(source_root),
        "commit": commit,
        "git_tree": tree,
        "snapshot_sha256": context.request.snapshot_sha256,
        "profile_id": context.request.profile_id,
        "provenance": "local_pinned_git_objects",
        "source_acquisition": ({
            "remote_url": source_entry.get("remote"),
            "fetch_ref": source_entry.get("ref"),
            "verified_commit": commit,
            "verified_tree": tree,
            "storage": "temporary bare Git repository",
        } if isinstance(source_entry, dict) else None),
        "original_manifest_source_repo_path": manifest["source_repo_path"],
        "scope_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "scope": inventory,
        "coverage": coverage,
        "detector_runs": detector_runs,
        "pinned_baseline_unsafe_detector": {
            "commit": BASELINE_COMMIT,
            "version": baseline_unsafe_run["version"],
            "source_sha256": baseline_hashes["unsafe_memory_call_detector"],
            "dependency_source_sha256": baseline_hashes["memory_safety"],
            "status": baseline_unsafe_run["status"],
            "findings": baseline_unsafe_run["findings"],
        },
        "unsafe_detector_before_after": {
            "baseline_commit": BASELINE_COMMIT,
            "baseline_version": baseline_unsafe_run["version"],
            "current_version": detector_runs[-1]["version"],
            "baseline_candidates": len(baseline_unsafe_run["findings"]),
            "current_candidates": len(detector_runs[-1]["findings"]),
            "baseline_status": baseline_unsafe_run["status"],
            "current_status": detector_runs[-1]["status"],
            "removed_exact_findings": len(set(map(_finding_key, baseline_unsafe_run["findings"])) - set(map(_finding_key, detector_runs[-1]["findings"]))),
            "added_exact_findings": len(set(map(_finding_key, detector_runs[-1]["findings"])) - set(map(_finding_key, baseline_unsafe_run["findings"]))),
        },
        "candidate_count": len(findings),
        "candidate_groups": len({
            (run["detector_id"], item["rule_id"], item["symbol"])
            for run in detector_runs for item in run["findings"]
        }),
        "validated_vulnerability": 0,
        "eligible_for_metrics": False,
        "precision_recall": None,
        "performance": {
            "wall_seconds": wall,
            "selected_source_files": inventory["selected_source_files"],
            "selected_source_bytes": inventory["selected_source_bytes"],
            "process_peak_rss_kib": None,
        },
        "environment": environment_fingerprint(),
        "exact_argv": list(sys.argv),
        "limitations": [
            "Candidate-only lexical analysis; no confirmed/reportable vulnerability is claimed.",
            "No product build, permission boundary, attacker control, trigger trace or CIA impact is established.",
            "Pointer aliases, wrappers, macro expansion, templates, interprocedural range facts and complete CFG dominance remain unknown.",
            "Source objects were acquired before analysis and their remote/ref are recorded separately; analysis reads only the verified local pinned Git objects, performs no checkout, and invokes no external scanner.",
        ],
    }
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = [
        f"# A memory-safety pinned scan: {component}", "",
        "> Candidate-only report; `validated_vulnerability=0`.", "",
        f"- Repository: `{repository}`",
        f"- Commit: `{commit}`",
        f"- Git tree: `{tree}`",
        f"- Snapshot SHA-256: `{report['snapshot_sha256']}`",
        f"- Scope manifest SHA-256: `{report['scope_manifest_sha256']}`",
        f"- Selected files/bytes: {inventory['selected_source_files']}/{inventory['selected_source_bytes']}",
        f"- Wall seconds: {wall:.6f}",
        f"- Candidate findings/groups: {len(findings)}/{report['candidate_groups']}",
        "",
        "## Detector runs", "",
    ]
    for run in detector_runs:
        md.append(f"### `{run['detector_id']}` {run['version']} ({run['status']})")
        md.append("")
        if not run["findings"]:
            md.append("- No candidate emitted in the analyzed lexical scope.")
        for finding in run["findings"]:
            md.append(
                f"- `{finding['file']}:{finding['line']}:{finding['column']}` "
                f"`{finding['rule_id']}` `{finding['candidate_cwe']}` "
                f"{finding['message']}"
            )
        md.append("")
    md.extend(["## Limitations", ""])
    md.extend("- " + item for item in report["limitations"])
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return {
        "component": component,
        "repository": repository,
        "commit": commit,
        "git_tree": tree,
        "snapshot_sha256": report["snapshot_sha256"],
        "candidate_count": len(findings),
        "candidate_groups": report["candidate_groups"],
        "validated_vulnerability": 0,
        "wall_seconds": wall,
        "selected_source_files": inventory["selected_source_files"],
        "selected_source_bytes": inventory["selected_source_bytes"],
        "scope_manifest_sha256": report["scope_manifest_sha256"],
        "source_acquisition": report["source_acquisition"],
        "unsafe_detector_before_after": report["unsafe_detector_before_after"],
        "json": str(json_path),
        "markdown": str(md_path),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--components", nargs="*", default=list(DEFAULT_COMPONENTS))
    parser.add_argument("--source-roots-json", type=Path, required=True,
                        help="JSON map of component names to local Git object stores")
    args = parser.parse_args(argv)
    source_roots = json.loads(args.source_roots_json.read_text(encoding="utf-8"))
    baseline_detector_type, baseline_hashes = _load_baseline_unsafe_detector()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for component in args.components:
        manifest_path = args.manifest_dir / f"{component}.manifest.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        rows.append(_run_component(manifest_path, args.out_dir, source_roots, baseline_detector_type, baseline_hashes))
    summary = {
        "schema_version": 1,
        "experiment_kind": "a_memory_safety_pinned_component_summary",
        "status": "completed_with_limitations",
        "components": rows,
        "totals": {
            "components": len(rows),
            "candidate_count": sum(item["candidate_count"] for item in rows),
            "candidate_groups": sum(item["candidate_groups"] for item in rows),
            "validated_vulnerability": 0,
            "eligible_for_metrics": False,
            "wall_seconds": sum(item["wall_seconds"] for item in rows),
            "selected_source_files": sum(item["selected_source_files"] for item in rows),
            "selected_source_bytes": sum(item["selected_source_bytes"] for item in rows),
            "process_peak_rss_kib": None,
        },
        "exact_argv": list(sys.argv),
        "unsafe_detector_baseline": {
            "commit": BASELINE_COMMIT,
            "source_sha256": baseline_hashes["unsafe_memory_call_detector"],
            "dependency_source_sha256": baseline_hashes["memory_safety"],
        },
        "environment": environment_fingerprint(),
        "limitations": [
            "Candidate counts are not vulnerability counts and groups are not confirmed root causes.",
            "Precision/Recall are not computed without an independent reliable labelled holdout.",
            "The source repositories are pre-fixed local OpenHarmony Git objects; no remote acquisition was performed.",
        ],
    }
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# A memory-safety pinned component summary", "",
        "> Candidate-only; `validated_vulnerability=0`; no Precision/Recall claim.", "",
        "| Component | Files | Bytes | Candidates | Groups | Wall s | Commit |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for item in rows:
        lines.append(
            f"| `{item['component']}` | {item['selected_source_files']} | "
            f"{item['selected_source_bytes']} | {item['candidate_count']} | "
            f"{item['candidate_groups']} | {item['wall_seconds']:.3f} | `{item['commit']}` |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend("- " + item for item in summary["limitations"])
    (args.out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

