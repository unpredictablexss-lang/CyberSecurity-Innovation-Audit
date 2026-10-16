"""Additive cross-version impact evidence packaging.

The package separates detector observation relations from impact assessment.
A disappeared candidate is never treated as a fix without exact patch and
revalidation evidence. The module reads fixed local Git objects and existing
scan artifacts; it never fetches or checks out historical revisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from .identity import build_identity_record, compare_findings, line_byte_range


MANIFEST_SCHEMA = "ohscanner.cross-version-comparison-manifest.v1"
PACKAGE_SCHEMA = "ohscanner.cross-version-impact-evidence.v1"
ARTIFACT_SCHEMA = "ohscanner.cross-version-artifact-manifest.v1"
RELATION_VALUES = ("added", "persistent", "disappeared", "unknown")
IMPACT_VALUES = ("affected", "fixed", "not_present", "unknown")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_GIT_OID = re.compile(r"[a-f0-9]{40}|[a-f0-9]{64}")
_REQUIRED_EVIDENCE_ROLES = {
    "affected": {"source", "patch", "call_path"},
    "fixed": {"source", "patch", "call_path", "revalidation"},
    "not_present": {"tree_absence"},
}


def _external_ast_fingerprint(
    source_text: str,
    diagnostic: Mapping[str, Any],
    symbol_identity: str,
) -> str:
    line = ""
    line_number = diagnostic.get("line")
    if isinstance(line_number, int) and 1 <= line_number <= len(source_text.splitlines()):
        line = source_text.splitlines()[line_number - 1]
    if "atomic_load" in line and "instance_" in line:
        role = "atomic_read"
    elif "atomic_store" in line and "instance_" in line:
        role = "atomic_write"
    elif re.search(r"\breturn\s+instance_\b", line):
        role = "return_operand"
    elif re.search(r"\bif\s*\(.*instance_", line):
        role = "condition_operand"
    elif re.search(r"instance_\s*=", line):
        role = "assignment_rhs"
    elif "reset" in line and "instance_" in line:
        role = "reset"
    else:
        role = "lexically_unclassified"
    basis = "|".join((
        "ohscanner.cpp.shared_ptr-race-ast-fingerprint.v1",
        symbol_identity,
        role,
    ))
    return "ohast:v1:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()


def enrich_diagnostic_identity(
    diagnostic: Mapping[str, Any],
    *,
    repository: str,
    commit: str,
    snapshot_sha256: str,
    profile_id: str,
    source_blob_oid: str,
    source_text: str,
    rule_version: str,
    rule_lineage_id: str,
    symbol_identity: str | None = None,
    ast_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Add a source-bound stable identity projection without changing detector code.

    The detector contract remains untouched. This additive projection is used by
    cross-version evidence runs where the production detector intentionally emits
    legacy diagnostics but the comparison requires stable Finding identity.
    """
    item = dict(diagnostic)
    symbol = symbol_identity or str(item.get("symbol") or "")
    if not symbol:
        raise ValueError("symbol_identity is required for identity projection")
    fingerprint = ast_fingerprint or _external_ast_fingerprint(
        source_text,
        item,
        symbol,
    )
    byte_start, byte_end = line_byte_range(source_text, int(item["line"]))
    if byte_start is None or byte_end is None:
        raise ValueError("diagnostic line cannot be source-bound")
    observation = {
        "repository": repository,
        "commit": commit,
        "snapshot_sha256": snapshot_sha256,
        "profile_id": profile_id,
        "legacy_diagnostic_id": item.get("diagnostic_id"),
        "detector_id": item.get("provider"),
        "detector_version": item.get("tool_version"),
        "rule_id": item.get("rule_id"),
        "rule_version": rule_version,
        "rule_lineage_id": rule_lineage_id,
        "file": item.get("file"),
        "line": item.get("line"),
        "message": item.get("message"),
        "source_blob_oid": source_blob_oid,
        "source_sha256": item.get("source_sha256"),
        "byte_start": byte_start,
        "byte_end": byte_end,
        "symbol_identity": symbol,
        "ast_fingerprint": fingerprint,
        "identity_quality": "complete",
    }
    record = build_identity_record(observation)
    if record["stable"]["status"] != "stable" or record["occurrence"]["status"] != "stable":
        raise ValueError("identity projection did not produce complete stable identities")
    item.update({
        "rule_version": rule_version,
        "rule_lineage_id": rule_lineage_id,
        "symbol_identity": symbol,
        "ast_fingerprint": fingerprint,
        "identity_quality": "complete",
        "finding_identity_id": record["stable"]["id"],
        "occurrence_id": record["occurrence"]["id"],
        "finding_identity": record,
    })
    return item


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _git(repo: Path, *args: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError("local Git object verification failed: " + detail[:1000])
    return process.stdout


def _git_text(repo: Path, *args: str) -> str:
    return _git(repo, *args).decode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON payload must be an object: " + str(path))
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _verify_artifact(
    artifact: Mapping[str, Any],
    base: Path,
    *,
    role: str | None = None,
) -> dict[str, Any]:
    _require(isinstance(artifact, Mapping), "artifact entry must be an object")
    path_value = artifact.get("path")
    digest = artifact.get("sha256")
    _require(isinstance(path_value, str) and path_value, "artifact path is required")
    _require(
        isinstance(digest, str) and bool(_SHA256.fullmatch(digest)),
        "artifact SHA-256 is invalid: " + path_value,
    )
    path = (base / path_value).resolve()
    _require(path.is_file(), "artifact is missing: " + path_value)
    actual = _sha256_file(path)
    _require(actual == digest, "artifact hash mismatch: " + path_value)
    result = dict(artifact)
    result["role"] = role or artifact.get("role") or "evidence"
    result["bytes"] = path.stat().st_size
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = _load_json(Path(path))
    _require(manifest.get("kind") == MANIFEST_SCHEMA, "unsupported comparison manifest kind")
    _require(manifest.get("schema_version") == 1, "unsupported comparison manifest schema")
    _require(bool(manifest.get("repository")), "repository is required")
    _require(isinstance(manifest.get("versions"), list) and manifest["versions"], "versions are required")
    _require(isinstance(manifest.get("candidates"), list) and manifest["candidates"], "candidates are required")
    return manifest


def _manifest_artifacts(manifest: Mapping[str, Any], base: Path) -> list[dict[str, Any]]:
    raw = manifest.get("artifacts", [])
    _require(isinstance(raw, list), "artifacts must be a list")
    return [_verify_artifact(item, base) for item in raw]


def _ls_tree_blob(repo: Path, commit: str, source_path: str) -> str | None:
    raw = _git(repo, "ls-tree", "-z", commit, "--", source_path)
    entries = [item for item in raw.split(b"\x00") if item]
    if not entries:
        return None
    _require(len(entries) == 1, "source path is ambiguous in Git tree")
    metadata, _path = entries[0].split(b"\t", 1)
    fields = metadata.split()
    _require(len(fields) == 3 and fields[1] == b"blob", "source path is not a Git blob")
    return fields[2].decode("ascii")


def verify_git_versions(
    repo: Path,
    manifest: Mapping[str, Any],
) -> list[dict[str, Any]]:
    repo = Path(repo).resolve()
    _require(repo.is_dir() and not repo.is_symlink(), "repo-dir must be a real directory")
    source_path = manifest["scope"]["source_path"]
    verified: list[dict[str, Any]] = []
    for row in manifest["versions"]:
        _require(isinstance(row, Mapping), "version row must be an object")
        ref = row.get("ref")
        commit = row.get("commit")
        tree = row.get("tree")
        _require(isinstance(ref, str) and ref and not ref.startswith("-"), "version ref is invalid")
        _require(isinstance(commit, str) and bool(_GIT_OID.fullmatch(commit)), "commit is invalid")
        _require(isinstance(tree, str) and bool(_GIT_OID.fullmatch(tree)), "tree is invalid")
        resolved = _git_text(repo, "rev-parse", "--verify", ref + "^{commit}").strip()
        _require(resolved == commit, "ref/commit mismatch: " + ref)
        actual_tree = _git_text(repo, "rev-parse", "--verify", commit + "^{tree}").strip()
        _require(actual_tree == tree, "commit/tree mismatch: " + commit)
        blob = _ls_tree_blob(repo, commit, source_path)
        expected_blob = row.get("source_blob_oid")
        _require(blob == expected_blob, "source blob mismatch: " + ref)
        if blob is None:
            source_sha = None
        else:
            source_sha = _sha256_bytes(_git(repo, "cat-file", "blob", blob))
        _require(source_sha == row.get("source_sha256"), "source SHA-256 mismatch: " + ref)
        checked = dict(row)
        checked["verified_commit"] = resolved
        checked["verified_tree"] = actual_tree
        checked["verified_source_blob_oid"] = blob
        checked["verified_source_sha256"] = source_sha
        verified.append(checked)
    return verified


def _coverage(report: Mapping[str, Any], detector_id: str) -> str:
    info = report.get("detector_coverage", {}).get("detectors", {}).get(detector_id, {})
    run = next(
        (item for item in report.get("detector_runs", []) if item.get("tool") == detector_id),
        {},
    )
    status = info.get("status") if isinstance(info, Mapping) else None
    if run.get("status") == "completed" and status == "complete":
        return "complete"
    return str(status or "unknown")


def _diagnostics(report: Mapping[str, Any], detector_id: str) -> list[Mapping[str, Any]]:
    run = next(
        (item for item in report.get("detector_runs", []) if item.get("tool") == detector_id),
        None,
    )
    if not isinstance(run, Mapping):
        return []
    return [item for item in run.get("diagnostics", []) if isinstance(item, Mapping)]


def _identity_diagnostics(
    report: Mapping[str, Any],
    detector_id: str,
    identity_ids: Sequence[str],
) -> dict[str, Mapping[str, Any]]:
    wanted = set(identity_ids)
    result: dict[str, Mapping[str, Any]] = {}
    for diagnostic in _diagnostics(report, detector_id):
        identity_id = diagnostic.get("finding_identity_id")
        if identity_id in wanted:
            _require(identity_id not in result, "duplicate stable identity in one report")
            result[identity_id] = diagnostic
    return result


def _raw_relation(value: str) -> str:
    if value.startswith("persistent_"):
        return "persistent"
    if value == "observation_added_comparable":
        return "added"
    if value == "observation_absent_comparable":
        return "disappeared"
    return "unknown"


def candidate_observation_relation(
    previous_present: bool,
    current_present: bool,
    *,
    comparable: bool,
    first_row: bool,
) -> tuple[str, list[str]]:
    if first_row:
        return "unknown", ["no_previous_comparison_row"]
    if not comparable:
        return "unknown", ["comparison_not_comparable"]
    if previous_present and current_present:
        return "persistent", []
    if not previous_present and current_present:
        return "added", []
    if previous_present and not current_present:
        return "disappeared", []
    return "unknown", ["no_observation_on_either_side"]


def assess_impact(
    requested_status: str,
    evidence: Sequence[Mapping[str, Any]],
    *,
    source_present: bool,
    boundary_support: str | None = None,
) -> tuple[str, list[str]]:
    """Fail closed: only evidence-backed affected/fixed/not_present is published."""
    if requested_status not in IMPACT_VALUES:
        return "unknown", ["invalid_requested_status"]
    roles = {
        str(item.get("role"))
        for item in evidence
        if isinstance(item, Mapping) and item.get("verified") is True
    }
    if requested_status == "affected":
        missing = sorted(_REQUIRED_EVIDENCE_ROLES["affected"] - roles)
        return ("affected", []) if not missing else ("unknown", ["missing_evidence:" + item for item in missing])
    if requested_status == "fixed":
        missing = sorted(_REQUIRED_EVIDENCE_ROLES["fixed"] - roles)
        if missing:
            return "unknown", ["missing_evidence:" + item for item in missing]
        if boundary_support != "fixed":
            return "unknown", ["boundary_revalidation_not_fixed"]
        return "fixed", []
    if requested_status == "not_present":
        if source_present:
            return "unknown", ["source_present_cannot_be_not_present"]
        if "tree_absence" not in roles:
            return "unknown", ["missing_evidence:tree_absence"]
        return "not_present", []
    return "unknown", ["explicit_unknown"]


def _validate_report_binding(
    report: Mapping[str, Any],
    version: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    expected = {
        "repository": manifest["repository"],
        "commit": version["commit"],
        "git_tree": version["tree"],
        "snapshot_sha256": version["snapshot_sha256"],
        "profile_id": manifest["profile_id"],
    }
    for key, value in expected.items():
        _require(report.get(key) == value, f"report {key} mismatch for {version['ref']}")
    detector_id = manifest["detector"]["id"]
    detector_version = manifest["detector"]["version"]
    run = next(
        (item for item in report.get("detector_runs", []) if item.get("tool") == detector_id),
        None,
    )
    _require(isinstance(run, Mapping), "detector run is missing: " + version["ref"])
    _require(run.get("tool_version") == detector_version, "detector version mismatch: " + version["ref"])
    _require(
        run.get("rule_id") if "rule_id" in run else manifest["detector"]["rule_id"],
        "detector rule is missing",
    )


def _evidence_index(
    manifest: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    base: Path,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in manifest.get("evidence", []):
        item = _verify_artifact(raw, base)
        key = str(item.get("evidence_id"))
        _require(key and key not in result, "evidence_id must be present and unique")
        item["verified"] = True
        result[key] = item
    return result


def build_package(
    manifest_path: Path,
    repo_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    output = Path(output_dir).resolve()
    base = manifest_path.parent
    manifest = load_manifest(manifest_path)
    input_artifacts = _manifest_artifacts(manifest, base)
    evidence_index = _evidence_index(manifest, input_artifacts, base)
    versions = verify_git_versions(Path(repo_dir), manifest)
    _require(len({row["ref"] for row in versions}) == len(versions), "duplicate version ref")
    _require(
        manifest["version_range"]["topology_note"].startswith("first-parent is only"),
        "first-parent topology limitation is missing",
    )
    detector = manifest["detector"]
    for key in ("id", "version", "rule_id", "rule_version", "rule_lineage_id", "implementation_sha256"):
        _require(bool(detector.get(key)), "detector binding is missing: " + key)
        if key == "implementation_sha256":
            _require(bool(_SHA256.fullmatch(detector[key])), "detector implementation hash is invalid")

    output.mkdir(parents=True, exist_ok=True)
    candidate_packages = []
    for candidate in manifest["candidates"]:
        identity_ids = candidate.get("stable_identity_ids")
        _require(
            isinstance(identity_ids, list)
            and identity_ids
            and len(identity_ids) == len(set(identity_ids))
            and all(isinstance(item, str) and item.startswith("ohfi:v1:") for item in identity_ids),
            "candidate stable identity list is invalid",
        )
        impact_by_blob = candidate.get("impact_by_blob", {})
        _require(isinstance(impact_by_blob, Mapping), "impact_by_blob must be an object")
        rows = []
        previous: dict[str, bool] | None = None
        previous_coverage = "unknown"
        for index, version in enumerate(versions):
            report_path = version.get("report_path")
            report: dict[str, Any] | None = None
            coverage = "complete" if version["source_blob_oid"] is None else "unknown"
            if report_path:
                report = _load_json((base / report_path).resolve())
                _validate_report_binding(report, version, manifest)
                coverage = _coverage(report, detector["id"])
            elif version["source_blob_oid"] is not None:
                raise ValueError("source-present version requires a scan report: " + version["ref"])

            current = {identity_id: False for identity_id in identity_ids}
            diagnostics: dict[str, Any] = {}
            if report is not None:
                matched = _identity_diagnostics(report, detector["id"], identity_ids)
                diagnostics = dict(matched)
                for identity_id in identity_ids:
                    current[identity_id] = identity_id in matched

            comparable = (
                version["source_blob_oid"] is None
                or coverage == "complete"
            ) and (index == 0 or previous_coverage in ("complete", "not_present"))
            if version.get("comparison_role") == "boundary_regression":
                relation, reasons = (
                    "unknown",
                    ["boundary_regression_not_in_version_matrix_sequence"],
                )
            else:
                relation, reasons = candidate_observation_relation(
                    bool(previous and any(previous.values())),
                    any(current.values()),
                    comparable=comparable,
                    first_row=index == 0,
                )
            identity_rows = []
            raw_rows = []
            if report is not None and index > 0 and previous is not None:
                previous_path = versions[index - 1].get("report_path")
                previous_report = (
                    _load_json((base / previous_path).resolve())
                    if previous_path
                    else {}
                )
                raw_rows = compare_findings(
                    _diagnostics(previous_report, detector["id"]),
                    _diagnostics(report, detector["id"]),
                    before_coverage=previous_coverage,
                    after_coverage=coverage,
                    rule_compatibility="compatible",
                )
            raw_by_identity = {
                item.get("finding_identity_id"): item
                for item in raw_rows
                if isinstance(item, Mapping)
            }
            for identity_id in identity_ids:
                before_present = bool(previous and previous.get(identity_id))
                after_present = current[identity_id]
                if version.get("comparison_role") == "boundary_regression":
                    identity_relation, identity_reasons = (
                        "unknown",
                        ["boundary_regression_not_in_version_matrix_sequence"],
                    )
                else:
                    identity_relation, identity_reasons = candidate_observation_relation(
                        before_present,
                        after_present,
                        comparable=comparable,
                        first_row=index == 0,
                    )
                raw = raw_by_identity.get(identity_id, {})
                identity_rows.append({
                    "finding_identity_id": identity_id,
                    "relation": identity_relation,
                    "raw_relation": raw.get("relation", "not_compared"),
                    "previous_present": before_present if index else None,
                    "current_present": after_present,
                    "diagnostic_id": diagnostics.get(identity_id, {}).get("diagnostic_id"),
                    "occurrence_id": diagnostics.get(identity_id, {}).get("occurrence_id"),
                    "reasons": identity_reasons,
                })

            blob = version["source_blob_oid"]
            requested = "unknown"
            evidence_ids: list[str] = []
            boundary_support = None
            if blob is None:
                requested = "not_present"
                evidence_ids = list(candidate.get("not_present_evidence_ids", []))
            elif blob in impact_by_blob:
                assessment = impact_by_blob[blob]
                requested = assessment.get("status", "unknown")
                evidence_ids = list(assessment.get("evidence_ids", []))
                boundary_support = assessment.get("boundary_support")
            evidence = [evidence_ids_value for evidence_ids_value in (
                evidence_index.get(item) for item in evidence_ids
            ) if evidence_ids_value is not None]
            impact_status, impact_reasons = assess_impact(
                requested,
                evidence,
                source_present=blob is not None,
                boundary_support=boundary_support,
            )
            rows.append({
                "ref": version["ref"],
                "label": version.get("label", version["ref"]),
                "comparison_role": version.get("comparison_role", "version_matrix"),
                "commit": version["commit"],
                "tree": version["tree"],
                "source_path": manifest["scope"]["source_path"],
                "source_blob_oid": blob,
                "source_sha256": version["source_sha256"],
                "snapshot_sha256": version["snapshot_sha256"],
                "profile_id": manifest["profile_id"],
                "detector": {
                    "id": detector["id"],
                    "version": detector["version"],
                    "rule_id": detector["rule_id"],
                    "rule_version": detector["rule_version"],
                    "rule_lineage_id": detector["rule_lineage_id"],
                    "implementation_sha256": detector["implementation_sha256"],
                },
                "coverage": coverage,
                "observation_relation": relation,
                "observation_reasons": reasons,
                "identity_observations": identity_rows,
                "impact_status": impact_status,
                "impact_reasons": impact_reasons,
                "impact_scope": "component_source_candidate_only",
                "product_applicability": "unknown",
                "evidence_ids": evidence_ids,
            })
            previous = current
            previous_coverage = "complete" if blob is None else coverage

        candidate_packages.append({
            "candidate_id": candidate["candidate_id"],
            "candidate_status": "candidate/unassessed",
            "validated_vulnerability": 0,
            "stable_identity_ids": identity_ids,
            "historical_diagnostic_ids": list(candidate.get("historical_diagnostic_ids", [])),
            "historical_ids_preserved": True,
            "versions": rows,
        })

    boundary_raw = manifest.get("boundary_regression")
    boundary = None
    if boundary_raw is not None:
        boundary = _verify_artifact(boundary_raw, base, role="boundary_regression")
        boundary["verified"] = True

    package = {
        "schema_version": 1,
        "kind": PACKAGE_SCHEMA,
        "repository": manifest["repository"],
        "comparison_manifest": {
            "path": manifest_path.name,
            "sha256": _sha256_file(manifest_path),
        },
        "version_range": manifest["version_range"],
        "scope": manifest["scope"],
        "profile_id": manifest["profile_id"],
        "detector": detector,
        "selection_inputs": list(manifest.get("selection_inputs", [])),
        "candidates": candidate_packages,
        "boundary_regression": boundary,
        "validated_vulnerability": 0,
        "limitations": [
            "first-parent is only a topology strategy for selecting a review window; it is not evidence of vulnerability propagation.",
            "Chronological order is not proof of vulnerability introduction order.",
            "A disappeared detector observation is not a fix unless exact source/patch/call-path/revalidation evidence supports fixed.",
            "affected/fixed here describe the selected component source mechanism only; product build applicability, entry/privilege boundary and CIA impact remain unknown.",
            "No historical report, diagnostic ID, review, commit, tree or blob was rewritten.",
        ],
    }

    json_path = output / "impact_evidence.json"
    json_path.write_text(
        json.dumps(package, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown = _render_markdown(package)
    md_path = output / "impact_evidence.md"
    md_path.write_text(markdown, encoding="utf-8")
    artifact_manifest = {
        "schema_version": 1,
        "kind": ARTIFACT_SCHEMA,
        "files": {
            json_path.name: {"sha256": _sha256_file(json_path), "bytes": json_path.stat().st_size},
            md_path.name: {"sha256": _sha256_file(md_path), "bytes": md_path.stat().st_size},
        },
    }
    (output / "artifact_manifest.json").write_text(
        json.dumps(artifact_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return package


def _render_markdown(package: Mapping[str, Any]) -> str:
    lines = [
        "# Cross-version impact evidence package",
        "",
        "> Candidate-level component source evidence. This is not a confirmed/reportable vulnerability.",
        "",
        f"- Repository: `{package['repository']}`",
        f"- Comparison manifest SHA-256: `{package['comparison_manifest']['sha256']}`",
        f"- Detector: `{package['detector']['id']}` `{package['detector']['version']}`",
        f"- Profile: `{package['profile_id']}`",
        f"- Scope: `{package['scope']['source_path']}`",
        f"- Validated vulnerabilities: {package['validated_vulnerability']}",
        "",
        "## Interpretation boundary",
        "",
        "- `added` / `persistent` / `disappeared` / `unknown` describe detector observations between explicit matrix rows.",
        "- `affected` / `fixed` / `not_present` / `unknown` are separate evidence-gated impact states.",
        "- first-parent is only a topology strategy for selecting a review window; it is not evidence of vulnerability propagation.",
        "- Chronological order is not proof of vulnerability introduction order.",
        "",
    ]
    for candidate in package["candidates"]:
        lines.extend([
            f"## Candidate `{candidate['candidate_id']}`",
            "",
            f"- Status: `{candidate['candidate_status']}`",
            f"- Stable Finding identities: {len(candidate['stable_identity_ids'])}",
            "",
            "| Ref / role | Commit | Blob | Observation | Impact | Coverage |",
            "|---|---|---|---|---|---|",
        ])
        for row in candidate["versions"]:
            blob = row["source_blob_oid"] or "absent"
            lines.append(
                f"| `{row['ref']}` | `{row['commit']}` | `{blob}` | "
                f"`{row['observation_relation']}` | `{row['impact_status']}` | `{row['coverage']}` |"
            )
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend("- " + item for item in package["limitations"])
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    package = build_package(args.manifest, args.repo_dir, args.out_dir)
    totals = {
        "candidates": len(package["candidates"]),
        "versions": len(package["candidates"][0]["versions"]) if package["candidates"] else 0,
    }
    print("[OK] cross-version impact evidence package")
    print("[OK] candidates: " + str(totals["candidates"]))
    print("[OK] version rows per candidate: " + str(totals["versions"]))
    print("[OK] JSON: " + str(Path(args.out_dir).resolve() / "impact_evidence.json"))


if __name__ == "__main__":
    main()
