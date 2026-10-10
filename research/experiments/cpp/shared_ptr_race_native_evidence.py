"""Pinned real-source evidence runner for ``ohscanner.cpp.shared_ptr_race``.

This experiment reads exact source blobs from a local Git repository, verifies
the public repository identity, pinned commit/tree/blob bindings, and source
SHA-256 values against a separately pinned binding manifest, parses the selected
source with the existing C/C++ frontend, runs the detector, and produces
separate vulnerable/fixed review records.

It does not accept arbitrary exported files as ``git_object`` evidence, execute
external scanners, fetch code, run a sanitizer, or commit third-party source
bytes. A manifest hash is an integrity binding to independently trusted data,
not an authentication mechanism.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    SharedPtrRaceDetector,
)
from src.ohscanner.detectors.cpp.shared_ptr_race_review import (
    build_shared_ptr_race_review_evidence,
    verify_review_evidence,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import (
    load_git_sources,
    verify_repository_identity,
)
from src.parser.ast import parse_source


REPOSITORY = "openharmony/commonlibrary_c_utils"
SOURCE_PATH = "base/include/singleton.h"
DETECTOR = SharedPtrRaceDetector()
_COMMIT_RE = re.compile(r"[a-f0-9]{40}")
_OID_RE = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_REVISIONS = ("vulnerable", "fixed")
_BINDING_FIELDS = {"commit", "git_tree", "blob_oid", "source_sha256"}


@dataclass(frozen=True)
class PinnedUnit:
    unit: SourceUnit
    git_tree: str
    blob_oid: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def binding_manifest_sha256(binding_manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(binding_manifest).encode("utf-8")).hexdigest()


def _parse_status(source_text: str) -> Tuple[str, Tuple[str, ...]]:
    index = parse_source(source_text, language="cpp")
    return index.parse_status, tuple(
        json.dumps(item, sort_keys=True) for item in index.parse_issues
    )


def load_pinned_unit(
    repo_root: Path,
    repository: str,
    commit: str,
    source_repo_path: str,
) -> PinnedUnit:
    verify_repository_identity(repo_root, repository)
    pinned_commit, git_tree, sources, _inventory = load_git_sources(
        repo_root,
        commit,
        includes=(source_repo_path,),
    )
    if pinned_commit != commit:
        raise ValueError("source commit must match the pinned full SHA")
    if len(sources) != 1 or sources[0].path != source_repo_path:
        raise ValueError("exact pinned source path was not found in the Git tree")
    source = sources[0]
    raw = source.data
    text = raw.decode("utf-8")
    parse_status, parse_issues = _parse_status(text)
    unit = SourceUnit(
        path=source_repo_path,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(raw).hexdigest(),
        parse_status=parse_status,
        parse_issues=parse_issues,
    )
    return PinnedUnit(unit=unit, git_tree=git_tree, blob_oid=source.oid)


def validate_binding_manifest(
    binding_manifest: Mapping[str, Any],
    binding_manifest_sha256_value: str,
    repository: str,
    source_repo_path: str,
) -> Mapping[str, Mapping[str, str]]:
    if not isinstance(binding_manifest, Mapping):
        raise ValueError("source binding manifest must be an object")
    if binding_manifest_sha256_value != binding_manifest_sha256(binding_manifest):
        raise ValueError("source binding manifest hash mismatch")
    if binding_manifest.get("schema_version") != 1:
        raise ValueError("unsupported source binding manifest schema")
    if binding_manifest.get("repository") != repository:
        raise ValueError("source binding manifest repository mismatch")
    if binding_manifest.get("source_path") != source_repo_path:
        raise ValueError("source binding manifest source path mismatch")
    revisions = binding_manifest.get("revisions")
    if not isinstance(revisions, Mapping) or set(revisions) != set(_REVISIONS):
        raise ValueError("source binding manifest must bind vulnerable and fixed")
    validated: Dict[str, Mapping[str, str]] = {}
    for revision in _REVISIONS:
        item = revisions[revision]
        if not isinstance(item, Mapping) or set(item) != _BINDING_FIELDS:
            raise ValueError(f"source binding fields are invalid for {revision}")
        if not isinstance(item["commit"], str) or not _COMMIT_RE.fullmatch(item["commit"]):
            raise ValueError(f"source binding commit is invalid for {revision}")
        for field in ("git_tree", "blob_oid"):
            if not isinstance(item[field], str) or not _OID_RE.fullmatch(item[field]):
                raise ValueError(f"source binding {field} is invalid for {revision}")
        if not isinstance(item["source_sha256"], str) or not _SHA256_RE.fullmatch(
            item["source_sha256"]
        ):
            raise ValueError(f"source binding source hash is invalid for {revision}")
        validated[revision] = item
    if validated["vulnerable"]["commit"] == validated["fixed"]["commit"]:
        raise ValueError("vulnerable and fixed commits must differ")
    return validated


def _fixture_manifest_for(
    pinned: PinnedUnit,
    repository: str,
    commit: str,
    category: str,
) -> Tuple[Mapping[str, Any], str]:
    manifest = {
        "schema_version": 1,
        "provenance": {
            "kind": "local_git_objects",
            "repository": repository,
            "commit": commit,
            "git_tree": pinned.git_tree,
            "source_path": pinned.unit.path,
            "blob_oid": pinned.blob_oid,
        },
        "units": [
            {
                "path": pinned.unit.path,
                "sha256": pinned.unit.sha256,
                "parse_status": pinned.unit.parse_status,
                "parse_issues": list(pinned.unit.parse_issues),
                "fixture_category": category,
                "language": pinned.unit.language,
            }
        ],
    }
    return manifest, binding_manifest_sha256(manifest)


def build_evidence_record(
    repo_root: Path,
    repository: str,
    revision: str,
    source_repo_path: str,
    revision_binding: Mapping[str, str],
) -> Dict[str, Any]:
    commit = revision_binding["commit"]
    pinned = load_pinned_unit(repo_root, repository, commit, source_repo_path)
    actual = {
        "commit": commit,
        "git_tree": pinned.git_tree,
        "blob_oid": pinned.blob_oid,
        "source_sha256": pinned.unit.sha256,
    }
    if actual != revision_binding:
        raise ValueError(f"pinned Git source does not match {revision} binding")
    request = ScanRequest(
        request_id=f"shared-ptr-race-native:{revision}:{commit[:12]}",
        repository=repository,
        commit=commit,
        snapshot_sha256=snapshot_digest((pinned.unit,)),
        target_id="current-component:" + repository,
        profile_id="light-ast",
        provenance="git_object",
    )
    context = ScanContext(request=request, units=(pinned.unit,))
    run = DETECTOR.detect(context, context.units)
    category = "vulnerable" if revision == "vulnerable" else "fixed"
    manifest, manifest_sha256 = _fixture_manifest_for(
        pinned, repository, commit, category
    )
    evidence = build_shared_ptr_race_review_evidence(
        context,
        run,
        manifest,
        manifest_sha256,
    )
    verify_review_evidence(evidence, context, run, manifest, manifest_sha256)
    return evidence


def build(
    repo_root: Path,
    binding_manifest: Mapping[str, Any],
    binding_manifest_sha256_value: str,
    repository: str = REPOSITORY,
    source_repo_path: str = SOURCE_PATH,
) -> Tuple[str, str]:
    revisions = validate_binding_manifest(
        binding_manifest,
        binding_manifest_sha256_value,
        repository,
        source_repo_path,
    )
    vulnerable = build_evidence_record(
        repo_root,
        repository,
        "vulnerable",
        source_repo_path,
        revisions["vulnerable"],
    )
    fixed = build_evidence_record(
        repo_root,
        repository,
        "fixed",
        source_repo_path,
        revisions["fixed"],
    )
    evidence = {
        "schema_version": 1,
        "package_id": "teammate-a-shared-ptr-race-native-evidence",
        "source_binding_manifest_sha256": binding_manifest_sha256_value,
        "interpretation": (
            "Separate vulnerable/fixed source-bound detector evidence. No vulnerability "
            "verdict, no Precision/Recall, no dynamic evidence is inferred by this script."
        ),
        "records": [vulnerable, fixed],
    }
    evidence_text = json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
    md = [
        "# SharedPtrRace native pinned-source evidence",
        "",
        "> Static candidate evidence only; not a vulnerability verdict.",
        "",
        f"- Source binding manifest SHA-256: `{binding_manifest_sha256_value}`",
        "",
    ]
    for record in evidence["records"]:
        req = record["request"]
        artifact = record["source_artifacts"][0]
        md.extend(
            [
                f"## {record['evidence_class']}",
                "",
                f"- Repository origin-verified: `{req['repository']}`",
                f"- Commit: `{req['commit']}`",
                f"- Git tree: `{artifact['git_tree']}`",
                f"- Blob OID: `{artifact['git_blob_oid']}`",
                f"- File: `{artifact['path']}`",
                f"- Source SHA-256: `{artifact['sha256']}`",
                f"- Run status: `{record['scope']['run_status']}`",
                f"- Finding bindings: **{len(record['finding_bindings'])}**",
                "",
            ]
        )
    return evidence_text, "\n".join(md) + "\n"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--binding-manifest", required=True, type=Path)
    parser.add_argument("--binding-sha256", required=True)
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--source-path", default=SOURCE_PATH)
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--md-out", required=True, type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare existing outputs with the deterministic reconstruction",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        binding_manifest = json.loads(
            args.binding_manifest.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("source binding manifest is unreadable") from error
    evidence_text, markdown_text = build(
        repo_root=args.repo_root,
        binding_manifest=binding_manifest,
        binding_manifest_sha256_value=args.binding_sha256,
        repository=args.repository,
        source_repo_path=args.source_path,
    )
    if args.check:
        if not args.json_out.exists() or args.json_out.read_text(encoding="utf-8") != evidence_text:
            raise SystemExit("shared_ptr_race native evidence JSON mismatch")
        if not args.md_out.exists() or args.md_out.read_text(encoding="utf-8") != markdown_text:
            raise SystemExit("shared_ptr_race native evidence Markdown mismatch")
        print("[OK] shared_ptr_race native evidence outputs match")
        return 0
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.md_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(evidence_text, encoding="utf-8")
    args.md_out.write_text(markdown_text, encoding="utf-8")
    print(f"[OK] wrote {args.json_out} and {args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
