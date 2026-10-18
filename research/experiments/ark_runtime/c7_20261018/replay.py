"""Reproduce the frozen Ark Runtime 0.7.0 historical source comparison.

This script only consumes an existing local Git object database. It never
fetches, substitutes a checkout file, or creates source fixtures.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
from pathlib import Path

from src.ohscanner.detectors.ark_runtime.unseen_detector import (
    ArkRuntimeUnseenTypeSafetyDetector,
)
from src.ohscanner.detectors.ark_runtime.unseen_model import UnseenRuntimeTypeModel
from src.ohscanner.detectors.ark_runtime.model import DETECTOR_ID
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.facts import build_syntax_facts
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.ark_runtime.syntax import parse_functions


TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
FREEZE_COMMIT = "a2fce96f98ffbb968c04ac69e19a7da24032d368"
FREEZE_TREE = "a9eba411bcbb0e9dc940f2abe4f4e96f454007c4"
MODEL_DIGEST = "548996ced072b847e2a01d17c4f56de11b6fe4e42e3657f1434c7b8fbc9f3aca"

# Values were recovered from the OpenHarmony GitHub repository API and written
# as Git objects after checking the recorded commit/tree/blob SHA-1s and source
# SHA-256s. These are known development inputs, not a holdout roster.
SAMPLES = (
    {
        "sample_id": "c1_type_origin_parent",
        "role": "development_vulnerable_parent",
        "expectation": "C1 historical type-origin case; development expectation only",
        "commit": "830e85b40240677039719fcbf14f721ad3b19050",
        "tree": "579712c1ebbb703d17cea422b1572023bed5d8a4",
        "parent": ["0f5024602bd29681dedb70f5bb3832c79870c4ce", "01652f9b256fdbc58ab256be45117ec0578b7961"],
        "blob": "054451b1be4f39254d56a1683cc9d1c1b5e55018",
        "source_sha256": "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422",
        "bytes": 150433,
        "pair": "c1_type_origin",
    },
    {
        "sample_id": "c1_type_origin_fix",
        "role": "development_fixed_control",
        "expectation": "C1 patch endpoint; fixed only for the documented patch behavior",
        "commit": "a0e30483ab3e4aead67ecfb5c708489915e447f9",
        "tree": "82af11ced4297818410ccf61906b703d25b69165",
        "parent": ["830e85b40240677039719fcbf14f721ad3b19050"],
        "blob": "95f54f2875f401afe3167c62f8c1e7799782be8c",
        "source_sha256": "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e",
        "bytes": 150509,
        "pair": "c1_type_origin",
    },
    {
        "sample_id": "c2_exception_guard_parent",
        "role": "development_vulnerable_parent",
        "expectation": "C2 historical allocation/exception-path case; development expectation only",
        "commit": "c758818dbfd0b146a908d43d21f6ca1706c33783",
        "tree": "5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a",
        "parent": ["952188685663d5024954269269979ef4f34174b2", "bf8c27dc8f2bfb5652f02221f06528072424be33"],
        "blob": "857ad416bc102fcd5d462e9702d2ba7c51f29b6d",
        "source_sha256": "984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9",
        "bytes": 152202,
        "pair": "c2_exception_guard",
    },
    {
        "sample_id": "c2_exception_guard_fix",
        "role": "development_fixed_control",
        "expectation": "C2 patch endpoint; fixed only for the documented patch behavior",
        "commit": "81ca57487d04ea30cd11c271e86494a4e130f43e",
        "tree": "f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5",
        "parent": ["c758818dbfd0b146a908d43d21f6ca1706c33783"],
        "blob": "3b9de9d915d767d7a67316145451da2446162884",
        "source_sha256": "4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0",
        "bytes": 152910,
        "pair": "c2_exception_guard",
    },
    {
        "sample_id": "unrelated_rename_control",
        "role": "previously_exposed_unrelated_patch_control",
        "expectation": "Historical spelling-only change; label remains unknown and excluded from holdout",
        "commit": "95554c2ee75b35d556640eb6f2591d429796f60e",
        "tree": "65728158c365a0100db906bfca1cedf3ee3f5ebf",
        "parent": ["1ff0b7c7e257085834c3f16c7ab145d60bc2aee0"],
        "blob": "e652d5e5ef1cec7176527f4d04023a8060abb5e9",
        "source_sha256": "db7856c17f46d4a6c9ac1e5114e72504c5487ace4cc92d70eacb8deaeb190fb4",
        "bytes": 153164,
        "pair": None,
    },
)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parser_version(name: str) -> str:
    return importlib.metadata.version(name)


def verify_bindings(repo: Path) -> list[dict]:
    verified = []
    for sample in SAMPLES:
        commit = sample["commit"]
        commit_raw = git(repo, "cat-file", "commit", commit)
        headers = commit_raw.split(b"\n\n", 1)[0].decode("utf-8", errors="strict").splitlines()
        actual_tree = next(line[5:] for line in headers if line.startswith("tree "))
        parents = [line[7:] for line in headers if line.startswith("parent ")]
        entry = git(repo, "ls-tree", "--full-tree", commit, "--", TARGET).decode().strip()
        parts = entry.split(None, 3)
        if len(parts) != 4 or parts[1] != "blob" or parts[3] != TARGET:
            raise ValueError(f"target_path_not_a_blob:{sample['sample_id']}:{entry}")
        actual_blob = parts[2]
        raw = git(repo, "cat-file", "blob", actual_blob)
        actual_sha = sha256(raw)
        actual_bytes = len(raw)
        checks = {
            "tree": (actual_tree, sample["tree"]),
            "parents": (parents, sample["parent"]),
            "blob": (actual_blob, sample["blob"]),
            "source_sha256": (actual_sha, sample["source_sha256"]),
            "bytes": (actual_bytes, sample["bytes"]),
        }
        mismatches = {key: {"actual": a, "expected": e} for key, (a, e) in checks.items() if a != e}
        if mismatches:
            raise ValueError(f"source_binding_mismatch:{sample['sample_id']}:{mismatches}")
        verified.append({
            **sample,
            "path": TARGET,
            "git_tree_verified": actual_tree,
            "git_parents_verified": parents,
            "git_blob_verified": actual_blob,
            "source_sha256_verified": actual_sha,
            "source_bytes_verified": actual_bytes,
            "provenance": "local_git_object_database; exact OIDs and raw bytes verified",
        })
    return verified


def run(repo: Path, output: Path, scanner_root: Path) -> dict:
    expected_files = {
        "src/ohscanner/detectors/catalog.py": "ed718983a54a2ecebc2ed30725e134f9bc34abb38f34bf3f078ce542705584e5",
        "src/ohscanner/detectors/ark_runtime/unseen_detector.py": "50dfc9979daf244c3e8d66c6ad3ee405b75e36e2ef2195ae9f551bf06de13fd0",
        "src/ohscanner/detectors/ark_runtime/unseen_model.py": "32c603b18f71a31f7c845145456f9182ba9d0872afa61b0a446d6cbf22f75495",
        "src/ohscanner/detectors/ark_runtime/model.py": "1c2fa93762f19a9ceb6f17999ba74c447203367d6cb107e130d846b81cd7404e",
        "src/ohscanner/detectors/ark_runtime/analysis.py": "4fd9f375725ca7039beb2fe428f176ebe360299ce1f9e105ab4235e80875853d",
        "src/ohscanner/detectors/ark_runtime/exception_guard.py": "3bb959a1164d43b44bbe0e20a79193d55907278ea83da8b85490bbf2c409437c",
        "src/ohscanner/detectors/ark_runtime/runtime_ir.py": "f3c2c85f086e223cb5897150f7d1e6890bf568599a287c1a6fe6e5411c2a39ca",
        "src/ohscanner/detectors/ark_runtime/syntax.py": "c3616ad6404967927d1a4a98c46257f8df19c3c36990efbae82c859f5108bcf9",
        "src/ohscanner/detectors/ark_runtime/type_origin.py": "5ff1ffacbf80f175b75979e6a49cdba4ba70e34bc4736e5d4c48402fb67a3073",
        "src/parser/ast.py": "eabb4aff1b613661cb37f9f8d7bb50c6c2b5a4fb28cb55fbd452aa5179ec5eb0",
        "src/ohscanner/contracts.py": "18b2fe2a2a3da5e5e7d31381ff45c84be28469e2f88bb8aae03f5e77883bd494",
        "src/ohscanner/runner.py": "372967bfdb266b057ba8e797602cebdd25beeaee750a860a25f8cb510f6c9dac",
        "requirements.txt": "d640566eb055a3844d62caa6314a0900f94e7766e5a619c364e4dca6aa69bb2f",
        "tests/detectors/ark_runtime/test_unseen_detector.py": "45bedd53b784d6f196532ba1bc7af1360b20a759fb56cae741e6614319b0c88a",
    }
    actual_files = {p: sha256((scanner_root / p).read_bytes()) for p in expected_files}
    mismatches = {p: {"actual": actual_files[p], "expected": expected_files[p]}
                  for p in expected_files if actual_files[p] != expected_files[p]}
    if mismatches:
        raise ValueError(f"frozen_scanner_files_mismatch:{mismatches}")
    bindings = verify_bindings(repo)
    model = UnseenRuntimeTypeModel()
    if model.digest != MODEL_DIGEST:
        raise ValueError(f"model_digest_mismatch:{model.digest}")
    registry = DetectorRegistry()
    registry.register(ArkRuntimeUnseenTypeSafetyDetector(model=model))

    rows = []
    inventory_probe = None
    for binding in bindings:
        commit = binding["commit"]
        ingestion_mode = "full_pinned_git_source_loader"
        inventory_error = None
        try:
            context, _tree, _inventory, _initial_coverage, _sources = prepare_git_context(
                repo, model.source_repository, commit, (TARGET,)
            )
        except ValueError as exc:
            # The recovered subset has exact commit/tree/path/blob objects but
            # lacks unrelated subtrees needed for a full repository inventory.
            # Keep the declared one-file scope and use the same shared indexer
            # and Runner over the already verified exact target blob.
            inventory_error = str(exc)
            ingestion_mode = "verified_target_blob_scoped_context"
            data = git(repo, "cat-file", "blob", binding["blob"])
            source = GitSource(TARGET, "cpp", binding["blob"], data)
            units, ast, source_coverage = index_sources((source,))
            digest = snapshot_digest(units)
            context = ScanContext(
                request=ScanRequest(
                    request_id="git-index:" + commit[:12] + ":" + digest[:12],
                    repository=model.source_repository,
                    commit=commit,
                    snapshot_sha256=digest,
                    target_id="current-component:" + model.source_repository,
                    profile_id="light-ast",
                    provenance="git_object",
                ),
                units=units,
                shared_facts={
                    "ast": ast,
                    "source_blob_oid": {TARGET: binding["blob"]},
                    "facts_v1": build_syntax_facts(ast),
                    "coverage": source_coverage,
                },
            )
        if inventory_probe is None:
            inventory_probe = {
                "status": "blocked" if inventory_error else "available",
                "mode_used_for_samples": ingestion_mode,
                "reason": inventory_error,
                "scope": [TARGET],
            }
        reports, coverage = run_all_with_coverage(context, registry)
        report = reports[0]
        detector_coverage = coverage["detectors"][DETECTOR_ID]
        unit = context.units[0]
        _, functions = parse_functions(unit.text.encode("utf-8"))
        names = set(model.callers) | set(model.exception_guard_callers)
        targets = sorted({fn.qualified_name for fn in functions if fn.qualified_name in names})
        if context.request.commit != commit:
            raise ValueError(f"runner_source_identity_mismatch:{binding['sample_id']}")
        rows.append({
            **binding,
            "snapshot_sha256": context.request.snapshot_sha256,
            "source_inventory_mode": ingestion_mode,
            "source_inventory_blocker": inventory_error,
            "profile_id": context.request.profile_id,
            "detector_id": report.tool,
            "detector_version": report.tool_version,
            "model_version": model.version,
            "model_digest_sha256": model.digest,
            "run_status": report.status,
            "file_outcomes": [
                {"path": item["file"], "analysis_status": item["analysis_status"],
                 "parse_status": item["status"], "reason": item["analysis_reason"]}
                for item in report.parsing
            ],
            "parser_status": unit.parse_status,
            "parser_issues": [json.loads(issue) if isinstance(issue, str) else issue
                              for issue in unit.parse_issues],
            "resolved_semantic_targets": targets,
            "diagnostics": [finding.to_dict() for finding in report.diagnostics],
            "candidate_count": len(report.diagnostics),
            "coverage": detector_coverage,
            "limitations": list(report.limitations),
            "holdout_eligible": False,
        })

    pair_diffs = {}
    for parent, fixed, pair in (
        (SAMPLES[0]["commit"], SAMPLES[1]["commit"], "c1_type_origin"),
        (SAMPLES[2]["commit"], SAMPLES[3]["commit"], "c2_exception_guard"),
    ):
        diff = git(repo, "diff", "--no-ext-diff", "--unified=0", parent, fixed, "--", TARGET)
        lines = diff.decode("utf-8", errors="replace").splitlines()
        pair_diffs[pair] = {
            "parent_commit": parent,
            "fixed_commit": fixed,
            "path": TARGET,
            "patch_sha256": sha256(diff),
            "added_lines": sum(line.startswith("+") and not line.startswith("+++") for line in lines),
            "removed_lines": sum(line.startswith("-") and not line.startswith("---") for line in lines),
            "hunks": [line for line in lines if line.startswith("@@")],
            "patch": lines,
        }

    output.mkdir(parents=True, exist_ok=False)
    payload = {
        "experiment": "Ark Runtime 0.7.0 frozen semantic contract historical development replay",
        "freeze": {
            "detector_id": DETECTOR_ID,
            "detector_version": model.version,
            "scanner_commit": FREEZE_COMMIT,
            "scanner_tree": FREEZE_TREE,
            "model_digest_sha256": model.digest,
            "profile_id": "light-ast",
            "scope_paths": [TARGET],
            "source_independent_applicability": True,
            "preprocessing": "none; macro expansion disabled",
            "build_profile": "assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified",
            "toolchain": {
                "python": platform.python_version(),
                "git": subprocess.check_output(["git", "--version"]).decode().strip(),
                "tree-sitter": parser_version("tree-sitter"),
                "tree-sitter-c": parser_version("tree-sitter-c"),
                "tree-sitter-cpp": parser_version("tree-sitter-cpp"),
            },
            "frozen_implementation_sha256": actual_files,
        },
        "source_repository": {
            "declared_repository": model.source_repository,
            "local_object_database": str(repo.resolve()),
            "object_recovery_note": "Original GitHub API recovery metadata and source bytes are recorded in the prior C-line recovery packet; every object and raw source binding was rechecked before execution.",
            "full_tree_inventory_probe": inventory_probe,
            "scope_boundary": "Only the exact target path was analyzed. No whole-repository inventory or coverage claim is made.",
        },
        "samples": rows,
        "pair_diffs": pair_diffs,
        "safe_control": {
            "status": "blocked_unavailable",
            "reason": "C1/C2 deliverables provide developer fixtures and fixed endpoints but no separately sourced and independently reviewed safe historical source revision. Developer fixtures are excluded by the task; fixed endpoints remain fixed controls, not broad safe labels.",
        },
        "scoring": {
            "holdout_samples": 0,
            "developer_control_samples": len(rows),
            "precision": None,
            "recall": None,
            "reason": "All historical inputs are known C1/C2 development or previously exposed controls; there are no independent labels/reviewer declarations. No metric is estimated.",
        },
        "semantic_profile_review": {
            "contract_id": "ark-runtime-semantic-applicability-v1",
            "contract_sha256": "4e98f891a71534d4554cfff5c2b1d72dfa28d126602340acf7afc8f5603abfa7",
            "C1_rule_expectation": "Filter type-origin parent should retain a partial candidate if the destination and type-token origins diverge; the fixed endpoint should remove that specific candidate.",
            "C2_rule_expectation": "Filter/Map allocation exception parents should retain candidates where the allocation result is read before pending-exception handling; fixed endpoints should remove those specific candidates.",
            "unresolved": [
                "C1/C2 operation semantics originate in development work and were not independently revalidated against all changed helper implementations.",
                "The frozen model has no bound semantic helper/dependency source list; full header, macro, type, and build context is unavailable.",
                "The assumed build profile is not verified against an OpenHarmony product build.",
                "All relevant sources parse as partial or may remain unanalysed; no result is a safe/miss verdict.",
            ],
        },
    }
    (output / "manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True, help="Local Git object database with exact historical objects")
    parser.add_argument("--scanner-root", type=Path, required=True, help="Clean archive extracted from the 0.7.0 freeze commit")
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    payload = run(args.repo_dir, args.output, args.scanner_root)
    print(json.dumps({
        "manifest": str((args.output / "manifest.json").resolve()),
        "freeze": payload["freeze"],
        "samples": [{"id": row["sample_id"], "role": row["role"],
                     "parse": row["parser_status"], "status": row["run_status"],
                     "outcomes": row["file_outcomes"], "candidates": row["candidate_count"]}
                    for row in payload["samples"]],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
