"""Freeze a D41 cross-component source-only holdout before executing the scanner."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from d19_unreviewed_replay import pinned_source_paths

ENGINE_PATHS = (
    "src/ohscanner/detectors/data/sensitive_exposure.py",
    "src/ohscanner/detectors/data/models.py",
    "src/ohscanner/execution.py",
    "src/ohscanner/runner.py",
    "src/ohscanner/git_source.py",
    "src/ohscanner/indexing.py",
    "requirements.txt",
    "requirements-web.txt",
)
REPOSITORIES = (
    ("openharmony/security_huks", "gitcode", "security_huks", "4ae4e0db461f137672719d43ffc6c5b1b6c05be8"),
    ("openharmony/security_certificate_manager", "gitcode", "security_certificate_manager", "5fcc0b6379567a70176307c281360be2ba281d6b"),
    ("openharmony/inputmethod_imf", "perf", "inputmethod_imf", "7777cba9eb19085af8e7b90088531028d2937460"),
    ("openharmony/window_window_manager", "perf", "window_window_manager", "8b0d8fe1b973d865904c942c286b3d2a3b9b08e7"),
    ("openharmony/telephony_call_manager", "perf", "telephony_call_manager", "6638d1b37f278d7ed380d907674820e7467cedf8"),
    ("openharmony/multimedia_camera_framework", "perf", "multimedia_camera_framework", "085a5d0e2dc1c90a4b676bad55675a1cf12a6380"),
)
BASELINE_COMMIT = "efb79ee2397396f38bb0df5d4703f55d7977f138"


def git(repo: Path, *args: str, binary: bool = False):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=not binary).strip() if not binary else subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitcode-corpus-root", type=Path, required=True)
    parser.add_argument("--perf-corpus-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    checkout = Path(__file__).resolve().parents[2]
    baseline = git(checkout, "rev-parse", "--verify", BASELINE_COMMIT + "^{commit}")
    engine = []
    bundle = hashlib.sha256()
    for rel in ENGINE_PATHS:
        worktree_bytes = (checkout / rel).read_bytes()
        baseline_bytes = git(checkout, "show", baseline + ":" + rel, binary=True)
        if worktree_bytes != baseline_bytes:
            raise SystemExit("detector/runtime source differs from baseline: " + rel)
        digest = hashlib.sha256(worktree_bytes).hexdigest()
        engine.append({"path": rel, "sha256": digest})
        bundle.update(rel.encode("utf-8") + b"\0" + bytes.fromhex(digest))

    repos = []
    for name, root_kind, directory, requested_commit in REPOSITORIES:
        root = args.gitcode_corpus_root if root_kind == "gitcode" else args.perf_corpus_root
        source_repo = (root / directory).resolve(strict=True)
        if git(source_repo, "status", "--porcelain"):
            raise SystemExit("source checkout is dirty; refusing preregistration: " + name)
        commit = git(source_repo, "rev-parse", "--verify", requested_commit + "^{commit}")
        tree = git(source_repo, "rev-parse", commit + "^{tree}")
        paths = pinned_source_paths(source_repo, commit)
        if len(paths) > 2000:
            raise SystemExit("scope exceeds per-run limit: " + name)
        remote = git(source_repo, "remote", "get-url", "origin")
        committed_at = git(source_repo, "show", "-s", "--format=%cI", commit)
        repos.append({
            "repository": name,
            "source_alias": root_kind + "-corpus/" + directory,
            "origin_identity": remote,
            "commit": commit,
            "tree": tree,
            "commit_time": committed_at,
            "checkout_clean_at_freeze": True,
            "eligible_source_files": len(paths),
            "scope_paths_sha256": hashlib.sha256("\n".join(paths).encode("utf-8")).hexdigest(),
            "profile_status": "unreviewed_source_profile",
            "label_status": "pending_independent_blind_review",
        })

    manifest = {
        "schema": 1,
        "study": "D41 cross-component sensitive-data exposure holdout",
        "study_status": "preregistered_not_run",
        "freeze_date": "2026-10-19",
        "detector_baseline_commit": baseline,
        "detector_id": "ohscanner.data.sensitive_exposure",
        "detector_version": "0.17.0",
        "source_model_version": "0.4.0",
        "source_profile_catalog_version": "0.1.0",
        "sink_model_version": "0.7.0",
        "engine_bundle_sha256": bundle.hexdigest(),
        "engine_files": engine,
        "selection_policy": {
            "selection_before_scanning": True,
            "exclude_development_profiles_and_fixtures": [
                "openharmony/communication_dsoftbus",
                "openharmony/security_access_token",
                "openharmony/communication_iot_connect",
                "openharmony/communication_wifi",
                "all existing D1-D40 replay repositories and fixtures",
            ],
            "scope": "all eligible C/C++ source paths from pinned Git trees using D19 source-path policy",
            "repeat_count": 2,
            "replay_comparison": "candidate identities, coverage, source binding, detector status",
        },
        "label_protocol": {
            "independent_labeler_required": True,
            "labels": ["supported_risk", "protected_safe", "unrelated", "unknown"],
            "current_independent_labels": 0,
            "do_not_use_machine_candidate_count_as_TP_FP_FN": True,
            "do_not_promote_to_confirmed": True,
        },
        "repositories": repos,
        "limitations": [
            "This preregistration is not a holdout result; no detector run has been performed by this script.",
            "Local Git source identity is commit/tree/blob based; origin names remain declared repository metadata.",
            "No product build, runtime log visibility, unauthorized reader, or product impact is evaluated here.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "study_status": manifest["study_status"],
        "detector_baseline_commit": baseline,
        "engine_bundle_sha256": manifest["engine_bundle_sha256"],
        "repositories": len(repos),
        "source_files": sum(item["eligible_source_files"] for item in repos),
        "independent_labels": 0,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())