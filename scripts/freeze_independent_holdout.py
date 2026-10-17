from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.holdout import canonical_digest, verify_freeze, write_freeze_files


SPECS = (
    ("HOLDOUT-NULL-01", "cpp.null_dereference", "communication_dsoftbus", "d272051eb605be1c17655da57439598bf545f1ce", "CWE-476"),
    ("HOLDOUT-NULL-02", "cpp.null_dereference", "communication_dsoftbus", "8b0ef63ef1f591e86255ea0bf9d9c1083dfa39c2", "CWE-476"),
    ("HOLDOUT-NULL-03", "cpp.null_dereference", "communication_dsoftbus", "783a1dd8dacc9ccded5189069b56221902c074bd", "CWE-476"),
    ("HOLDOUT-NULL-04", "cpp.null_dereference", "communication_dsoftbus", "13570b766f728793b51ec83693293acc998438f0", "CWE-476"),
    ("HOLDOUT-NULL-05", "cpp.null_dereference", "arkcompiler_ets_runtime", "e8dc367f6dddde646424f84dce6f32210e408afd", "CWE-476"),
    ("HOLDOUT-UAF-01", "cpp.lifetime_uaf", "communication_dsoftbus", "393f0a734cc968ecd405fbebe2610f0562fda2cb", "CWE-416"),
    ("HOLDOUT-UAF-02", "cpp.lifetime_uaf", "communication_dsoftbus", "34fb261bcbf27fdbbdc87ba6346b1b84fc540069", "CWE-416"),
    ("HOLDOUT-UAF-03", "cpp.lifetime_uaf", "communication_dsoftbus", "05c5dfec907eafc8314192863d4fd2526831f4ec", "CWE-416"),
    ("HOLDOUT-UAF-04", "cpp.lifetime_uaf", "communication_dsoftbus", "a3bf544e1fbb8052cb3c1ce1997acbc5ed7bd4ab", "CWE-416"),
    ("HOLDOUT-UAF-05", "cpp.lifetime_uaf", "arkcompiler_ets_runtime", "2540d999ab23a37b3681e1ff5ad30ffd9890754f", "CWE-416"),
    ("HOLDOUT-RES-01", "cpp.resource_lifetime", "communication_dsoftbus", "c1dfba0022330b96267ce5fee75cc7d4dabbc6b1", "CWE-401"),
    ("HOLDOUT-RES-02", "cpp.resource_lifetime", "communication_dsoftbus", "f4b069d1f3cecc82fe08563080057ed6db45fd0e", "CWE-401"),
    ("HOLDOUT-RES-03", "cpp.resource_lifetime", "communication_dsoftbus", "e5bb84a5709a4dcc80249a6b2f79256ce5a2e0b5", "CWE-772"),
    ("HOLDOUT-RES-04", "cpp.resource_lifetime", "communication_dsoftbus", "0c057c8351113841e691bf7f4cf10c106405b8c1", "CWE-415"),
    ("HOLDOUT-RES-05", "cpp.resource_lifetime", "communication_dsoftbus", "9e5cf8e7c9ade887d576402151ba9fadd9e08b1e", "CWE-415"),
    ("HOLDOUT-BOUNDS-01", "cpp.bounds", "arkcompiler_ets_runtime", "e338dbe3a2a83e5131cd1252749b0db321b6a2da", "CWE-787"),
    ("HOLDOUT-BOUNDS-02", "cpp.bounds", "arkcompiler_ets_runtime", "466e8099c860a81d4155d666403773b01d1007b2", "CWE-787"),
    ("HOLDOUT-BOUNDS-03", "cpp.bounds", "arkcompiler_ets_runtime", "00206c93e988b4ae32f7982a5061383a1e8c530f", "CWE-125"),
    ("HOLDOUT-BOUNDS-04", "cpp.bounds", "distributeddatamgr_kv_store", "c9a4847d70b41e4d35f0da1786874784ca5a6c3b", "CWE-787"),
    ("HOLDOUT-BOUNDS-05", "cpp.bounds", "distributeddatamgr_kv_store", "a3ec506867acda22acac92e654c3e27a6c3c1d07", "CWE-787"),
    ("HOLDOUT-INT-01", "cpp.integer_bounds", "arkcompiler_ets_runtime", "dfe612a32cb73bf4b28769347f7ddd30d5e0a44b", "CWE-190"),
    ("HOLDOUT-INT-02", "cpp.integer_bounds", "commonlibrary_c_utils", "502d434b084dbf725d6849384e81e2854dff034f", "CWE-190"),
    ("HOLDOUT-INT-03", "cpp.integer_bounds", "arkcompiler_ets_runtime", "6a832492054e8a6e7aec45fd8dfde3ebe4109185", "CWE-190"),
    ("HOLDOUT-INT-04", "cpp.integer_bounds", "arkcompiler_ets_runtime", "191aab2aedd9f2e82037dae4335d367db46d7635", "CWE-190"),
    ("HOLDOUT-INT-05", "cpp.integer_bounds", "commonlibrary_c_utils", "a265735fe983f88a56e5034eed2d3815d890b9e8", "CWE-190"),
    ("HOLDOUT-UNSAFE-01", "cpp.unsafe_memory_call", "communication_dsoftbus", "098e7bbf24a77646cc55e1bc9f1503c85de72a99", "CWE-120"),
    ("HOLDOUT-UNSAFE-02", "cpp.unsafe_memory_call", "communication_dsoftbus", "2da9eb080c0865fbedb8a83624bf6acd49bbf9c0", "CWE-120"),
    ("HOLDOUT-UNSAFE-03", "cpp.unsafe_memory_call", "communication_dsoftbus", "2cfd3192cfda2c8f1bbe3af421bec10b7226a37c", "CWE-120"),
    ("HOLDOUT-UNSAFE-04", "cpp.unsafe_memory_call", "communication_dsoftbus", "2c6909b8c807448e58f6816020da7f430f503f25", "CWE-120"),
    ("HOLDOUT-UNSAFE-05", "cpp.unsafe_memory_call", "commonlibrary_c_utils", "d79caeff7f3cffc86e11a57d6706cdf82909a750", "CWE-120"),
)

DETECTOR_BY_FAMILY = {
    "cpp.null_dereference": "ohscanner.cpp.null_dereference",
    "cpp.lifetime_uaf": "ohscanner.cpp.lifetime",
    "cpp.resource_lifetime": "ohscanner.cpp.resource_lifetime",
    "cpp.bounds": "ohscanner.cpp.bounds",
    "cpp.integer_bounds": "ohscanner.cpp.integer_bounds",
    "cpp.unsafe_memory_call": "ohscanner.cpp.unsafe_memory_call",
}

FETCHED_BLOBS: set[tuple[str, str]] = set()
BLOB_ACQUISITION: list[dict[str, str]] = []

LANGUAGE_BY_SUFFIX = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
}

TRIGGER = {
    "cpp.null_dereference": "Reach the changed C/C++ function on a path where the pre-fix null condition is dereferenced.",
    "cpp.lifetime_uaf": "Trigger the pre-fix owner destruction/reset while the changed alias or task handle remains live.",
    "cpp.resource_lifetime": "Follow the changed allocation/error/cleanup path that the public fix makes leak- or double-release-free.",
    "cpp.bounds": "Supply the index, length or serialization input that reaches the changed access with the pre-fix insufficient bound condition.",
    "cpp.integer_bounds": "Supply arithmetic, length or index input that triggers the overflow/narrowing condition addressed by the public fix.",
    "cpp.unsafe_memory_call": "Reach the changed copy/string operation with the input, size or return condition addressed by the public fix.",
}


def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, check=False, timeout=60,
    )
    if result.returncode:
        raise ValueError("git " + " ".join(args[:2]) + " failed: " + result.stderr.decode("utf-8", "replace")[:500])
    return result.stdout


def has_object(repo: Path, oid: str) -> bool:
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo),
         "cat-file", "-e", oid],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env=offline_environment(), check=False, timeout=30,
    )
    return result.returncode == 0


def offline_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env


def git_blob_oid(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\\x00"
    return hashlib.sha1(header + data).hexdigest()


def ensure_blob(repo: Path, oid: str, revision: str, path: str) -> bytes:
    if not has_object(repo, oid):
        repo_name = repo.name
        encoded_path = quote(path, safe="/")
        raw_urls = (
            "https://gitee.com/openharmony/" + repo_name + "/raw/" + revision + "/" + encoded_path,
            "https://gitcode.com/openharmony/" + repo_name + "/raw/" + revision + "/" + encoded_path,
            "https://raw.githubusercontent.com/openharmony/" + repo_name + "/" + revision + "/" + encoded_path,
        )
        errors = []
        acquired = False
        for url in raw_urls:
            try:
                fetched_raw = subprocess.run(
                    ["curl", "-fsSL", "--connect-timeout", "15", "--max-time", "120", "--retry", "5", "--retry-all-errors", "--retry-delay", "2", url],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=135,
                )
                if fetched_raw.returncode:
                    errors.append(url + ": " + fetched_raw.stderr.decode("utf-8", "replace")[:160])
                    continue
                raw = fetched_raw.stdout
                observed = subprocess.run(
                    ["git", "hash-object", "--stdin"], input=raw,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30,
                )
                if observed.returncode or observed.stdout.decode().strip() != oid:
                    errors.append(url + ": content digest mismatch")
                    continue
                written = subprocess.run(
                    ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                    input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30,
                )
                if written.returncode or written.stdout.decode().strip() != oid:
                    errors.append(url + ": exact object import failed")
                    continue
                FETCHED_BLOBS.add((str(repo), oid))
                BLOB_ACQUISITION.append({
                    "repository_root_key": repo.name,
                    "revision": revision,
                    "path": path,
                    "blob_oid": oid,
                    "source_url": url,
                    "verification": "git blob SHA-1 exact match and hash-object -w import",
                })
                acquired = True
                break
            except Exception as exc:
                errors.append(url + ": " + type(exc).__name__ + ": " + str(exc)[:160])
        if not acquired:
            fetch_env = os.environ.copy()
            fetch_env.update({
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
            })
            configured = set(git(repo, "remote").decode("utf-8", "replace").split())
            for remote in ("origin", "gitcode", "gitee"):
                if remote not in configured:
                    continue
                try:
                    fetched = subprocess.run(
                        ["git", "-C", str(repo), "fetch", "--no-filter", remote, oid],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env=fetch_env, check=False, timeout=60,
                    )
                except subprocess.TimeoutExpired:
                    errors.append(remote + ": explicit fetch timeout")
                    continue
                if fetched.returncode == 0 and has_object(repo, oid):
                    FETCHED_BLOBS.add((str(repo), oid))
                    BLOB_ACQUISITION.append({
                        "repository_root_key": repo.name,
                        "revision": revision,
                        "path": path,
                        "blob_oid": oid,
                        "source_url": remote + ":" + oid,
                        "verification": "exact Git object fetched by OID",
                    })
                    acquired = True
                    break
                errors.append(remote + ": " + fetched.stderr.decode("utf-8", "replace")[:160])
        if not acquired:
            raise ValueError("explicit exact-blob acquisition failed for " + oid + "; " + " | ".join(errors))
    return git(repo, "cat-file", "blob", oid)


def blob_identity(repo: Path, revision: str, path: str) -> dict[str, Any]:
    oid = git(repo, "rev-parse", revision + ":" + path).decode().strip()
    raw = ensure_blob(repo, oid, revision, path)
    return {
        "path": path,
        "blob_oid": oid,
        "git_object_type": "blob",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "lines": len(raw.splitlines()),
        "language": LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower(), "not_source"),
    }


def source_at(repo: Path, revision: str, path: str) -> bytes:
    oid = git(repo, "rev-parse", revision + ":" + path).decode().strip()
    return ensure_blob(repo, oid, revision, path)


def changed_source_paths(repo: Path, parent: str, commit: str) -> tuple[list[str], list[str]]:
    raw = git(repo, "diff", "--no-renames", "--name-status", "-z", parent, commit)
    parts = raw.split(b"\x00")
    source, ignored = [], []
    for index in range(0, len(parts) - 1, 2):
        status_raw = parts[index].decode("ascii")
        path = parts[index + 1].decode("utf-8")
        status = status_raw.split("\t", 1)[0]
        source_path = Path(path).suffix.lower() in LANGUAGE_BY_SUFFIX
        test_like = any(part.lower() in {"test", "tests", "unittest", "unittests", "mock", "mocks", "fuzztest", "fuzz"} for part in Path(path).parts)
        if status != "M":
            if source_path and not test_like:
                raise ValueError("holdout production source must be modified in place without renames: " + status + " " + path)
            ignored.append(path)
            continue
        test_like = any(part.lower() in {"test", "tests", "unittest", "unittests", "mock", "mocks", "fuzztest", "fuzz"} for part in Path(path).parts)
        if Path(path).suffix.lower() in LANGUAGE_BY_SUFFIX and not test_like:
            source.append(path)
        else:
            ignored.append(path)
    if not source:
        raise ValueError("holdout fix has no modified C/C++ source: " + commit)
    return sorted(source), sorted(ignored)


def stable_patch_id(repo: Path, commit: str, paths: list[str]) -> str:
    parent = git(repo, "rev-parse", commit + "^").decode().strip()
    patch = git(repo, "diff", "--no-ext-diff", "--no-renames", "--binary", parent, commit, "--", *paths)
    output = subprocess.run(
        ["git", "patch-id", "--stable"], input=patch,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if output.returncode:
        raise ValueError("git patch-id failed: " + output.stderr.decode("utf-8", "replace")[:300])
    fields = output.stdout.decode().split()
    if len(fields) != 2 or len(fields[0]) != 40:
        raise ValueError("invalid stable patch-id output")
    return fields[0]


def license_identity(repo: Path, revision: str) -> dict[str, Any]:
    names = git(repo, "ls-tree", "--name-only", revision).decode("utf-8", "replace").splitlines()
    for name in ("LICENSE", "LICENSE.txt", "COPYING", "COPYING.txt"):
        if name in names:
            row = blob_identity(repo, revision, name)
            return {
                "declared_license": "Apache-2.0",
                "license_path": name,
                "license_blob_oid": row["blob_oid"],
                "license_sha256": row["source_sha256"],
                "basis": "repository root license file",
            }
    raise ValueError("repository has no recognized root license file")


def evidence_fields(family: str, paths: list[str]) -> dict[str, str]:
    scope = ", ".join(paths)
    return {
        "entry": "Changed C/C++ units: " + scope + ". Actual product entry and caller permission boundary remain unknown.",
        "attacker_control": "Unknown; the official fix proves a code-defect boundary but does not establish attacker-controlled input or product privileges.",
        "trigger": TRIGGER[family],
        "repair": "The public official commit fixes the vulnerable parent; exact source/blob and stable patch identity are frozen in this manifest.",
        "limitations": "Official fix-labelled code defect only. No claim of product exploitability, reachability, CIA impact, CVE assignment, or fixed-product deployment.",
    }


def parse_roots(values: list[str]) -> dict[str, Path]:
    roots = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--repo-root requires key=path")
        key, raw = value.split("=", 1)
        path = Path(raw).resolve()
        if not path.is_dir() or path.is_symlink():
            raise ValueError("invalid repository root: " + raw)
        roots[key] = path
    return roots


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--frozen-at", required=True)
    args = parser.parse_args()
    roots = parse_roots(args.repo_root)
    detector_registry = build_registry(tuple(DETECTOR_BY_FAMILY.values()))
    detector_versions = {
        detector.detector_id: detector.version for detector in detector_registry.detectors()
    }
    cases = []
    for root_cause_id, family, repository, commit, cwe in SPECS:
        root_key = repository
        if root_key not in roots:
            raise ValueError("missing repository root mapping for " + root_key)
        print("freeze-case", root_cause_id, repository, commit, flush=True)
        repo = roots[root_key]
        resolved = git(repo, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
        if resolved != commit:
            raise ValueError("commit resolution drift for " + commit)
        parents = git(repo, "rev-list", "--parents", "-n", "1", commit).decode().split()
        if len(parents) != 2:
            raise ValueError("holdout fix must be a non-merge commit: " + commit)
        parent = parents[1]
        fix_tree = git(repo, "rev-parse", commit + "^{tree}").decode().strip()
        parent_tree = git(repo, "rev-parse", parent + "^{tree}").decode().strip()
        paths, ignored_paths = changed_source_paths(repo, parent, commit)
        source = []
        for path in paths:
            fixed = blob_identity(repo, commit, path)
            vulnerable = blob_identity(repo, parent, path)
            source_at(repo, commit, path).decode("utf-8")
            source_at(repo, parent, path).decode("utf-8")
            source.append((path, vulnerable, fixed))
        metadata = git(repo, "show", "-s", "--format=%H%x00%aI%x00%cI%x00%s%x00%b", commit).split(b"\x00")
        if len(metadata) < 5:
            raise ValueError("invalid commit metadata for " + commit)
        subject = metadata[3].decode("utf-8", "replace")
        body = metadata[4].decode("utf-8", "replace").strip()
        evidence = evidence_fields(family, paths)
        case = {
            "root_cause_id": root_cause_id,
            "family": family,
            "detector_id": DETECTOR_BY_FAMILY[family],
            "detector_version": detector_versions[DETECTOR_BY_FAMILY[family]],
            "repository": "openharmony/" + repository,
            "repository_root_key": root_key,
            "fix_commit": commit,
            "vulnerable_parent": parent,
            "fix_tree": fix_tree,
            "vulnerable_tree": parent_tree,
            "stable_patch_id": stable_patch_id(repo, commit, paths),
            "stable_patch_scope": "modified non-test C/C++ source paths only; test and non-source files are excluded from holdout analysis scope",
            "commit_metadata": {
                "author_time": metadata[1].decode(),
                "committer_time": metadata[2].decode(),
                "subject": subject,
                "body": body,
            },
            "official_reference": "https://gitcode.com/openharmony/" + repository + "/commit/" + commit,
            "mirror_references": {
                "gitee": "https://gitee.com/openharmony/" + repository + "/commit/" + commit,
                "github": "https://github.com/openharmony/" + repository + "/commit/" + commit,
            },
            "cwe": cwe,
            "cve_id": None,
            "cve_status": "not_assigned_or_not_located; no CVE is inferred from the fix",
            "entry": evidence["entry"],
            "attacker_control": evidence["attacker_control"],
            "trigger": evidence["trigger"],
            "repair": evidence["repair"],
            "limitations": evidence["limitations"],
            "ignored_non_source_paths": ignored_paths,
            "license": license_identity(repo, commit),
            "vulnerable": {
                "sample_id": root_cause_id + ":vulnerable",
                "category": "vulnerable",
                "commit": parent,
                "tree": parent_tree,
                "files": [row for _, row, _ in source],
            },
            "fixed": {
                "sample_id": root_cause_id + ":fixed",
                "category": "fixed",
                "commit": commit,
                "tree": fix_tree,
                "files": [row for _, _, row in source],
            },
        }
        cases.append(case)

    selection = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-selection.v1",
        "selection_policy": {
            "frozen_before_detector_tuning": True,
            "root_cause_unit": "distinct official public fix commit with unique stable patch-id",
            "excluded_tuning_samples": [
                "CVE-2025-23420", "CVE-2025-0587",
                "commonlibrary_c_utils shared_ptr tuning sample",
                "communication_dsoftbus null tuning sample",
            ],
        },
        "cases": [
            {"root_cause_id": item[0], "family": item[1], "repository": item[2],
             "repository_root_key": item[2], "fix_commit": item[3], "cwe": item[4],
             "cve_id": None}
            for item in SPECS
        ],
    }
    manifest = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout.v1",
        "created_at": args.frozen_at,
        "eligible_for_metrics": True,
        "truth_independence": "official-public-fix-labels",
        "truth_scope": "developer-acknowledged code defect in official public source history",
        "detector_tuning_after_freeze": False,
        "family_min_root_causes": 5,
        "selection_sha256": canonical_digest(selection),
        "detector_bindings": [
            {"family": family, "detector_id": detector, "version": detector_versions[detector]}
            for family, detector in sorted(DETECTOR_BY_FAMILY.items())
        ],
        "explicit_blob_prefetch": [{"repository_root_key": Path(repo).name, "blob_oid": oid} for repo, oid in sorted(FETCHED_BLOBS)],
        "verified_raw_blob_acquisition": sorted(BLOB_ACQUISITION, key=lambda row: (row["repository_root_key"], row["path"], row["revision"])),
        "source_repository_policy": {
            "reads": "local pinned Git objects only",
            "network": "disabled",
            "lazy_fetch": "disabled; missing exact source blobs are explicitly fetched by OID before the offline freeze/scan",
            "external_source_size": "not copied into this repository",
        },
        "metric_semantics": {
            "sample_level": "vulnerable+detected=TP, vulnerable+not_detected=FN, fixed+detected=FP, fixed+not_detected=TN",
            "unknown": "blocked/failed/partial/unexecuted is unable-to-analyze and excluded, never a miss",
            "family_publication": "publish only families with at least five independent root causes",
            "security_claim": "metrics measure fix-labelled defect detection, not exploitability or CIA impact",
        },
        "root_causes": cases,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "selection.json").write_text(
        json.dumps(selection, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    verify_freeze(manifest)
    freeze = write_freeze_files(manifest, args.output_dir)
    print(json.dumps(freeze, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
