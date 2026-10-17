from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


PR_HEADS = {
    8: "86fbf9951967aaab879d24748a8231744d6977aa",
    9: "d443f11bff917d475e4b1e3e92a0c1cbc2637a58",
    10: "aa79d57a3612c0bc5a04dac7af03c2a086dcddd8",
    11: "54a4d980766ca9b8f2e3aaeccf3420bd98700399",
    12: "7e6ff537f23c1adde6cb82859e714d4025e0d375",
    13: "09d79b14bfa0d242932037076e8cbd22a0de53d1",
    14: "dcac1dccf205269e772ccac0df910007bf22ad9b",
}

TARGET_TEST = re.compile(
    r"^tests/(?:test_ipc_[^/]+|test_owner_ipc_platform|test_cross_ab_parcel_case)\.py$"
)


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if result.returncode:
        raise ValueError("git " + " ".join(args[:2]) + " failed: "
                         + result.stderr.decode("utf-8", "replace")[:300])
    return result.stdout


def selected(path: str) -> str | None:
    if path.startswith("analysis/"):
        return "analysis"
    if path.startswith("index/"):
        return "index"
    if path.startswith("models/"):
        return "models"
    if path.startswith("src/ohscanner/detectors/interface/"):
        return "interface_source"
    if path.startswith("tests/fixtures/ipc/"):
        return "fixtures"
    if TARGET_TEST.fullmatch(path):
        return "tests"
    return None


def tree_rows(repo: Path, commit: str) -> dict[str, str]:
    rows = {}
    raw = git(repo, "ls-tree", "-r", "-z", commit)
    for item in raw.split(b"\x00"):
        if not item:
            continue
        metadata, path_raw = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        if kind == "blob":
            rows[path_raw.decode("utf-8")] = oid
    return rows


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--work-dir", type=Path, default=Path("work/ipc-20261017"))
    parser.add_argument("--evidence", type=Path,
                        default=Path("research/evidence/platform/ipc_external_input_recovery_20261017.json"))
    args = parser.parse_args()
    repo = args.repo.resolve()
    head = git(repo, "rev-parse", "HEAD").decode().strip()
    source_refs = {}
    observations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pr, expected in sorted(PR_HEADS.items()):
        ref = "refs/remotes/origin/pr/" + str(pr)
        resolved = git(repo, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
        if resolved != expected:
            raise ValueError("PR " + str(pr) + " ref drift")
        source_refs[str(pr)] = {
            "ref": ref,
            "head": resolved,
            "github_ref": "refs/pull/" + str(pr) + "/head",
        }
        rows = tree_rows(repo, resolved)
        for path, blob in rows.items():
            category = selected(path)
            if category is None:
                continue
            observations[path].append({
                "pr": pr,
                "commit": resolved,
                "blob_oid": blob,
                "category": category,
            })
    head_rows = tree_rows(repo, head)
    entries = []
    for path in sorted(observations):
        source = observations[path]
        current = head_rows.get(path)
        statuses = []
        if current is None:
            statuses.append("not_present_in_current_head")
        elif any(row["blob_oid"] == current for row in source):
            statuses.append("exact_source_blob_present_in_current_head")
        else:
            statuses.append("current_head_modified_after_recovery")
        entries.append({
            "path": path,
            "category": source[0]["category"],
            "source_observations": source,
            "first_observed_pr": min(row["pr"] for row in source),
            "target_head": head,
            "target_blob_oid": current,
            "status": statuses[0],
        })
    counts = Counter(row["status"] for row in entries)
    category_counts = Counter(row["category"] for row in entries)
    required = {"analysis", "index", "models", "fixtures", "tests"}
    missing_categories = sorted(required - set(category_counts))
    manifest = {
        "schema_version": 1,
        "kind": "ohscanner.ipc-external-input-recovery.v1",
        "recovered_work_id": "work/ipc-20261017",
        "repository": {
            "remote": "https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git",
            "target_head": head,
        },
        "source_refs": source_refs,
        "recovery_method": (
            "Exact GitHub refs/pull/8/head through refs/pull/14/head were fetched "
            "without checkout. Every selected analysis/index/models/interface/fixtures/tests "
            "blob is enumerated and compared with current HEAD; no source is synthesized."
        ),
        "migration_semantics": {
            "exact_source_blob_present_in_current_head":
                "Recovered external input is already migrated byte-for-byte; no duplicate copy is created.",
            "current_head_modified_after_recovery":
                "Recovered source is present but later reviewed changes exist; source and target blobs remain separately bound.",
            "not_present_in_current_head":
                "External source exists in a PR ref but is not migrated and remains a fail-closed gap.",
        },
        "counts": {
            "entries": len(entries),
            "statuses": dict(sorted(counts.items())),
            "categories": dict(sorted(category_counts.items())),
            "missing_required_categories": missing_categories,
        },
        "entries": entries,
        "limitations": (
            "PR refs prove repository-local external input provenance only. They do "
            "not prove authorship, product deployment, runtime reachability or security impact."
        ),
    }
    manifest["canonical_content_digest"] = canonical_digest({
        key: value for key, value in manifest.items() if key != "canonical_content_digest"
    })
    args.work_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.work_dir / "recovery-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    index = {
        "schema_version": 1,
        "kind": "ohscanner.ipc-external-input-migration-index.v1",
        "recovery_manifest_sha256": hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest(),
        "categories": {
            category: [
                {
                    "path": row["path"],
                    "source_blob_oid": row["source_observations"][0]["blob_oid"],
                    "target_blob_oid": row["target_blob_oid"],
                    "status": row["status"],
                }
                for row in entries if row["category"] == category
            ]
            for category in sorted(category_counts)
        },
    }
    (args.work_dir / "migration-index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(
        json.dumps({
            "schema_version": 1,
            "kind": "ohscanner.ipc-external-input-recovery-evidence.v1",
            "recovery_manifest": str(manifest_path).replace("\\", "/"),
            "recovery_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "canonical_content_digest": manifest["canonical_content_digest"],
            "counts": manifest["counts"],
        }, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
