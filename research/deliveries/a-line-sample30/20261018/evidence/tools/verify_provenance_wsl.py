from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

SCANNER_ROOT = Path("/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit")
sys.path.insert(0, str(SCANNER_ROOT))
from src.ohscanner.indexing import prepare_git_context  # noqa: E402


def git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    process = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
        timeout=120,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.decode("utf-8", "replace")[:500])
    return process.stdout


def source_check(source, diagnostic: dict) -> dict:
    data = source.data
    sha = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    line = int(diagnostic["line"])
    line_ok = 1 <= line <= len(lines)
    start = max(1, line - 6)
    end = min(len(lines), line + 6)
    excerpt = "\n".join(f"{index}: {lines[index - 1]}" for index in range(start, end + 1)) if line_ok else ""
    return {
        "diagnostic_id": diagnostic["diagnostic_id"],
        "file": diagnostic["file"],
        "line": line,
        "expected_source_sha256": diagnostic["source_sha256"],
        "actual_source_sha256": sha,
        "source_sha256_matches": sha == diagnostic["source_sha256"],
        "git_blob_oid": source.oid,
        "source_bytes": len(data),
        "line_count": len(lines),
        "line_exists": line_ok,
        "line_text": lines[line - 1] if line_ok else None,
        "excerpt": excerpt,
    }


def main() -> None:
    manifest_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = []
    for record in manifest["records"]:
        repo = Path(record["wsl_repo_dir"])
        commit = record["commit"]
        result = {
            "sample_order": record["sample_order"],
            "repository": record["repository"],
            "repo_dir": str(repo),
            "expected": {
                "commit": record["commit"],
                "git_tree": record["git_tree"],
                "snapshot_sha256": record["snapshot_sha256"],
            },
            "errors": [],
        }
        try:
            resolved = git(repo, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
            tree = git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()
            result["actual"] = {"commit": resolved, "git_tree": tree}
            result["commit_matches"] = resolved == commit
            result["tree_matches"] = tree == record["git_tree"]
            context, computed_tree, inventory, coverage, sources = prepare_git_context(
                repo, record["repository"], commit
            )
            source_map = {source.path: source for source in sources}
            checks = []
            for diagnostic in record["diagnostics"]:
                source = source_map.get(diagnostic["file"])
                if source is None:
                    checks.append({
                        "diagnostic_id": diagnostic["diagnostic_id"],
                        "file": diagnostic["file"],
                        "line": diagnostic["line"],
                        "expected_source_sha256": diagnostic["source_sha256"],
                        "actual_source_sha256": None,
                        "source_sha256_matches": False,
                        "git_blob_oid": None,
                        "source_bytes": None,
                        "line_count": None,
                        "line_exists": False,
                        "line_text": None,
                        "excerpt": "",
                        "error": "source_not_selected_by_snapshot_index",
                    })
                else:
                    checks.append(source_check(source, diagnostic))
            result.update({
                "snapshot_sha256_recomputed": context.request.snapshot_sha256,
                "snapshot_sha256_matches": context.request.snapshot_sha256 == record["snapshot_sha256"],
                "computed_git_tree": computed_tree,
                "inventory": inventory,
                "coverage": coverage,
                "source_checks": checks,
                "all_source_hashes_match": bool(checks) and all(item["source_sha256_matches"] for item in checks),
                "all_lines_exist": bool(checks) and all(item["line_exists"] for item in checks),
                "source_check_count": len(checks),
            })
        except Exception as error:
            result["errors"].append(f"{type(error).__name__}: {error}")
            result.setdefault("source_checks", [])
            result["all_source_hashes_match"] = False
            result["all_lines_exist"] = False
            result["snapshot_sha256_matches"] = False
        records.append(result)
        print(record["sample_order"], record["repository"], result.get("snapshot_sha256_matches"), result.get("all_source_hashes_match"), result["errors"])

    payload = {
        "schema_version": "openharmony-a-line-provenance-v1",
        "scanner_root": str(SCANNER_ROOT),
        "method": "WSL Git offline object reads plus OHScanner prepare_git_context; no fetch or checkout.",
        "records": records,
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
