from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.repository_registry import verify_registry


MIRRORS = ("gitcode", "gitee", "github")


def query_ref(url: str, revision: str) -> dict[str, Any]:
    env = os.environ.copy()
    env.pop("GIT_SSL_BACKEND", None)
    env.pop("GIT_SSL_CAINFO", None)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false"})
    started = time.monotonic()
    errors = []
    for attempt in range(1, 4):
        try:
            result = subprocess.run(
                ["git", "-c", "http.sslBackend=gnutls", "ls-remote", "--exit-code", url, "refs/heads/" + revision, "refs/tags/" + revision, "refs/tags/" + revision + "^{}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, check=False, timeout=30,
            )
            elapsed = time.monotonic() - started
            if result.returncode == 0:
                rows = [
                    line.split("\t", 1)
                    for line in result.stdout.decode("utf-8", "replace").splitlines()
                    if "\t" in line
                ]
                by_ref = {ref: sha for sha, ref in rows}
                for candidate, kind in (
                    ("refs/tags/" + revision + "^{}", "peeled_tag_commit"),
                    ("refs/tags/" + revision, "tag"),
                    ("refs/heads/" + revision, "head"),
                ):
                    if candidate in by_ref:
                        return {"status": "resolved", "sha": by_ref[candidate], "ref_kind": kind,
                                "elapsed_seconds": elapsed, "attempts": attempt, "errors": errors}
                errors.append("attempt " + str(attempt) + ": expected head, tag or peeled tag")
            else:
                errors.append("attempt " + str(attempt) + ": exit " + str(result.returncode) + ": "
                              + result.stderr.decode("utf-8", "replace")[:300])
        except subprocess.TimeoutExpired:
            errors.append("attempt " + str(attempt) + ": timeout")
        except Exception as exc:
            errors.append("attempt " + str(attempt) + ": " + type(exc).__name__ + ": " + str(exc)[:200])
    return {"status": "unavailable", "sha": None, "elapsed_seconds": time.monotonic() - started,
            "attempts": 3, "errors": errors}


def resolve_entry(entry: dict[str, Any], resolved_ref: str) -> tuple[str, dict[str, Any]]:
    urls = dict(entry["mirror_urls"])
    urls["github"] = "https://github.com/openharmony/" + entry["name"] + ".git"
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(query_ref, urls[name], resolved_ref): name for name in MIRRORS}
        observations = {}
        for future in as_completed(futures):
            observations[futures[future]] = future.result()
    resolved = {name: row["sha"] for name, row in observations.items() if row["sha"]}
    unique = set(resolved.values())
    if len(resolved) == len(MIRRORS) and len(unique) == 1:
        status = "mirror_sha_consistent"
        scan_sha = next(iter(unique))
    elif len(unique) > 1:
        status = "mirror_sha_divergence"
        scan_sha = None
    elif len(unique) == 1:
        status = "single_or_partial_mirror_agreement"
        scan_sha = None
    else:
        status = "unavailable"
        scan_sha = None
    return entry["name"], {
        "name": entry["name"],
        "path": entry["path"],
        "registry_revision": entry["revision"],
        "resolved_ref": resolved_ref,
        "observations": observations,
        "status": status,
        "scan_sha": scan_sha,
        "scan_eligible": status == "mirror_sha_consistent",
    }


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ref", default="OpenHarmony-v5.0.2-Release")
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.workers < 1 or args.workers > 64:
        raise ValueError("workers must be between 1 and 64")
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    verify_registry(registry)
    existing = {}
    if args.resume and args.out.exists():
        existing = json.loads(args.out.read_text(encoding="utf-8")).get("repositories", {})
    result = {
        "schema_version": 1,
        "kind": "ohscanner.openharmony-mirror-head-registry.v1",
        "registry_sha256": hashlib.sha256(args.registry.read_bytes()).hexdigest(),
        "policy": {
            "repository_count_is_dynamic": True,
            "resolved_ref": args.ref,
            "required_mirrors": list(MIRRORS),
            "scan_requires_three_mirror_same_sha": True,
            "retry_attempts_per_mirror": 3,
        },
        "repositories": existing,
    }
    pending = [entry for entry in registry["repositories"] if entry["name"] not in existing]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(resolve_entry, entry, args.ref): entry["name"] for entry in pending}
        completed = 0
        for future in as_completed(futures):
            name, row = future.result()
            result["repositories"][name] = row
            completed += 1
            if completed % 10 == 0 or completed == len(pending):
                atomic_json(args.out, result)
                counts = {}
                for item in result["repositories"].values():
                    counts[item["status"]] = counts.get(item["status"], 0) + 1
                print(json.dumps({"completed": completed, "pending": len(pending) - completed,
                                  "statuses": counts}, sort_keys=True), flush=True)
    atomic_json(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
