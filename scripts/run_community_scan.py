from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.community import plan_repository_shards, scan_shard


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--detector-id", action="append")
    parser.add_argument("--max-repositories", type=int)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    detector_ids = tuple(args.detector_id or (
        "ohscanner.cpp.bounds",
        "ohscanner.cpp.integer_bounds",
        "ohscanner.cpp.lifetime",
        "ohscanner.cpp.null_dereference",
        "ohscanner.cpp.resource_lifetime",
        "ohscanner.cpp.shared_ptr_race",
        "ohscanner.cpp.unsafe_memory_call",
        "ohscanner.interface.ipc",
    ))
    state = {
        "schema_version": 1,
        "kind": "ohscanner.community-scan-checkpoint.v1",
        "inventory_sha256": hashlib.sha256(args.inventory.read_bytes()).hexdigest(),
        "detector_ids": list(detector_ids),
        "completed": {},
        "failed": {},
    }
    if args.state.exists():
        loaded = json.loads(args.state.read_text(encoding="utf-8"))
        if loaded["inventory_sha256"] != state["inventory_sha256"]:
            raise ValueError("checkpoint inventory drift")
        if tuple(loaded["detector_ids"]) != detector_ids:
            raise ValueError("checkpoint detector selection drift")
        state = loaded
    repositories = inventory["repositories"]
    if args.max_repositories is not None:
        repositories = repositories[:args.max_repositories]
    total_shards = 0
    for repository in repositories:
        source_root = Path(repository["source_root"])
        plan = plan_repository_shards(
            repository="openharmony/" + repository["name"],
            commit=repository["commit"],
            tree=repository.get("tree") or ("0" * 40),
            files=repository["files"],
        )
        total_shards += len(plan["shards"])
        for shard in plan["shards"]:
            key = repository["name"] + ":" + shard["resume_key"]
            if key in state["completed"]:
                continue
            rows = [row for row in repository["files"] if row["path"] in set(shard["paths"])]
            try:
                result = scan_shard(
                    source_root=source_root,
                    repository="openharmony/" + repository["name"],
                    commit=repository["commit"],
                    rows=rows,
                    detector_ids=detector_ids,
                )
                result_path = args.output_dir / repository["name"] / f"shard-{shard['shard_id']:04d}.json.gz"
                result_path.parent.mkdir(parents=True, exist_ok=True)
                payload = json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")
                result_path.write_bytes(gzip.compress(payload, compresslevel=9, mtime=0))
                state["failed"].pop(key, None)
                state["completed"][key] = {
                    "result_path": str(result_path),
                    "result_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
                    "snapshot_sha256": result["identity"]["snapshot_sha256"],
                    "files": result["coverage"]["files"],
                    "loc": result["coverage"]["loc"],
                    "diagnostics": sum(row["diagnostic_count"] for row in result["detector_reports"]),
                }
            except Exception as exc:
                state["failed"][key] = {
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:1000],
                    "shard": shard,
                }
            atomic_json(args.state, state)
            print(json.dumps({
                "repository": repository["name"],
                "shard": shard["shard_id"],
                "completed": len(state["completed"]),
                "failed": len(state["failed"]),
                "total_shards_so_far": total_shards,
            }, sort_keys=True), flush=True)
    state["counts"] = {
        "repositories": len(repositories),
        "planned_shards": total_shards,
        "completed_shards": len(state["completed"]),
        "failed_shards": len(state["failed"]),
    }
    atomic_json(args.state, state)
    return 1 if state["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
