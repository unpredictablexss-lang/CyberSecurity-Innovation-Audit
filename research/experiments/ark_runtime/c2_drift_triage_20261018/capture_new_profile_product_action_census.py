#!/usr/bin/env python3
"""Stream the exact C1 compile database and bind actions for changed C2 .cpp paths."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path


def json_value(line: bytes):
    return json.loads(line.decode("utf-8").split(":", 1)[1].strip().rstrip(","))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--compile-db", required=True, type=Path)
    ap.add_argument("--profile", required=True, type=Path)
    ap.add_argument("--triage", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    profile = json.loads(ns.profile.read_text(encoding="utf-8"))
    triage = json.loads(ns.triage.read_text(encoding="utf-8"))
    changed_cpp: dict[str, list[int]] = {}
    for row in triage["dependencies"]:
        path = row["path"]
        if row["source_identity_changed"] and path.endswith(".cpp"):
            changed_cpp.setdefault(path, []).append(row["index"])
    expected_db_sha = profile["runs"][0]["compile_commands_sha256"]
    expected_db_bytes = profile["runs"][0]["compile_commands_bytes"]
    actions: dict[str, list[dict]] = {path: [] for path in sorted(changed_cpp)}
    db_hash = hashlib.sha256()
    object_count = 0
    file_field = re.compile(rb'^\s*"file"\s*:')

    with ns.compile_db.open("rb", buffering=4 * 1024 * 1024) as stream:
        for line in stream:
            db_hash.update(line)
            if not file_field.match(line):
                continue
            source_file = json_value(line)
            object_count += 1
            normalized = source_file.replace("\\", "/")
            matched = next((p for p in actions if normalized.endswith("arkcompiler/ets_runtime/" + p)), None)
            if matched is None:
                continue
            directory_line = stream.readline()
            command_line = stream.readline()
            db_hash.update(directory_line)
            db_hash.update(command_line)
            directory = json_value(directory_line)
            command = json_value(command_line)
            argv = shlex.split(command)
            out = argv[argv.index("-o") + 1] if "-o" in argv and argv.index("-o") + 1 < len(argv) else None
            target = next((arg.split("=", 1)[1] for arg in argv if arg.startswith("--target=")), None)
            actions[matched].append({
                "file": source_file,
                "directory": directory,
                "object_output": out,
                "target": target,
                "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
                "command": command,
            })

    observed_sha = db_hash.hexdigest()
    observed_bytes = ns.compile_db.stat().st_size
    if observed_sha != expected_db_sha or observed_bytes != expected_db_bytes or object_count != 234245:
        raise SystemExit(f"compile database identity mismatch: {observed_sha}/{observed_bytes}")

    rows = []
    for path in sorted(actions):
        entries = actions[path]
        rows.append({
            "path": path,
            "drift_rows": changed_cpp[path],
            "new_profile_source_action_count": len(entries),
            "action_binding_status": "profile_compile_action_captured" if entries else "no_compile_database_source_action",
            "actions": entries,
        })
    report = {
        "schema": "c2-new-profile-product-action-census/v1",
        "scope": "changed C2 .cpp files as compile database source entries; excludes header include consumers and does not establish semantic relevance",
        "profile_artifact": ns.profile.as_posix(),
        "profile_digest_sha256": profile["profile_digest_sha256"],
        "product": profile["product"],
        "compile_database_external_path": str(ns.compile_db),
        "compile_database_identity": {"sha256": observed_sha, "bytes": observed_bytes, "expected_source_entry_count": 234245,
                                       "observed_source_entry_count": object_count},
        "source_materialization_status": profile["snapshot"]["materialization_status"],
        "source_rows": rows,
        "semantic_limit": "A compile database entry proves GN exported a source compile action for this new profile. It does not prove the action ran, that a changed line is active, that a modeled path reaches it, or that the old profile used the same action.",
    }
    ns.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "verified_compile_database_and_captured_source_actions",
        "compile_database_sha256": observed_sha,
        "bytes": observed_bytes,
        "source_entry_count": object_count,
        "rows": [{"path": r["path"], "count": r["new_profile_source_action_count"],
                  "targets": sorted({a["target"] for a in r["actions"] if a["target"]})}
                 for r in rows],
        "output": str(ns.output),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
