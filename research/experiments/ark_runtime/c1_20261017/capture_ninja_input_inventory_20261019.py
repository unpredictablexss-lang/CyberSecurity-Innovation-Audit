#!/usr/bin/env python3
"""Stream Ninja's read-only default-target input inventory and isolate npm inputs."""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
NINJA = BASE / "toolchain-20261019/ninja"
OUTPUT = BASE / "out-gn-20261019-retry3/rk3568"
EXPECTED_NINJA = "2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b"
RESULT = HERE / "ninja_input_inventory_20261019.v1.json"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    ninja_hash = sha(NINJA)
    if ninja_hash != EXPECTED_NINJA:
        raise SystemExit(f"Ninja hash mismatch: {ninja_hash}")
    command = [str(NINJA), "-C", str(OUTPUT), "-w", "dupbuild=warn", "-t", "inputs", "all"]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert proc.stdout is not None
    output_hash = hashlib.sha256()
    input_count = byte_count = 0
    references: Counter[str] = Counter()
    examples: dict[str, str] = {}
    for raw in iter(proc.stdout.readline, b""):
        output_hash.update(raw)
        byte_count += len(raw)
        line = raw.decode("utf-8", "replace").strip()
        if line:
            input_count += 1
        if "node_modules/" in line:
            token = next((part for part in line.split() if "node_modules/" in part), line)
            root = token.split("/node_modules/", 1)[0].strip("\"'=:;")
            references[root] += 1
            examples.setdefault(root, line[:500])
    returncode = proc.wait()
    result = {
        "schema": "ohscanner.c1.ninja-input-inventory/v1",
        "status": "captured" if returncode == 0 else "tool_failed",
        "product": "hihope/rk3568",
        "target": "all",
        "command": command,
        "ninja_sha256": ninja_hash,
        "build_ninja_sha256": sha(OUTPUT / "build.ninja"),
        "returncode": returncode,
        "input_line_count": input_count,
        "stdout_bytes": byte_count,
        "stdout_sha256": output_hash.hexdigest(),
        "node_modules_reference_roots": [
            {"build_path_root": root, "reference_count": count, "example": examples[root]}
            for root, count in sorted(references.items())
        ],
        "scope_note": "Ninja -t inputs is a read-only graph query. It enumerates declared inputs; it does not establish source-tree completeness, run build actions, or prove input existence.",
    }
    RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "returncode": returncode,
                      "input_line_count": input_count, "stdout_bytes": byte_count,
                      "node_modules_roots": result["node_modules_reference_roots"]}, ensure_ascii=False, indent=2))
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
