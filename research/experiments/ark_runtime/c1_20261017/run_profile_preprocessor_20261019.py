#!/usr/bin/env python3
"""Run dependency-only preprocessing for exact GN-exported Ark Runtime actions.

Designed to run inside the isolated C1 container. Source is mounted read-only;
all preprocessed output and dependency files go to a separate writable mount.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from pathlib import Path

COMPILE_DB = Path("/src/out/rk3568/compile_commands.json")
RESULTS = Path("/results")
TARGET_SUFFIX = "arkcompiler/ets_runtime/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"


def sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def matching_actions() -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    with COMPILE_DB.open(encoding="utf-8") as stream:
        rows = iter(enumerate(stream, 1))
        for line_number, line in rows:
            if not line.lstrip().startswith('"file"') or TARGET_SUFFIX not in line:
                continue
            source = json.loads(line.split(":", 1)[1].strip().rstrip(","))
            _, directory_line = next(rows)
            directory = json.loads(directory_line.split(":", 1)[1].strip().rstrip(","))
            _, command_line = next(rows)
            command = json.loads(command_line.split(":", 1)[1].strip().rstrip(","))
            argv = shlex.split(command)
            if "--target=arm-linux-ohos" not in argv:
                continue
            output = argv[argv.index("-o") + 1]
            found.append({
                "compile_db_line": line_number,
                "source": source,
                "directory": directory,
                "object_output": output,
                "command": command,
                "argv": argv,
            })
    return found


def compiler_args(action: dict[str, object]) -> list[str]:
    argv = list(action["argv"])
    result = [argv[0]]
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "-MMD":
            i += 1
        elif arg == "-MF":
            i += 2
        elif arg == "-o":
            i += 2
        elif arg == "-c":
            i += 1
        else:
            result.append(arg)
            i += 1
    return result


def run(action: dict[str, object], index: int) -> dict[str, object]:
    RESULTS.mkdir(parents=True, exist_ok=True)
    stem = f"ark-runtime-arm-action-{index}"
    base = compiler_args(action)
    record: dict[str, object] = {
        "compile_db_line": action["compile_db_line"],
        "source": action["source"],
        "directory": action["directory"],
        "object_output": action["object_output"],
        "command_sha256": hashlib.sha256(str(action["command"]).encode()).hexdigest(),
        "preprocess": {},
        "dependency_scan": {},
        "macro_dump": {},
    }
    operations = [
        ("preprocess", ["-E", "-o", f"/results/{stem}.ii"], Path(f"{stem}.ii")),
        ("dependency_scan", ["-M", "-MF", f"/results/{stem}.d", "-MT", str(action["source"])], Path(f"{stem}.d")),
        ("macro_dump", ["-E", "-dM", "-o", f"/results/{stem}.macros"], Path(f"{stem}.macros")),
    ]
    for label, extra, relative_output in operations:
        stderr_path = RESULTS / f"{stem}.{label}.stderr"
        command = base + extra
        with stderr_path.open("wb") as stderr:
            completed = subprocess.run(command, cwd=str(action["directory"]), stdout=subprocess.DEVNULL,
                                       stderr=stderr, check=False)
        output_path = RESULTS / relative_output
        item: dict[str, object] = {
            "argv": command,
            "returncode": completed.returncode,
            "stderr_sha256": sha256(stderr_path)[0],
            "stderr_path": str(stderr_path),
        }
        if output_path.exists():
            item.update({"output_path": str(output_path), "output_sha256": sha256(output_path)[0],
                         "output_bytes": output_path.stat().st_size})
        record[label] = item
    return record


def main() -> int:
    actions = matching_actions()
    if len(actions) != 2:
        raise SystemExit(f"expected two ARM actions for {TARGET_SUFFIX}, found {len(actions)}")
    results = [run(action, index + 1) for index, action in enumerate(actions)]
    payload = {
        "schema": "ohscanner.c1.preprocessor-observation/v1",
        "compile_database": str(COMPILE_DB),
        "compile_database_sha256": sha256(COMPILE_DB)[0],
        "source_mount_read_only": True,
        "network": "none",
        "actions": results,
    }
    destination = RESULTS / "preprocessor_observation.json"
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"observation": str(destination), "actions": [
        {"object_output": x["object_output"], "preprocess_rc": x["preprocess"]["returncode"],
         "dependency_rc": x["dependency_scan"]["returncode"], "macro_rc": x["macro_dump"]["returncode"]}
        for x in results]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
