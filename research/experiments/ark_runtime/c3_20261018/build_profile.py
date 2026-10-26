#!/usr/bin/env python3
"""Explicit, fail-closed capture/replay for a GN-produced C++ compile command.

This tool consumes an existing compilation database. It never invokes GN, Ninja,
build.py, build.sh, or repository scripts. `capture` runs only the compiler's
dependency-only preprocessing mode; `replay` runs only compiler preprocessing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def digest_fixture(argv=None, compiler_version="clang version fixture", header_sha="a" * 64):
    """Tiny deterministic fixture for digest sensitivity regression checks."""
    return canonical_digest({
        "argv": argv or ["clang++", "-DPROFILE_FLAG=1", "-I", "include", "-target", "aarch64-linux-ohos"],
        "compiler_version": compiler_version,
        "dependencies": [{"path": "${SOURCE_ROOT}/include/generated.h", "sha256": header_sha}],
    })


def load_json(path: Path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def commands(entry: dict) -> list[str]:
    if isinstance(entry.get("arguments"), list):
        return [str(item) for item in entry["arguments"]]
    if isinstance(entry.get("command"), str):
        return shlex.split(entry["command"], posix=True)
    raise ValueError("compile database entry has neither arguments[] nor command")


def find_entry(database: Path, source: Path) -> tuple[dict, Path]:
    entries = load_json(database)
    matches = []
    for entry in entries:
        cwd = Path(entry.get("directory", database.parent)).resolve()
        candidate = Path(entry.get("file", ""))
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if candidate.resolve() == source.resolve():
            matches.append((entry, cwd))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one compile command for target, found {len(matches)}")
    return matches[0]


def expand_responses(argv: list[str], cwd: Path, seen=None) -> tuple[list[str], list[dict]]:
    seen = set() if seen is None else seen
    expanded: list[str] = []
    records: list[dict] = []
    for token in argv:
        if not token.startswith("@") or token == "@":
            expanded.append(token)
            continue
        response = Path(token[1:])
        if not response.is_absolute():
            response = cwd / response
        response = response.resolve()
        if response in seen:
            raise ValueError(f"response-file cycle detected: {response}")
        if not response.is_file():
            raise ValueError(f"compiler response file missing: {response}")
        seen.add(response)
        records.append({"path": str(response), "sha256": sha256(response)})
        nested = shlex.split(response.read_text(encoding="utf-8"), posix=True)
        nested_args, nested_records = expand_responses(nested, cwd, seen)
        expanded.extend(nested_args)
        records.extend(nested_records)
        seen.remove(response)
    return expanded, records


def dep_command(argv: list[str], depfile: Path) -> list[str]:
    out: list[str] = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg == "-o":
            skip = True
        elif arg in ("-c", "-S", "-E", "-MD", "-MMD", "-MP", "-MG"):
            continue
        elif arg.startswith("-o") and len(arg) > 2:
            continue
        else:
            out.append(arg)
    out.extend(["-M", "-MF", str(depfile)])
    return out


def preprocess_command(argv: list[str], output: Path) -> list[str]:
    out: list[str] = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
            continue
        if arg == "-o":
            skip = True
        elif arg in ("-c", "-S", "-E", "-MD", "-MMD", "-MP", "-MG"):
            continue
        elif arg.startswith("-o") and len(arg) > 2:
            continue
        else:
            out.append(arg)
    out.extend(["-E", "-dD", "-o", str(output)])
    return out


def make_dependencies(depfile: Path) -> list[Path]:
    text = depfile.read_text(encoding="utf-8", errors="strict").replace("\\\n", " ")
    if ":" not in text:
        raise ValueError("compiler dependency output is malformed")
    body = text.split(":", 1)[1]
    # GCC/Clang make escaping: backslash quotes spaces, #, colon, and backslash.
    words, word, escaped = [], [], False
    for char in body:
        if escaped:
            word.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            if word:
                words.append("".join(word)); word = []
        else:
            word.append(char)
    if escaped:
        word.append("\\")
    if word:
        words.append("".join(word))
    return [Path(item) for item in words]


def run_checked(argv: list[str], cwd: Path, label: str) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{label} could not execute: {exc}") from exc
    if result.returncode:
        raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr[-4000:]}")
    return result


def stable_path(path: Path, source_root: Path, build_root: Path) -> str:
    value = str(path.resolve()).replace("\\", "/")
    for root, marker in ((build_root, "${BUILD_ROOT}"), (source_root, "${SOURCE_ROOT}")):
        prefix = str(root.resolve()).replace("\\", "/").rstrip("/")
        if value == prefix or value.startswith(prefix + "/"):
            return marker + value[len(prefix):]
    return value


def capture(args) -> dict:
    manifest = load_json(args.manifest)
    if manifest.get("schema") != "ark-runtime-build-profile-v1":
        raise ValueError("unsupported manifest schema")
    if manifest.get("repository") != "openharmony/arkcompiler_ets_runtime":
        raise ValueError("repository binding mismatch")
    source_root = args.source_root.resolve()
    source_rel = manifest["target"]["path"]
    source = source_root / source_rel
    if not source.is_file():
        raise ValueError(f"target source missing: {source}")
    expected = manifest["target"].get("sha256")
    actual = sha256(source)
    if expected and actual != expected:
        raise ValueError(f"target source SHA-256 mismatch: expected {expected}, got {actual}")
    git = shutil.which("git")
    if not git:
        raise ValueError("git unavailable; exact commit/tree/blob binding cannot be checked")
    def git_value(*parts: str) -> str:
        result = subprocess.run([git, "-C", str(source_root), *parts], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            raise ValueError(f"git identity check failed ({' '.join(parts)}): {result.stderr.strip()}")
        return result.stdout.strip()
    actual_commit = git_value("rev-parse", "HEAD")
    actual_tree = git_value("rev-parse", "HEAD^{tree}")
    actual_blob = git_value("rev-parse", f"HEAD:{source_rel}")
    if (actual_commit, actual_tree, actual_blob) != (manifest["commit"], manifest["tree"], manifest["target"]["git_blob"]):
        raise ValueError("exact commit/tree/blob mismatch; refusing capture")
    entry, cwd = find_entry(args.compile_db.resolve(), source)
    argv, response_files = expand_responses(commands(entry), cwd)
    if not argv:
        raise ValueError("empty compiler command")
    compiler_arg = argv[0]
    compiler_candidate = Path(compiler_arg)
    if not compiler_candidate.is_absolute() and ("/" in compiler_arg or "\\" in compiler_arg):
        compiler_candidate = cwd / compiler_candidate
    compiler = str(compiler_candidate.resolve()) if compiler_candidate.is_file() else shutil.which(
        compiler_arg, path=entry.get("environment", {}).get("PATH", os.environ.get("PATH")))
    if compiler is None:
        candidate = Path(argv[0])
        if candidate.is_file():
            compiler = str(candidate.resolve())
        else:
            raise ValueError(f"compiler unavailable: {argv[0]}")
    argv[0] = compiler
    version = run_checked([compiler, "--version"], cwd, "compiler version probe").stdout.strip()
    with tempfile.TemporaryDirectory(prefix="ark-profile-") as temp:
        depfile = Path(temp) / "deps.d"
        run_checked(dep_command(argv, depfile), cwd, "dependency preprocessing")
        dependencies = make_dependencies(depfile)
    records = []
    missing = []
    for dep in dependencies:
        resolved = dep if dep.is_absolute() else cwd / dep
        resolved = resolved.resolve()
        if not resolved.is_file():
            missing.append(str(resolved))
        else:
            records.append({"path": stable_path(resolved, source_root, args.build_root), "sha256": sha256(resolved)})
    if missing:
        raise ValueError("missing compiler dependency/generated header(s): " + ", ".join(missing[:20]))
    normalized = [stable_path(Path(token), source_root, args.build_root)
                  if token.startswith("/") or (len(token) > 2 and token[1:3] == ":\\") else token
                  for token in argv]
    payload = {
        "schema": "ark-runtime-captured-profile-v1",
        "profile_tool_version": "1.0.0",
        "profile_tool_sha256": sha256(Path(__file__).resolve()),
        "binding": {"repository": manifest["repository"], "commit": manifest["commit"],
                    "tree": manifest["tree"], "target": source_rel, "source_sha256": actual},
        "compile_database": str(args.compile_db.resolve()),
        "compile_database_sha256": sha256(args.compile_db.resolve()),
        "response_files": sorted(response_files, key=lambda item: item["path"]),
        "working_directory": stable_path(cwd, source_root, args.build_root),
        "normalized_argv": normalized,
        "compiler_realpath": stable_path(Path(compiler), source_root, args.build_root),
        "compiler_version": version,
        "dependencies": sorted(records, key=lambda item: item["path"]),
        "defines": "from normalized compiler argv; see -D flags",
        "include_search_paths": "from normalized compiler argv; see -I/-isystem/-iquote flags",
        "platform": "from target/sysroot flags and compile database; no inference",
    }
    payload["profile_digest"] = canonical_digest(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    cap = sub.add_parser("capture", help="capture exact compile command and dependency hashes")
    cap.add_argument("--manifest", type=Path, required=True)
    cap.add_argument("--source-root", type=Path, required=True)
    cap.add_argument("--compile-db", type=Path, required=True)
    cap.add_argument("--build-root", type=Path, required=True)
    cap.add_argument("--output", type=Path, required=True)
    rep = sub.add_parser("replay", help="run -E with a previously captured compile database entry")
    rep.add_argument("--manifest", type=Path, required=True)
    rep.add_argument("--source-root", type=Path, required=True)
    rep.add_argument("--compile-db", type=Path, required=True)
    rep.add_argument("--build-root", type=Path, required=True)
    rep.add_argument("--output", type=Path, required=True, help="preprocessed translation unit output")
    rep.add_argument("--record", type=Path, required=True, help="profile record JSON output")
    sub.add_parser("self-check", help="verify stable digest and macro/header/tool/flag sensitivity")
    args = parser.parse_args()
    try:
        if args.action == "self-check":
            baseline = digest_fixture()
            if baseline != digest_fixture():
                raise ValueError("identical profile fixture produced different digest")
            variants = [
                digest_fixture(argv=["clang++", "-DPROFILE_FLAG=2", "-I", "include", "-target", "aarch64-linux-ohos"]),
                digest_fixture(header_sha="b" * 64),
                digest_fixture(compiler_version="clang version changed"),
                digest_fixture(argv=["clang++", "-DPROFILE_FLAG=1", "-I", "include", "-target", "aarch64-linux-ohos", "-fno-exceptions"]),
            ]
            if any(item == baseline for item in variants):
                raise ValueError("one or more profile input changes did not alter the digest")
            print(json.dumps({"status": "passed", "stable_repeat": True,
                              "macro_header_tool_parameter_each_changed_digest": True,
                              "fixture_digest": baseline}, sort_keys=True))
            return 0
        if args.action == "capture" and args.output.exists():
            raise ValueError(f"refusing to overwrite existing output: {args.output}")
        if args.action == "replay" and (args.output.exists() or args.record.exists()):
            raise ValueError("refusing to overwrite existing preprocessed output or profile record")
        profile = capture(args)
        if args.action == "replay":
            _, cwd = find_entry(args.compile_db.resolve(), args.source_root.resolve() / profile["binding"]["target"])
            entry, _ = find_entry(args.compile_db.resolve(), args.source_root.resolve() / profile["binding"]["target"])
            argv, _ = expand_responses(commands(entry), cwd)
            compiler = profile["compiler_realpath"]
            if compiler.startswith("${SOURCE_ROOT}"):
                compiler = str(args.source_root.resolve()) + compiler[len("${SOURCE_ROOT}"):]
            elif compiler.startswith("${BUILD_ROOT}"):
                compiler = str(args.build_root.resolve()) + compiler[len("${BUILD_ROOT}"):]
            argv[0] = compiler
            args.output.parent.mkdir(parents=True, exist_ok=True)
            try:
                run_checked(preprocess_command(argv, args.output.resolve()), cwd, "preprocessor replay")
            except Exception:
                if args.output.exists():
                    args.output.unlink()
                raise
            profile["preprocessed_output"] = str(args.output.resolve())
            profile["preprocessed_output_sha256"] = sha256(args.output)
            profile["preprocessing_status"] = "complete"
        else:
            profile["preprocessing_status"] = "not_run"
        record_path = args.record if args.action == "replay" else args.output
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(profile["profile_digest"])
        return 0
    except Exception as exc:
        print(json.dumps({"status": "blocked", "diagnostic": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
