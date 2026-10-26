#!/usr/bin/env python3
"""Re-extract the 11 chain functions from the pinned Contacts clone and compare
them with the recorded manifest and with the .inc files that the harness
compiles.

Usage:
  verify_extraction.py --repo <contacts_data checkout> \
                       --manifest <extraction_manifest.json> \
                       --inc-dir <dir with generated/*.inc> \
                       --out-json <result.json> [--write-inc]

Exit code 0 = every file/snippet/line-number/inc check passed.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def extract(text: str, needle: str):
    start = text.index(needle)
    brace = text.index("{", start + len(needle))
    depth = 0
    i = brace
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    line_start = text.count("\n", 0, start) + 1
    line_end = text.count("\n", 0, i) + 1
    return text[start:i + 2], line_start, line_end


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--inc-dir", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--write-inc", action="store_true")
    args = ap.parse_args()

    repo = Path(args.repo)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    inc_dir = Path(args.inc_dir)
    inc_dir.mkdir(parents=True, exist_ok=True)

    ok = True
    report = {"files": [], "functions": [], "all_ok": False}

    for rel, meta in manifest["files"].items():
        raw = (repo / rel).read_bytes()
        lf = raw.replace(b"\r\n", b"\n")
        got = sha(lf)
        match = got == meta["sha256"] and len(lf) == meta["size_bytes"]
        ok &= match
        report["files"].append({"file": rel, "lf_sha256": got, "manifest_sha256": meta["sha256"],
                                "size_lf": len(lf), "size_manifest": meta["size_bytes"], "match": match})
        print(f"[file] {rel}: match={match} lf_sha256={got[:16]}...")

    for fn in manifest["functions"]:
        src = (repo / fn["file"]).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
        snippet, ls, le = extract(src, fn["needle"])
        snip_hash = sha(snippet.encode("utf-8"))
        hash_ok = snip_hash == fn["snippet_sha256"]
        lines_ok = (ls, le) == (fn["line_start"], fn["line_end"])
        inc_path = inc_dir / fn["output"]
        if args.write_inc or not inc_path.exists():
            inc_path.write_bytes(snippet.encode("utf-8"))
        inc_ok = inc_path.read_bytes().replace(b"\r\n", b"\n") == snippet.encode("utf-8")
        ok &= hash_ok and lines_ok and inc_ok
        report["functions"].append({"id": fn["id"], "hash_ok": hash_ok, "lines_ok": lines_ok,
                                    "inc_ok": inc_ok, "lines": [ls, le],
                                    "expected_lines": [fn["line_start"], fn["line_end"]]})
        print(f"[fn] {fn['id']}: hash={hash_ok} lines={lines_ok} ({ls}-{le}) inc={inc_ok}")

    report["all_ok"] = ok
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"ALL_OK={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
