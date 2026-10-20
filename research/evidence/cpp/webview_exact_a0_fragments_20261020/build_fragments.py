from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from src.parser.ast import parse_source

SOURCE_GIT = Path(r"D:\openHarmonyScanner\tmp\web-webview-flowbuf-full-tu-m2-20261019")
SNAPSHOT = Path(r"D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020")
SOURCE_PATH = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"
SOURCE_REPOSITORY = "openharmony/web_webview"
SOURCES = {
    "vulnerable": {
        "commit": "a15cbf4ef20673cfcf1856bf40a723b3ce026564",
        "tree": "03e16f6f4f2c33c2cd08e31c14e00be689230c39",
        "blob": "78e83fea67a2db3297cc59f07566a0c0b6153e7a",
        "sha256": "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920",
        "bytes": 185698,
    },
    "fixed": {
        "commit": "fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb",
        "tree": "9873e4146e4a521b80f05a61c24d9c6047f696a7",
        "blob": "27e93e338ced03aeed6e7d892e29d4d0740f3653",
        "sha256": "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483",
        "bytes": 185982,
    },
}
CONTROLS = {
    "safe.cpp": "#include <cstddef>\n#include <vector>\nvoid safe_vector(std::vector<int>& values) {\n    for (std::size_t cursor = 0; cursor < values.size(); ++cursor) values[cursor] = 1;\n}\n",
    "unrelated.cpp": "void unrelated_array(int cursor) {\n    int local[8]{}; if (cursor >= 0 && cursor < 8) local[cursor] = 1;\n}\n",
    "renamed.cpp": "#include <vector>\nvoid renamed_positive(std::vector<int>& renamed_items, int renamed_cursor) {\n    while (renamed_cursor < 2) { renamed_items[renamed_cursor] = 1; ++renamed_cursor; }\n}\n",
    "partial.cpp": "#include <vector>\nvoid partial_vector(std::vector<int>& partial_values, int partial_cursor) {\n    partial_values[partial_cursor] = 1;\n",
}
FUNCTIONS = ("FlowbufStrAtIndex", "ProcessNativeProxyResultNewFlowbuf")


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SOURCE_GIT), *args], text=True).strip()


def snapshot_git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SNAPSHOT), *args], text=True).strip()


def main() -> None:
    if not SOURCE_GIT.exists():
        raise SystemExit(f"missing exact A0 source checkout: {SOURCE_GIT}")
    if SNAPSHOT.exists() and any(SNAPSHOT.iterdir()):
        raise SystemExit(f"refusing to overwrite nonempty snapshot: {SNAPSHOT}")
    SNAPSHOT.mkdir(parents=True, exist_ok=True)
    snapshot_git("init", "-q")
    snapshot_git("config", "user.name", "OHScanner exact A0 evidence")
    snapshot_git("config", "user.email", "exact-a0-evidence@example.invalid")
    manifest = {
        "schema_version": 1,
        "case": "web_webview-CVE-2026-27648-exact-A0-function-fragments",
        "source_repository": SOURCE_REPOSITORY,
        "source_path": SOURCE_PATH,
        "function_names": list(FUNCTIONS),
        "source_identity_is_not_snapshot_identity": True,
        "snapshots": {},
    }
    for label, identity in SOURCES.items():
        commit = identity["commit"]
        if git("cat-file", "-t", commit) != "commit":
            raise SystemExit(f"missing source commit: {label}")
        if git("rev-parse", f"{commit}^{{tree}}") != identity["tree"]:
            raise SystemExit(f"tree mismatch: {label}")
        if git("rev-parse", f"{commit}:{SOURCE_PATH}") != identity["blob"]:
            raise SystemExit(f"blob mismatch: {label}")
        raw = subprocess.check_output(["git", "-C", str(SOURCE_GIT), "show", f"{commit}:{SOURCE_PATH}"])
        if len(raw) != identity["bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
            raise SystemExit(f"raw source mismatch: {label}")
        parsed = parse_source(raw.decode("utf-8"), "cpp")
        funcs = [f for f in parsed.functions if f.name in FUNCTIONS]
        if {f.name for f in funcs} != set(FUNCTIONS):
            raise SystemExit(f"missing expected functions: {label}")
        lines = raw.splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line))
        records = []
        fragments = []
        for func in funcs:
            start, end = offsets[func.start_line - 1], offsets[func.end_line]
            fragment = raw[start:end]
            records.append({
                "name": func.name,
                "start_line": func.start_line,
                "end_line": func.end_line,
                "start_byte": start,
                "end_byte_exclusive": end,
                "byte_length": len(fragment),
                "sha256": hashlib.sha256(fragment).hexdigest(),
            })
            fragments.append(fragment)
        combined = b"\n".join(fragments)
        check = parse_source(combined.decode("utf-8"), "cpp")
        if check.parse_status != "complete" or check.parse_issues:
            raise SystemExit(f"source-derived functions parse incomplete: {label}: {check.parse_issues}")
        filename = f"{label}_flowbuffer_functions.cc"
        (SNAPSHOT / filename).write_bytes(combined)
        for name, text in CONTROLS.items():
            (SNAPSHOT / name).write_text(text, encoding="utf-8", newline="\n")
        files = [filename, *CONTROLS]
        snapshot_git("add", *files)
        snapshot_git("commit", "-qm", f"{label} exact A0 function fragments and controls")
        manifest["snapshots"][label] = {
            **identity,
            "function_ranges": records,
            "combined_fragment_sha256": hashlib.sha256(combined).hexdigest(),
            "combined_fragment_bytes": len(combined),
            "fragment_parse_status": check.parse_status,
            "fragment_parse_issues": check.parse_issues,
            "synthetic_snapshot_commit": snapshot_git("rev-parse", "HEAD"),
            "synthetic_snapshot_tree": snapshot_git("rev-parse", "HEAD^{tree}"),
            "synthetic_snapshot_file": filename,
            "control_sha256": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in CONTROLS.items()},
        }
    (EVIDENCE / "source-identities.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
