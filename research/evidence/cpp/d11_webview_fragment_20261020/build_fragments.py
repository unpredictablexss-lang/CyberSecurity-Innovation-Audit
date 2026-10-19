from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from src.parser.ast import parse_source


EVIDENCE = Path(__file__).resolve().parent
SOURCE_GIT = Path(r"D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git")
SNAPSHOT_REPO = Path(r"D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2")
SOURCE_PATH = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"
UPSTREAM = {
    "vulnerable": {
        "commit": "5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8",
        "tree": "4ed3b46721fbfe04059af4ddb18bcd5272ce4762",
        "blob": "78e83fea67a2db3297cc59f07566a0c0b6153e7a",
        "sha256": "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920",
        "bytes": 185698,
    },
    "fixed": {
        "commit": "4cf313408de7b6d807465ea2bb22e434269b7c5e",
        "tree": "a7769bf612be457e6e368f14ee355f3ea8ed2935",
        "blob": "27e93e338ced03aeed6e7d892e29d4d0740f3653",
        "sha256": "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483",
        "bytes": 185982,
    },
}
CONTROLS = {
    "safe.cpp": """#include <cstddef>\n#include <vector>\nvoid safe_vector(std::vector<int>& values) {\n    for (std::size_t cursor = 0; cursor < values.size(); ++cursor) values[cursor] = 1;\n}\n""",
    "unrelated.cpp": """void unrelated_array(int cursor) {\n    int local[8]{}; if (cursor >= 0 && cursor < 8) local[cursor] = 1;\n}\n""",
    "renamed.cpp": """#include <vector>\nvoid renamed_positive(std::vector<int>& renamed_items, int renamed_cursor) {\n    while (renamed_cursor < 2) { renamed_items[renamed_cursor] = 1; ++renamed_cursor; }\n}\n""",
    "partial.cpp": """#include <vector>\nvoid partial_vector(std::vector<int>& partial_values, int partial_cursor) {\n    partial_values[partial_cursor] = 1;\n""",
}


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", f"--git-dir={SOURCE_GIT}", *args], text=True
    ).strip()


def git_snapshot(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(SNAPSHOT_REPO), *args], text=True
    ).strip()


def main() -> None:
    if not SOURCE_GIT.exists():
        raise SystemExit(f"missing pinned local source object store: {SOURCE_GIT}")
    if SNAPSHOT_REPO.exists() and any(SNAPSHOT_REPO.iterdir()):
        raise SystemExit(f"refusing nonempty snapshot repository: {SNAPSHOT_REPO}")
    SNAPSHOT_REPO.mkdir(parents=True, exist_ok=True)
    git_snapshot("init", "-q")
    git_snapshot("config", "user.name", "OHScanner D11 Evidence")
    git_snapshot("config", "user.email", "d11-evidence@example.invalid")
    controls_hashes = {
        name: hashlib.sha256(text.encode()).hexdigest()
        for name, text in CONTROLS.items()
    }
    manifest = {
        "schema_version": 1,
        "case": "web_webview-CVE-2026-27648-D11",
        "source_repository": "OpenHarmony-TPC/chromium_src",
        "source_path": SOURCE_PATH,
        "basis": "Functions independently extracted from exact pinned upstream 6.0 blobs; synthetic commits package those bytes with identical detector controls.",
        "controls_sha256": controls_hashes,
        "snapshots": {},
    }
    for label, identity in UPSTREAM.items():
        commit = identity["commit"]
        if git("cat-file", "-t", commit) != "commit":
            raise SystemExit(f"upstream commit missing: {commit}")
        if git("rev-parse", f"{commit}^{{tree}}") != identity["tree"]:
            raise SystemExit(f"upstream tree mismatch: {label}")
        blob = git("rev-parse", f"{commit}:{SOURCE_PATH}")
        if blob != identity["blob"]:
            raise SystemExit(f"upstream blob mismatch: {label}: {blob}")
        raw = subprocess.check_output(
            ["git", f"--git-dir={SOURCE_GIT}", "show", f"{commit}:{SOURCE_PATH}"]
        )
        if len(raw) != identity["bytes"] or hashlib.sha256(raw).hexdigest() != identity["sha256"]:
            raise SystemExit(f"upstream source byte/hash mismatch: {label}")
        text = raw.decode("utf-8")
        parsed = parse_source(text, "cpp")
        wanted = {"FlowbufStrAtIndex", "ProcessNativeProxyResultNewFlowbuf"}
        funcs = [item for item in parsed.functions if item.name in wanted]
        if {item.name for item in funcs} != wanted:
            raise SystemExit(f"expected both target functions, got: {[item.name for item in funcs]}")
        lines = text.splitlines()
        fragment = "\n\n".join(
            "\n".join(lines[item.start_line - 1:item.end_line]) for item in funcs
        ) + "\n"
        fragment_bytes = fragment.encode()
        fragment_parse = parse_source(fragment, "cpp")
        if fragment_parse.parse_status != "complete" or fragment_parse.parse_issues:
            raise SystemExit(f"fragment parse not complete: {label} {fragment_parse.parse_issues}")
        (SNAPSHOT_REPO / "flowbuffer_functions.cc").write_bytes(fragment_bytes)
        for name, text in CONTROLS.items():
            (SNAPSHOT_REPO / name).write_text(text, encoding="utf-8", newline="\n")
        git_snapshot("add", "flowbuffer_functions.cc", *CONTROLS)
        git_snapshot("commit", "-qm", label)
        synthetic_commit = git_snapshot("rev-parse", "HEAD")
        synthetic_tree = git_snapshot("rev-parse", "HEAD^{tree}")
        manifest["snapshots"][label] = {
            **identity,
            "synthetic_commit": synthetic_commit,
            "synthetic_tree": synthetic_tree,
            "fragment_sha256": hashlib.sha256(fragment_bytes).hexdigest(),
            "fragment_bytes": len(fragment_bytes),
            "function_ranges": [
                {"name": item.name, "start_line": item.start_line, "end_line": item.end_line}
                for item in funcs
            ],
            "fragment_parse_status": fragment_parse.parse_status,
            "fragment_parse_issues": fragment_parse.parse_issues,
            "controls": {
                name: {"sha256": controls_hashes[name], "bytes": len(text.encode())}
                for name, text in CONTROLS.items()
            },
        }
    (EVIDENCE / "source-identities.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
