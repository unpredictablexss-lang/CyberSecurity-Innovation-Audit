from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src.parser.ast import parse_source

EVIDENCE = Path(__file__).resolve().parent / "webview_exact_a0_fragments_20261020"
SOURCE_PATH = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"
EXPECTED = {
    "vulnerable": {
        "commit": "a15cbf4ef20673cfcf1856bf40a723b3ce026564",
        "tree": "03e16f6f4f2c33c2cd08e31c14e00be689230c39",
        "blob": "78e83fea67a2db3297cc59f07566a0c0b6153e7a",
        "sha256": "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920",
        "flowbuffer_lines": {85, 87, 96, 98, 140, 142},
        "diagnostics": 13,
    },
    "fixed": {
        "commit": "fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb",
        "tree": "9873e4146e4a521b80f05a61c24d9c6047f696a7",
        "blob": "27e93e338ced03aeed6e7d892e29d4d0740f3653",
        "sha256": "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483",
        "flowbuffer_lines": set(),
        "diagnostics": 7,
    },
}
CONTROLS = {"safe.cpp", "unrelated.cpp", "renamed.cpp", "partial.cpp"}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def raw_source(repo: Path, commit: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{SOURCE_PATH}"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--snapshot-repo", type=Path, required=True)
    parser.add_argument("--d11-identities", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((EVIDENCE / "source-identities.json").read_text(encoding="utf-8"))
    assert manifest["source_repository"] == "openharmony/web_webview"
    assert manifest["source_path"] == SOURCE_PATH
    assert manifest["source_identity_is_not_snapshot_identity"] is True
    assert manifest["function_names"] == ["FlowbufStrAtIndex", "ProcessNativeProxyResultNewFlowbuf"]

    old_d11 = json.loads(args.d11_identities.read_text(encoding="utf-8"))
    assert old_d11["source_repository"] == "OpenHarmony-TPC/chromium_src"
    old_fragments = old_d11["snapshots"]
    results = {}
    for label, expected in EXPECTED.items():
        identity = manifest["snapshots"][label]
        for key, value in expected.items():
            if key in {"flowbuffer_lines", "diagnostics"}:
                continue
            assert identity[key] == value, (label, key)
        assert git(args.source_repo, "rev-parse", f"{identity['commit']}^{{tree}}") == identity["tree"]
        assert git(args.source_repo, "rev-parse", f"{identity['commit']}:{SOURCE_PATH}") == identity["blob"]
        source = raw_source(args.source_repo, identity["commit"])
        assert len(source) == identity["bytes"]
        assert hashlib.sha256(source).hexdigest() == identity["sha256"]
        parsed = parse_source(source.decode("utf-8"), "cpp")
        parsed_ranges = {f.name: (f.start_line, f.end_line) for f in parsed.functions if f.name in manifest["function_names"]}
        assert set(parsed_ranges) == set(manifest["function_names"])
        spans = []
        for record in identity["function_ranges"]:
            assert parsed_ranges[record["name"]] == (record["start_line"], record["end_line"])
            fragment = source[record["start_byte"]:record["end_byte_exclusive"]]
            assert len(fragment) == record["byte_length"]
            assert hashlib.sha256(fragment).hexdigest() == record["sha256"]
            spans.append(fragment)
        combined = b"\n".join(spans)
        assert len(combined) == identity["combined_fragment_bytes"]
        assert hashlib.sha256(combined).hexdigest() == identity["combined_fragment_sha256"]
        synthetic = identity["synthetic_snapshot_commit"]
        assert git(args.snapshot_repo, "rev-parse", f"{synthetic}^{{tree}}") == identity["synthetic_snapshot_tree"]
        packaged = subprocess.check_output([
            "git", "-C", str(args.snapshot_repo), "show", f"{synthetic}:{identity['synthetic_snapshot_file']}"
        ])
        assert packaged == combined
        assert hashlib.sha256(packaged).hexdigest() == identity["combined_fragment_sha256"]
        # D11 used a distinct Chromium-derived repo identity; only exact bytes/hashes are compared here.
        assert identity["sha256"] == old_fragments[label]["sha256"]
        assert identity["blob"] == old_fragments[label]["blob"]
        assert identity["combined_fragment_sha256"] == old_fragments[label]["fragment_sha256"]

        report = json.loads((EVIDENCE / f"{label}.json").read_text(encoding="utf-8"))
        assert report["repository"] == "openharmony/web_webview"
        assert report["commit"] == synthetic
        assert report["status"] == "completed_with_limitations"
        run = report["detector_runs"][0]
        assert run["tool"] == "ohscanner.cpp.bounds" and run["tool_version"] == "0.3.0"
        assert run["status"] == "blocked" and run["diagnostic_count"] == expected["diagnostics"]
        parsing = {item["file"]: item for item in run["parsing"]}
        assert set(parsing) == {identity["synthetic_snapshot_file"], *CONTROLS}
        assert parsing[identity["synthetic_snapshot_file"]]["status"] == "complete"
        assert parsing["partial.cpp"]["status"] == "partial"
        diagnostics = run["diagnostics"]
        by_file = {}
        for item in diagnostics:
            by_file.setdefault(item["file"], []).append(item)
        assert by_file.get("safe.cpp", []) == []
        assert by_file.get("unrelated.cpp", []) == []
        assert len(by_file.get("renamed.cpp", [])) == 1
        assert by_file.get("partial.cpp", []) == []
        fragment_file = identity["synthetic_snapshot_file"]
        flowbuffer = {item["line"] for item in by_file.get(fragment_file, []) if item["line"] in expected["flowbuffer_lines"]}
        assert flowbuffer == expected["flowbuffer_lines"]
        assert len(by_file.get(fragment_file, [])) == (12 if label == "vulnerable" else 6)
        results[label] = {
            "source_commit": identity["commit"],
            "source_tree": identity["tree"],
            "source_blob": identity["blob"],
            "source_sha256": identity["sha256"],
            "fragment_sha256": identity["combined_fragment_sha256"],
            "fragment_parse": identity["fragment_parse_status"],
            "fragment_diagnostics": len(by_file.get(fragment_file, [])),
            "flowbuffer_root_lines": sorted(flowbuffer),
            "renamed": len(by_file["renamed.cpp"]),
            "safe": 0,
            "unrelated": 0,
            "partial_control": parsing["partial.cpp"]["status"],
            "aggregate": run["status"],
        }

    print(json.dumps({"result": "PASS_EXACT_A0_SOURCE_AND_FRAGMENT_REPLAY", "cases": results,
                      "interpretation": "function-fragment candidate differential only; both aggregates blocked by partial control; whole-TU remains partial"}, indent=2))


if __name__ == "__main__":
    main()
