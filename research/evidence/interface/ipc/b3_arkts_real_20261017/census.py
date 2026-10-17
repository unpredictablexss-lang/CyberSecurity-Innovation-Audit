"""B-3 census over a real ArkTS application repository.

Run from the repository root, with the scan checkout outside the repository:

    python research/evidence/interface/ipc/b3_arkts_real_20261017/census.py \
        <scan-root> <out.json> [repository] [commit]

Only aggregate counts and finding metadata are written. Third-party source is
read but never stored, which is why the artifact keeps shape counts instead of
the files themselves.
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter

# The script lives three levels below the repository root; imports resolve
# against the working directory, which the usage line tells you to set.
sys.path.insert(0, os.getcwd())

from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.arkts_js import ArkTsJsInterfaceDetector

SKIP_DIRS = {".git", "node_modules", "oh_modules", "build", "dist", "output",
             "third_party", "preview"}
MAX_BYTES = 2 * 1024 * 1024
LANG = {".ets": "arkts", ".ts": "ts", ".js": "js"}
BATCH = 400
SHAPE_PATTERNS = {
    "bridge_text": re.compile(r"registerJavaScriptProxy|javaScriptProxy"),
    "want_parameters_text": re.compile(r"want\s*\.\s*parameters"),
    "file_sink_text": re.compile(
        r"fileIo\.(openSync|open|readSync|writeSync|readTextSync)|"
        r"fs\.(openSync|open|readFileSync|writeFileSync)"),
    "eval_text": re.compile(r"\beval\s*\(|new\s+Function\s*\("),
    "native_import_text": re.compile(
        r"\bfrom\s+['\"][^'\"]*lib[^'\"]*\.so['\"]|requireNapi\s*\("),
}
COUNTER_PATTERNS = {
    "call_sites": re.compile(r"^ArkTS/JS frontend: .*? (\d+) call site"),
    "ability_classes": re.compile(r"^Ability surface: (\d+)"),
    "bridge_sites": re.compile(r"^WebView bridge coverage: (\d+)"),
    "bridge_guarded": re.compile(r"(\d+) with an origin predicate"),
    "path_sinks": re.compile(r"^Taint coverage: (\d+) path sink"),
    "path_guarded": re.compile(r"(\d+) behind a same-function path predicate"),
    "eval_sites": re.compile(r"(\d+) eval site"),
    "native_modules": re.compile(r"^N-API binding map: (\d+) \.so module"),
    "native_signatures": re.compile(r"(\d+) function signature"),
    "native_calls": re.compile(r"(\d+) call site\(s\) into lib\*\.so imports"),
    "native_unmapped": re.compile(r"(\d+) unmapped"),
    "native_guarded": re.compile(
        r"(\d+) behind a same-function numeric predicate"),
}


def read_units(root):
    files = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(directory for directory in dirs
                         if directory not in SKIP_DIRS)
        for name in sorted(names):
            extension = os.path.splitext(name)[1].lower()
            if extension not in LANG:
                continue
            path = os.path.join(base, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                text = open(path, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            files.append((relative, LANG[extension], text))
    files.sort(key=lambda item: item[0])
    return files


def main(scan_root, out_path,
         repository="openharmony/applications_settings",
         commit="5e8af0a2a104bc634f8d5e18ed03db202cd1ea02"):
    files = read_units(scan_root)
    counts = Counter()
    findings = []
    coverage_lines = []
    for start in range(0, len(files), BATCH):
        chunk = files[start:start + BATCH]
        units = tuple(
            SourceUnit(relative, language, text,
                       hashlib.sha256(text.encode("utf-8")).hexdigest())
            for relative, language, text in chunk)
        request = ScanRequest("b3-census", repository, commit,
                              snapshot_digest(units),
                              "current-component:" + repository)
        result = ArkTsJsInterfaceDetector().detect(
            ScanContext(request, units, {}), units)
        assert result.status == "completed", result.status
        for path, status in result.file_outcomes:
            counts[(path.rsplit(".", 1)[1], status)] += 1
        for finding in result.findings:
            findings.append({"file": finding.file, "line": finding.line,
                             "rule": finding.rule_id,
                             "cwe": finding.candidate_cwe,
                             "symbol": finding.symbol,
                             "message": finding.message})
        coverage_lines.extend(
            line for line in result.limitations
            if line.startswith(("ArkTS/JS frontend:", "Ability surface:",
                                "WebView bridge coverage:", "Taint coverage:",
                                "N-API binding map:")))

    totals = {key: 0 for key in COUNTER_PATTERNS}
    for line in coverage_lines:
        for key, pattern in COUNTER_PATTERNS.items():
            match = pattern.search(line)
            if match:
                totals[key] += int(match.group(1))

    shape = {key: 0 for key in SHAPE_PATTERNS}
    for _path, _language, text in files:
        for key, pattern in SHAPE_PATTERNS.items():
            if pattern.search(text):
                shape[key] += 1

    payload = {
        "repository": repository,
        "commit": commit,
        "detector": ArkTsJsInterfaceDetector.detector_id,
        "detector_version": ArkTsJsInterfaceDetector.version,
        "files_seen": len(files),
        "by_language_status": {"%s/%s" % key: value
                               for key, value in sorted(counts.items())},
        "counters": totals,
        "findings_total": len(findings),
        "findings_by_rule": dict(sorted(
            Counter(item["rule"] for item in findings).items())),
        "findings": findings,
        "text_shape_files": shape,
        "dts_files": sum(1 for path, _language, _text in files
                         if path.endswith(".d.ts")),
        "batch_coverage_lines": coverage_lines,
        "limits": {
            "max_bytes": MAX_BYTES,
            "batch_size": BATCH,
            "excluded_dirs": sorted(SKIP_DIRS),
            "note": "Third-party source is not stored; only this aggregate "
                    "is kept. Shape counts are text matches, not findings. "
                    "The N-API binding map is rebuilt per batch of "
                    + str(BATCH) + " files, so a .d.ts declaration in another "
                    "batch is not visible to the calling file.",
        },
    }
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    print(json.dumps({key: payload[key] for key in
                      ("files_seen", "by_language_status", "counters",
                       "findings_total", "findings_by_rule", "text_shape_files")},
                     indent=2))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 5):
        raise SystemExit(
            "usage: census.py <scan-root> <out.json> [repository] [commit]")
    main(*sys.argv[1:])
