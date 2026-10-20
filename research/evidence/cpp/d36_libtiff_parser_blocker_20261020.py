from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.ohscanner.indexing import prepare_git_context
from src.parser.ast import parse_source


REVISIONS = {
    "vulnerable": "9dff73bebc5661f2dace6f16e14cf9e857172f4e",
    "fixed": "3e0dcf0ec651638b2bd849b2e6f3124b36890d99",
}
SCOPE = ("libtiff/tif_getimage.c", "libtiff/tiffio.h")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = {}
    for role, revision in REVISIONS.items():
        context, tree, _, _, sources = prepare_git_context(
            args.repo_dir, "libtiff/libtiff", revision, SCOPE,
        )
        units = {unit.path: unit for unit in context.units}
        source_by_path = {source.path: source for source in sources}
        files = {}
        for path in SCOPE:
            unit = units[path]
            source = source_by_path[path]
            lines = unit.text.splitlines()
            issues = []
            for encoded in unit.parse_issues:
                issue = json.loads(encoded)
                line = issue["start_line"]
                issues.append({
                    **issue,
                    "text": lines[line - 1].strip() if 0 < line <= len(lines) else "",
                })
            files[path] = {
                "blob": source.oid,
                "sha256": hashlib.sha256(source.data).hexdigest(),
                "language": unit.language,
                "parse_status": unit.parse_status,
                "parse_issue_count": len(issues),
                "parse_issues": issues,
                "indexed_functions": len(context.shared_facts["ast"][path]["functions"]),
            }
        header = source_by_path["libtiff/tiffio.h"].data.decode("utf-8")
        header_c = parse_source(header, language="c")
        header_cpp = parse_source(header, language="cpp")
        results[role] = {
            "commit": revision,
            "tree": tree,
            "files": files,
            "header_grammar_comparison": {
                "current_classification": "cpp",
                "cpp_status": header_cpp.parse_status,
                "cpp_issue_count": len(header_cpp.parse_issues),
                "c_status": header_c.parse_status,
                "c_issue_count": len(header_c.parse_issues),
                "c_issue_lines": sorted({
                    issue["start_line"] for issue in header_c.parse_issues
                }),
            },
        }
    record = {
        "schema_version": 1,
        "task": "D36 libtiff full translation unit parser blocker localization",
        "scanner_commit": git(Path.cwd(), "rev-parse", "HEAD"),
        "source_repository": "libtiff/libtiff (user-declared; exact local Git objects checked)",
        "scope": list(SCOPE),
        "source_revisions": results,
        "interpretation": (
            "The C translation unit has unexpanded macro invocation syntax errors; the .h file "
            "is classified as C++, where conditional-compilation alternatives produce missing "
            "nodes. Parsing the header as C also remains partial and is less complete. The "
            "current frontend has no compile-command or preprocessing input, so these full-TU "
            "partial statuses cannot be safely repaired by changing detector logic or by "
            "relabeling coverage."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    assert all(
        file["parse_status"] == "partial"
        for result in results.values() for file in result["files"].values()
    )
    assert all(
        result["files"]["libtiff/tif_getimage.c"]["parse_issue_count"] == 6
        for result in results.values()
    )
    assert all(
        result["files"]["libtiff/tiffio.h"]["parse_issue_count"] == 7
        for result in results.values()
    )
    print("D36 parser blocker reproduction: PASS (both exact source pairs remain partial)")


if __name__ == "__main__":
    main()
