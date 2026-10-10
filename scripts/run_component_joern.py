"""Run Joern on the pinned c_utils C/C++ scope with explicit parse coverage.

The runner records commands, hashes, native query output and coverage logs. A
query hit is only a structural candidate. Failed or partial extraction is
unknown, not a miss or a successful analysis.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath

from scripts.run_graph_tool_experiments import execute, has_parse_errors
from src.benchmark.component import verify_snapshot
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output

PROJECT = Path(__file__).resolve().parents[1]


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cpp_scope(manifest):
    records = []
    for item in manifest["files"]:
        if item.get("language_scope") != "cpp":
            continue
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or "\\" in str(path):
            raise ValueError("Unsafe C/C++ scope path")
        records.append({"path": str(path), "sha256": item["sha256"], "blob": item["blob"]})
    records.sort(key=lambda item: item["path"])
    if not records or len({item["path"] for item in records}) != len(records):
        raise ValueError("Missing or duplicated C/C++ scope")
    return records


def joern_version(joern):
    jars = list((joern / "lib").glob("io.joern.joern-cli-*.jar"))
    if len(jars) != 1:
        raise ValueError("Cannot identify a unique Joern installation")
    return jars[0].name.removeprefix("io.joern.joern-cli-").removesuffix(".jar")


def component_joern_coverage_issues(log, expected_files):
    issues = ["Joern parser reported problems"] if has_parse_errors(log) else []
    rows = {}
    for line in log.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5 or not cells[1]:
            continue
        rows[cells[1]] = cells
    for file in expected_files:
        match = None
        for name, cells in rows.items():
            if name == file or name.endswith("/" + file):
                match = cells
                break
        if match is None:
            issues.append("Missing parsed/CPG coverage row: " + file)
        elif len(match) < 5 or match[3].lower() != "yes" or match[4].lower() != "yes":
            issues.append("Incomplete parsed/CPG coverage row: " + file)
    return issues


def relative_findings(payload, source_root):
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ValueError("Joern query output must contain a findings list")
    converted = []
    for item in payload["findings"]:
        if not isinstance(item, dict):
            raise ValueError("Joern finding must be an object")
        result = dict(item)
        file = result.get("file")
        if isinstance(file, str) and file:
            path = Path(file)
            if path.is_absolute():
                try:
                    result["file"] = path.resolve().relative_to(source_root.resolve()).as_posix()
                except ValueError:
                    raise ValueError("Joern finding is outside pinned source: " + file)
                result["native_file"] = file
        converted.append(result)
    result = dict(payload)
    result["findings"] = converted
    return result


def analysis_interpretation(successful, coverage_issues):
    if not successful or coverage_issues:
        return "unknown"
    return "candidate_query_completed"


def run(snapshot, output, joern, query):
    manifest = json.loads((snapshot / "snapshot.json").read_text())
    root = snapshot / "source"
    verify_snapshot(manifest, root)
    scope = cpp_scope(manifest)
    files = [item["path"] for item in scope]
    version = joern_version(joern)
    output.mkdir(parents=True, exist_ok=True)
    native = output / "native.json"
    native.unlink(missing_ok=True)
    cpg = output / "cpg.bin"
    env = os.environ.copy()
    env.update(JOERN_CPG=str(cpg), JOERN_OUT=str(native), JOERN_VERSION=version,
               SL_LOGGING_LEVEL="INFO")
    commands = [
        [str(joern / "c2cpg.sh"), str(root), "--output", str(cpg), "--log-problems"],
        [str(joern / "joern"), "--script", str(query)],
    ]
    steps = []
    for index, command in enumerate(commands):
        step = execute(command, output if index else PROJECT, env, 600)
        steps.append(step)
        (output / ("c2cpg.log" if index == 0 else "query.log")).write_text(
            step["stdout"] + "\n" + step["stderr"]
        )
        execution = {
            "experiment_kind": "current_component",
            "repository": manifest["repository"],
            "commit": manifest["commit"],
            "snapshot_tree": manifest["tree"],
            "snapshot_manifest_path": str(snapshot / "snapshot.json"),
            "snapshot_manifest_sha256": sha256_file(snapshot / "snapshot.json"),
            "tool": "joern",
            "tool_version": version,
            "query_path": str(query.resolve()),
            "query_sha256": sha256_file(query),
            "scope_files": scope,
            "scope_loc": sum(len((root / item["path"]).read_text(errors="replace").splitlines())
                             for item in scope),
            "steps": steps,
        }
        (output / "execution.json").write_text(json.dumps(execution, indent=2))
        if step["exit_code"]:
            break

    log = steps[0]["stdout"] + "\n" + steps[0]["stderr"] if steps else ""
    coverage_issues = component_joern_coverage_issues(log, files)
    successful = (len(steps) == 2 and all(not step["exit_code"] for step in steps)
                  and native.exists())
    if not successful:
        coverage_issues.append("CPG generation/query failed or timed out")
    coverage_issues = list(dict.fromkeys(coverage_issues))
    payload = {"joern_version": version, "query": query.stem, "findings": []}
    if successful:
        payload = relative_findings(json.loads(native.read_text()), root)
    interpretation = analysis_interpretation(successful, coverage_issues)
    status = "completed" if successful and not coverage_issues else ("failed" if not successful else "blocked")
    limitations = [
        "Project-authored nothrow/null-guard structural query only; guard dominance is not proven.",
        "c2cpg runs without a product GN compile database and may partially parse build-dependent C++.",
        "Query hits remain candidates; absence of hits is not a miss or safety proof.",
    ] + coverage_issues
    normalized = normalize_tool_output("joern", payload, AdapterContext(
        run_id=manifest["commit"] + ":joern-component-nothrow-guard",
        target_id="current-component:" + manifest["repository"],
        commit=manifest["commit"], scope_files=len(scope),
        scope_loc=execution["scope_loc"] if steps else 0,
        elapsed_seconds=sum(step["elapsed_seconds"] for step in steps),
        status=status, tool_version=version, limitations=limitations,
    ))
    (output / "normalized.json").write_text(json.dumps(normalized.to_dict(), indent=2))
    summary = {
        "experiment_kind": "current_component",
        "repository": manifest["repository"],
        "commit": manifest["commit"],
        "snapshot_tree": manifest["tree"],
        "snapshot_manifest_sha256": sha256_file(snapshot / "snapshot.json"),
        "tool": "joern",
        "tool_version": version,
        "query": query.stem,
        "query_sha256": sha256_file(query),
        "scope_files": len(scope),
        "scope_loc": execution["scope_loc"] if steps else 0,
        "status": status,
        "analysis_interpretation": interpretation,
        "coverage_issues": coverage_issues,
        "diagnostics": len(normalized.diagnostics),
        "validated_vulnerability": 0,
        "runtime_validation": "not_run",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    execution["coverage_issues"] = coverage_issues
    execution["analysis_interpretation"] = interpretation
    (output / "execution.json").write_text(json.dumps(execution, indent=2))
    verify_snapshot(manifest, root)
    print("Joern component:", status, interpretation,
          "diagnostics:", len(normalized.diagnostics),
          "coverage issues:", len(coverage_issues), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--joern", type=Path, required=True)
    parser.add_argument("--query", type=Path, default=PROJECT / "scripts/joern_nothrow_guard.sc")
    args = parser.parse_args()
    run(args.snapshot.resolve(), args.output_dir.resolve(), args.joern.resolve(), args.query.resolve())
