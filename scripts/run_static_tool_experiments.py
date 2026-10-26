"""Run scoped static tools over already-prepared historical snapshots.

Consumes replay_static_baselines artifacts. Keeps native logs and normalized
results; providers still only normalize. No builds, PoC or vulnerability votes.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from importlib.metadata import distributions

from src.baseline.clang_analyzer import run_clang_analyzer
from src.benchmark.historical import load_sample, _show_file
from src.benchmark.report_inputs import DEFAULT_TOOLS, load_report_runs
from src.benchmark.tool_matrix import build_tool_matrix, write_reports as write_matrix
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output
from src.report.benchmark_report import build_benchmark_report, write_reports


PROJECT = Path(__file__).resolve().parents[1]


def summarize_experiments(output_dir):
    manifest_path = output_dir / "inputs.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = [load_sample(path) for path in sorted((PROJECT / "benchmarks/historical").glob("*.json"))]
    for sample in samples:
        for revision in ("vulnerable", "fixed"):
            paths = []
            for entry in manifest["runs"]:
                if entry["sample_id"] != sample.sample_id or entry["revision"] != revision:
                    continue
                path = output_dir / entry["report"]
                run = json.loads(path.read_text(encoding="utf-8"))
                if run["status"] == "completed" and not any(item["status"] != "complete" for item in run.get("parsing", [])):
                    paths.append(path)
            if paths:
                stem = f"{sample.sample_id}.{revision}.tools.matrix"
                write_matrix(build_tool_matrix(paths), output_dir / f"{stem}.json", output_dir / f"{stem}.md")
    summary = build_benchmark_report(samples, runs=load_report_runs(manifest_path, samples), tools=DEFAULT_TOOLS)
    write_reports(summary, output_dir / "summary.json", output_dir / "summary.md")


def experiments(output_dir, semgrep_root):
    manifest_path = output_dir / "inputs.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = [entry for entry in manifest["runs"] if ".text.json" in entry["report"] or ".ast.json" in entry["report"]]
    samples = []
    semgrep_version = next((distribution.version for distribution in distributions(path=[str(semgrep_root)])
                            if distribution.metadata.get("Name", "").lower() == "semgrep"), "unknown")
    for sample_path in sorted((PROJECT / "benchmarks/historical").glob("*.json")):
        sample = load_sample(sample_path)
        samples.append(sample)
        historical_path = output_dir / f"{sample_path.stem}.historical.json"
        if not historical_path.exists():
            continue
        historical = json.loads(historical_path.read_text(encoding="utf-8"))
        repo = Path(historical["repo_dir"])
        for revision in ("vulnerable", "fixed"):
            commit = getattr(sample, f"{revision}_commit")
            with tempfile.TemporaryDirectory(prefix="oh-tool-experiment-") as directory:
                root = Path(directory)
                loc = 0
                for file in sample.affected_files:
                    code = _show_file(repo, commit, file)
                    target = root / file
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(code, encoding="utf-8")
                    loc += len(code.splitlines())
                for tool in ("cppcheck", "clang_sa", "semgrep", "semgrep_oh"):
                    prefix = f"{sample_path.stem}.{revision}.{tool}"
                    started = time.perf_counter()
                    status, reason, incompatible = "completed", "", False
                    metadata = {"sample_id": sample.sample_id, "commit": commit, "revision": revision,
                                "tool": tool, "files": sample.affected_files}
                    if tool == "clang_sa":
                        result = run_clang_analyzer(root, sample.affected_files)
                        payload = result.to_dict()
                        metadata["file_results"] = payload["file_results"]
                        if result.failed_files:
                            status = "blocked"
                            reason = "Clang cannot form a translation unit: " + "; ".join(
                                item.stderr.strip() for item in result.file_results if item.exit_code)
                            incompatible = all("file not found" in item.stderr and "fatal error:" in item.stderr
                                               for item in result.file_results if item.exit_code)
                        native = json.dumps(payload, indent=2)
                        provider = "clang_sa"
                        version = result.clang_version
                    else:
                        env = os.environ.copy()
                        if tool == "cppcheck":
                            command = ["cppcheck", "--xml", "--xml-version=2", "--enable=warning,style,performance,portability",
                                       "--inconclusive", *sample.affected_files]
                            provider = "cppcheck"
                            version = subprocess.run(["cppcheck", "--version"], capture_output=True, text=True, check=True).stdout.strip()
                        else:
                            configs = [PROJECT / "rules/cpp/vendor/raptor"] if tool == "semgrep" else [
                                PROJECT / "rules/cpp/oh_shared_ptr_uaf.yaml", PROJECT / "rules/cpp/oh_nothrow_null_deref.yaml"]
                            command = [str(semgrep_root / "bin/semgrep"), "scan", "--metrics=off", "--disable-version-check",
                                       "--quiet", "--json", "--no-git-ignore", "--jobs=1", "--timeout=10"]
                            for config in configs:
                                command.extend(["--config", str(config)])
                            command.extend(sample.affected_files)
                            env["PYTHONPATH"] = str(semgrep_root)
                            env["PATH"] = str(semgrep_root / "bin") + os.pathsep + env.get("PATH", "")
                            env["SEMGREP_SEND_METRICS"] = "off"
                            provider, version = "semgrep", semgrep_version
                            rule_files = [file for config in configs for file in
                                          (sorted(config.rglob("*.yaml")) if config.is_dir() else [config])]
                            metadata["rules_sha256"] = {str(file.relative_to(PROJECT)): hashlib.sha256(file.read_bytes()).hexdigest()
                                                        for file in rule_files}
                        try:
                            process = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=60)
                            metadata.update(command=command, exit_code=process.returncode, stdout=process.stdout, stderr=process.stderr)
                            native = process.stderr if tool == "cppcheck" else process.stdout
                            payload = native if tool == "cppcheck" else json.loads(native)
                            if process.returncode or (tool.startswith("semgrep") and payload.get("errors")):
                                status = "failed"
                                reason = "Static tool failed or reported partial analysis; inspect the native log."
                        except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                            status, reason = "failed", str(error)
                            payload = "<results/>" if tool == "cppcheck" else {"results": []}
                            native = str(error)
                    elapsed = time.perf_counter() - started
                    (output_dir / f"{prefix}.native.txt").write_text(native, encoding="utf-8")
                    (output_dir / f"{prefix}.execution.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
                    normalized = normalize_tool_output(provider, payload, AdapterContext(
                        run_id=prefix, target_id=sample.sample_id, commit=commit, scope_files=len(sample.affected_files),
                        scope_loc=loc, elapsed_seconds=elapsed, status=status, tool_version=version,
                        limitations=["Affected-file snapshots only; no real build flags or dependency headers.",
                                     f"Native log: {prefix}.native.txt; execution log: {prefix}.execution.json"],
                    ))
                    normalized.tool = tool
                    normalized.diagnostics = [replace(item, file=Path(item.file).relative_to(root).as_posix())
                                              if Path(item.file).is_absolute() and Path(item.file).is_relative_to(root)
                                              else item for item in normalized.diagnostics]
                    if status == "completed" and any(not item.file for item in normalized.diagnostics):
                        normalized.status, reason = "blocked", "Diagnostic location is unresolved; native evidence retained."
                    report_name = f"{prefix}.normalized.json"
                    (output_dir / report_name).write_text(json.dumps(normalized.to_dict(), indent=2) + "\n", encoding="utf-8")
                    entry = {"sample_id": sample.sample_id, "revision": revision, "report": report_name,
                             "analyzed_files": sample.affected_files, "source_repo": str(repo)}
                    if reason:
                        entry["not_applicable_reason" if incompatible else "reason"] = reason
                    entries.append(entry)
                    print(f"[RUN] {prefix}: {normalized.status}; diagnostics={len(normalized.diagnostics)}", flush=True)
    manifest["runs"] = entries
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summarize_experiments(output_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/reports/static_baselines"))
    parser.add_argument("--semgrep-root", type=Path)
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args()
    if args.summarize_only:
        summarize_experiments(args.output_dir.resolve())
    elif args.semgrep_root is None:
        parser.error("--semgrep-root is required to execute scans")
    else:
        experiments(args.output_dir.resolve(), args.semgrep_root.resolve())


if __name__ == "__main__":
    main()
