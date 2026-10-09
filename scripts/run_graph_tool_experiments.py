"""Execute CodeQL and Joern on pinned affected-file snapshots, retaining logs."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from dataclasses import replace
from pathlib import Path

from scripts.run_static_tool_experiments import PROJECT, summarize_experiments
from src.benchmark.historical import load_sample, _show_file
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output


def execute(command, cwd, env, timeout):
    start = time.perf_counter()
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return dict(command=command, exit_code=process.returncode, stdout=stdout,
                    stderr=stderr, elapsed_seconds=time.perf_counter() - start)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return dict(command=command, exit_code=-1, stdout=stdout, stderr=stderr,
                    timeout=True, elapsed_seconds=time.perf_counter() - start)


def run(output, codeql, joern, suite, timeout, tools=('codeql', 'joern')):
    version_step = execute([str(codeql), 'version', '--format=json'], output, os.environ.copy(), timeout)
    if version_step['exit_code']:
        raise RuntimeError('Cannot identify CodeQL installation')
    codeql_version = json.loads(version_step['stdout'])['version']
    jars = list((joern / 'lib').glob('io.joern.joern-cli-*.jar'))
    if len(jars) != 1:
        raise RuntimeError('Cannot identify a unique Joern installation')
    joern_version = jars[0].name.removeprefix('io.joern.joern-cli-').removesuffix('.jar')
    manifest_path = output / 'inputs.json'
    manifest = json.loads(manifest_path.read_text())
    for sample_path in sorted((PROJECT / 'benchmarks/historical').glob('*.json')):
        sample = load_sample(sample_path)
        historical = json.loads((output / f'{sample_path.stem}.historical.json').read_text())
        repo = Path(historical['repo_dir'])
        for revision in ('vulnerable', 'fixed'):
            commit = getattr(sample, f'{revision}_commit')
            for tool in tools:
                prefix = f'{sample_path.stem}.{revision}.{tool}'
                directory = output / prefix
                directory.mkdir(exist_ok=True)
                root = directory / 'source'
                loc = 0
                hashes = {}
                for file in sample.affected_files:
                    code = _show_file(repo, commit, file)
                    target = root / file
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(code, encoding='utf-8')
                    loc += len(code.splitlines())
                    hashes[file] = hashlib.sha256(target.read_bytes()).hexdigest()
                env = os.environ.copy()
                native = directory / ('results.sarif' if tool == 'codeql' else 'findings.json')
                native.unlink(missing_ok=True)
                if tool == 'codeql':
                    database = directory / 'database'
                    commands = [[str(codeql), 'database', 'create', str(database), '--language=cpp',
                                 '--build-mode=none', '--source-root=' + str(root), '--overwrite'],
                                [str(codeql), 'database', 'analyze', str(database), str(suite),
                                 '--format=sarifv2.1.0', '--output=' + str(native), '--threads=2', '--ram=2048']]
                    version = codeql_version
                    rules = {'suite': str(suite), 'suite_sha256': hashlib.sha256(suite.read_bytes()).hexdigest()}
                else:
                    cpg = directory / 'cpg.bin'
                    query = PROJECT / 'scripts/joern_nothrow_guard.sc'
                    env.update(JOERN_CPG=str(cpg), JOERN_OUT=str(native), JOERN_VERSION=joern_version,
                               SL_LOGGING_LEVEL='INFO')
                    commands = [[str(joern / 'c2cpg.sh'), str(root), '--output', str(cpg), '--log-problems'],
                                [str(joern / 'joern'), '--script', str(query)]]
                    version = joern_version
                    rules = {'query_sha256': hashlib.sha256(query.read_bytes()).hexdigest()}
                steps = []
                for command in commands:
                    step = execute(command, directory, env, timeout)
                    steps.append(step)
                    if step['exit_code']:
                        break
                successful = len(steps) == len(commands) and all(not step['exit_code'] for step in steps) and native.exists()
                # Successful process exit alone cannot establish complete extraction.
                log = '\n'.join(step['stdout'] + step['stderr'] for step in steps)
                partial = has_parse_errors(log)
                status = 'completed' if successful and not partial else 'failed'
                payload = json.loads(native.read_text()) if successful else ({'runs': []} if tool == 'codeql' else {'findings': []})
                metadata = dict(sample_id=sample.sample_id, commit=commit, revision=revision, tool=tool,
                                source_sha256=hashes, steps=steps, rules=rules, partial=partial)
                (directory / 'execution.json').write_text(json.dumps(metadata, indent=2))
                normalized = normalize_tool_output(tool, payload, AdapterContext(
                    run_id=prefix, target_id=sample.sample_id, commit=commit,
                    scope_files=len(sample.affected_files), scope_loc=loc,
                    elapsed_seconds=sum(step['elapsed_seconds'] for step in steps), status=status,
                    tool_version=version, limitations=['Affected-file snapshots; no build flags or dependency headers.',
                                                       'Joern query is a structural null-guard heuristic only.' if tool == 'joern' else 'CodeQL no-build extraction; inspect extraction logs.']))
                normalized.diagnostics = [replace(item, file=Path(item.file).relative_to(root).as_posix())
                                          if Path(item.file).is_absolute() and Path(item.file).is_relative_to(root)
                                          else item for item in normalized.diagnostics]
                report = directory / 'normalized.json'
                report.write_text(json.dumps(normalized.to_dict(), indent=2))
                entry = dict(sample_id=sample.sample_id, revision=revision, report=report.relative_to(output).as_posix(),
                             analyzed_files=sample.affected_files, source_repo=str(repo))
                if status != 'completed':
                    entry['reason'] = 'Graph tool failed, timed out or reported partial parsing; see execution.json.'
                manifest['runs'] = [item for item in manifest['runs'] if not (
                    item['sample_id'] == sample.sample_id and item['revision'] == revision
                    and (item['report'] == entry['report']))] + [entry]
                manifest_path.write_text(json.dumps(manifest, indent=2))
                print(f'{prefix}: {status}; diagnostics={len(normalized.diagnostics)}', flush=True)
    reconcile_coverage(output)


def has_parse_errors(log):
    """Treat explicit parser problems conservatively, ignoring zero-count summaries."""
    return any(re.search(r'parse problem|failed to parse|syntax error', line, re.I)
               and not re.search(r'\b0 (?:parse problems|syntax errors)\b', line, re.I)
               for line in log.splitlines())


def codeql_coverage_issues(payload, expected_files):
    extracted = set()
    issues = []
    for run in payload.get('runs', []):
        for metric in run.get('properties', {}).get('metricResults', []):
            if metric.get('ruleId') == 'cpp/telemetry/failed-includes' and metric.get('value', 0) > 0:
                issues.append('Missing include: ' + metric.get('message', {}).get('text', 'unknown'))
        for invocation in run.get('invocations', []):
            for notice in invocation.get('toolExecutionNotifications', []):
                if notice.get('level') == 'error':
                    issues.append(notice.get('message', {}).get('text', 'Extractor error'))
                if notice.get('descriptor', {}).get('id') == 'cpp/diagnostics/successfully-extracted-files':
                    for location in notice.get('locations', []):
                        extracted.add(location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri'))
    if not set(expected_files).issubset(extracted):
        issues.append('Expected files lack successful extraction evidence')
    return issues


def joern_coverage_issues(metadata, expected_files):
    steps = metadata.get('steps', [])
    if not steps:
        return ['Missing CPG execution log']
    log = steps[0].get('stdout', '') + steps[0].get('stderr', '')
    issues = ['Joern parser reported problems'] if has_parse_errors(log) else []
    for file in expected_files:
        pattern = r'\|\s*' + re.escape(file) + r'\s*\|\s*\d+\s*\|\s*yes\s*\|\s*yes\s*\|'
        if not re.search(pattern, log):
            issues.append('Missing parsed/CPG coverage row: ' + file)
    return issues


def reconcile_coverage(output):
    manifest_path = output / 'inputs.json'
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest['runs']:
        report_path = output / entry['report']
        if report_path.parent.name.endswith('.codeql'):
            native = report_path.parent / 'results.sarif'
            if not native.exists():
                logs = list((report_path.parent / 'database/log').glob('database-create-*.log'))
                if any('Extraction failed: No source files found.' in path.read_text() for path in logs):
                    entry.pop('reason', None)
                    entry['not_applicable_reason'] = 'CodeQL no-build rejected this header-only analysis unit: No source files found.'
                continue
            report = json.loads(report_path.read_text())
            issues = codeql_coverage_issues(json.loads(native.read_text()), entry['analyzed_files'])
            if issues:
                report['status'] = 'failed'
                report['limitations'] = list(dict.fromkeys(report['limitations'] + issues))
                entry['reason'] = 'CodeQL extraction coverage is incomplete: ' + '; '.join(issues)
                report_path.write_text(json.dumps(report, indent=2))
        elif report_path.parent.name.endswith('.joern'):
            metadata = json.loads((report_path.parent / 'execution.json').read_text())
            issues = joern_coverage_issues(metadata, entry['analyzed_files'])
            if issues:
                report = json.loads(report_path.read_text())
                report['status'] = 'failed'
                report['limitations'] = list(dict.fromkeys(report['limitations'] + issues))
                entry['reason'] = 'Joern parsing coverage is incomplete: ' + '; '.join(issues)
                report_path.write_text(json.dumps(report, indent=2))
    manifest_path.write_text(json.dumps(manifest, indent=2))
    summarize_experiments(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=PROJECT / 'outputs/reports/static_baselines')
    parser.add_argument('--codeql', type=Path)
    parser.add_argument('--joern', type=Path)
    parser.add_argument('--suite', type=Path)
    parser.add_argument('--reconcile-only', action='store_true')
    parser.add_argument('--tools', nargs='+', choices=['codeql', 'joern'], default=['codeql', 'joern'])
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.reconcile_only:
        reconcile_coverage(args.output_dir.resolve())
    else:
        if not all((args.codeql, args.joern, args.suite)):
            parser.error('--codeql, --joern and --suite are required for execution')
        run(args.output_dir.resolve(), args.codeql, args.joern, args.suite, args.timeout, args.tools)
