"""Run light static scanners on a verified full component, apart from historical matrices."""

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from dataclasses import replace
from importlib.metadata import distributions, version
from pathlib import Path

from scripts.run_graph_tool_experiments import execute
from src.benchmark.component import verify_snapshot, file_group
from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.core.scanner import scan_directory
from src.core.ast_scanner import scan_directory_ast
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output

PROJECT = Path(__file__).resolve().parents[1]


def run(snapshot, output, semgrep_root):
    manifest = json.loads((snapshot / 'snapshot.json').read_text())
    root = snapshot / 'source'
    verify_snapshot(manifest, root)
    output.mkdir(parents=True, exist_ok=True)
    files = sorted(item['path'] for item in manifest['files'] if item['language_scope'] == 'cpp')
    loc = sum(len((root / file).read_text().splitlines()) for file in files)
    target_id = 'current-component:' + manifest['repository']
    summaries = []
    for tool in ('own_text', 'own_ast', 'cppcheck', 'semgrep', 'semgrep_oh'):
        started = time.perf_counter()
        issues = []
        metadata = dict(experiment_kind='current_component', commit=manifest['commit'],
                        repository=manifest['repository'], analyzed_files=files,
                        snapshot_sha256=hashlib.sha256((snapshot / 'snapshot.json').read_bytes()).hexdigest())
        if tool.startswith('own_'):
            scanner = scan_directory_ast if tool == 'own_ast' else scan_directory
            result = scanner(root, include_paths=files)
            issues.extend(result.skipped_files)
            parsing = [{**item, 'file': Path(item['file']).relative_to(root).as_posix()} for item in result.parsing]
            if result.scanned_files != len(files):
                issues.append('Scanner file coverage differs from declared scope')
            if any(item['status'] != 'complete' for item in parsing):
                issues.append('AST parsing is partial or failed; inspect per-file coverage')
            diagnostics = [ToolDiagnostic(
                diagnostic_id=f'{tool}:{index}', provider=tool,
                evidence_type='syntax' if tool == 'own_ast' else 'pattern',
                file=Path(item.file_path).relative_to(root).as_posix(), line=item.line, column=None,
                rule_id=item.rule_id, severity=item.severity, message=item.explanation,
                candidate_cwe=item.cwe, symbol=item.function) for index, item in enumerate(result.findings)]
            normalized = ToolRunResult(schema_version=1, run_id=manifest['commit'] + ':' + tool,
                tool=tool, tool_version=version('tree-sitter') if tool == 'own_ast' else 'text-v1',
                target_id=target_id, commit=manifest['commit'], scope_files=len(files), scope_loc=loc,
                status='blocked' if issues else 'completed', elapsed_seconds=time.perf_counter() - started,
                diagnostics=diagnostics, parsing=parsing, limitations=['Dangerous-call candidates only.'])
            native = json.dumps(result.to_dict(), indent=2)
        else:
            env = os.environ.copy()
            if tool == 'cppcheck':
                command = ['cppcheck', '--xml', '--xml-version=2', '--enable=warning,style,performance,portability',
                           '--inconclusive', *files]
                provider = tool
                tool_version = execute(['cppcheck', '--version'], root, env, 10)['stdout'].strip()
            else:
                configs = [PROJECT / 'rules/cpp/vendor/raptor'] if tool == 'semgrep' else [
                    PROJECT / 'rules/cpp/oh_shared_ptr_uaf.yaml', PROJECT / 'rules/cpp/oh_nothrow_null_deref.yaml']
                command = [str(semgrep_root / 'bin/semgrep'), 'scan', '--metrics=off', '--disable-version-check',
                           '--quiet', '--json', '--no-git-ignore', '--jobs=2', '--timeout=10']
                rule_files = []
                for config in configs:
                    command += ['--config', str(config)]
                    rule_files += sorted(config.rglob('*.yaml')) if config.is_dir() else [config]
                command += files
                env['PYTHONPATH'] = str(semgrep_root)
                env['PATH'] = str(semgrep_root / 'bin') + os.pathsep + env.get('PATH', '')
                env['SEMGREP_SEND_METRICS'] = 'off'
                metadata['rules_sha256'] = {str(path.relative_to(PROJECT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                           for path in rule_files}
                provider = 'semgrep'
                tool_version = next(dist.version for dist in distributions(path=[str(semgrep_root)])
                                    if dist.metadata.get('Name', '').lower() == 'semgrep')
            step = execute(command, root, env, 300)
            metadata['execution'] = step
            if step['exit_code']:
                issues.append('Process failed or timed out; native output retained')
            native = step['stderr'] if tool == 'cppcheck' else step['stdout']
            if tool == 'cppcheck':
                payload = native if native.strip().startswith('<?xml') or native.strip().startswith('<results') else '<results/>'
            else:
                try:
                    payload = json.loads(native)
                except json.JSONDecodeError:
                    payload = {'results': []}
                    issues.append('Invalid/missing native JSON')
                if payload.get('errors'):
                    issues.append('Semgrep reported analysis errors or partial parsing')
                if set(payload.get('paths', {}).get('scanned', [])) != set(files):
                    issues.append('Semgrep scanned-file inventory differs from declared scope')
            normalized = normalize_tool_output(provider, payload, AdapterContext(
                run_id=manifest['commit'] + ':' + tool, target_id=target_id, commit=manifest['commit'],
                scope_files=len(files), scope_loc=loc, elapsed_seconds=step['elapsed_seconds'],
                status='failed' if issues else 'completed', tool_version=tool_version,
                limitations=['No original build flags, external dependency headers or vulnerability verdict.']))
            normalized.tool = tool
            normalized.diagnostics = [replace(item, file=Path(item.file).relative_to(root).as_posix())
                if Path(item.file).is_absolute() and Path(item.file).is_relative_to(root) else item
                for item in normalized.diagnostics]
            if tool == 'cppcheck' and any(item.rule_id in ('syntaxError', 'internalError', 'preprocessorErrorDirective')
                                         for item in normalized.diagnostics):
                issues.append('Cppcheck reported parser/configuration errors')
        if any(item.file not in files for item in normalized.diagnostics):
            issues.append('Diagnostic location outside or unresolved in declared scope')
        if issues:
            normalized.status = 'blocked' if tool.startswith('own_') else 'failed'
        normalized.limitations += issues
        metadata['coverage_issues'] = issues
        (output / (tool + '.native.txt')).write_text(native)
        (output / (tool + '.execution.json')).write_text(json.dumps(metadata, indent=2))
        (output / (tool + '.normalized.json')).write_text(json.dumps(normalized.to_dict(), indent=2))
        groups = Counter(file_group(item.file) if item.file in files else 'unresolved' for item in normalized.diagnostics)
        summaries.append(dict(tool=tool, status=normalized.status, diagnostics=len(normalized.diagnostics),
                              groups=dict(groups), issues=issues,
                              parsing=dict(Counter(item['status'] for item in normalized.parsing))))
        print(tool, normalized.status, len(normalized.diagnostics), dict(groups), flush=True)
    # Recheck the immutable scope after every scanner has run.
    verify_snapshot(manifest, root)
    summary = dict(experiment_kind='current_component', repository=manifest['repository'], commit=manifest['commit'],
                   tracked_files=len(manifest['files']), scope_files=len(files), scope_loc=loc,
                   file_groups=dict(Counter(file_group(file) for file in files)), tools=summaries,
                   validated_vulnerability=0, deep_analysis_status='not_run',
                   interpretation='Raw diagnostic counts only; no historical hit/miss, precision or vulnerability conclusion.')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--semgrep-root', type=Path, required=True)
    args = parser.parse_args()
    run(args.snapshot.resolve(), args.output_dir.resolve(), args.semgrep_root.resolve())
