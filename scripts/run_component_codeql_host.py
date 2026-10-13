"""Trace real host object compilation and run CodeQL; keep product-build limits explicit."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from scripts.run_component_clang_host import host_sources
from scripts.run_graph_tool_experiments import execute, codeql_coverage_issues
from src.benchmark.component import verify_snapshot
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output

PROJECT = Path(__file__).resolve().parents[1]


def run(snapshot, dependency, output, codeql, suite):
    manifest = json.loads((snapshot / 'snapshot.json').read_text())
    dep = json.loads((dependency / 'snapshot.json').read_text())
    root = snapshot / 'source'
    verify_snapshot(manifest, root)
    verify_snapshot(dep, dependency / 'source', repository='openharmony/third_party_bounds_checking_function')
    files = host_sources((root / 'base/BUILD.gn').read_text())
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # CodeQL starts its build command in source-root, not the audit project.
    env['PYTHONPATH'] = str(PROJECT) + os.pathsep + env.get('PYTHONPATH', '')
    version_step = execute([str(codeql), 'version', '--format=json'], PROJECT, env, 20)
    if version_step['exit_code']:
        raise RuntimeError('Cannot identify CodeQL')
    version = json.loads(version_step['stdout'])['version']
    database = output / 'database'
    native = output / 'results.sarif'
    native.unlink(missing_ok=True)
    # CodeQL's manual-build command splitter retains shell quotes in argv on
    # some Linux builds. These experiment paths are already space-free, so emit
    # a plain argv string rather than shell quoting.
    compile_command = ' '.join(['python3', '-m', 'scripts.run_component_clang_host',
        '--snapshot', str(snapshot), '--dependency', str(dependency),
        '--output-dir', str(output / 'build'), '--compile-only'])
    commands = [[str(codeql), 'database', 'create', str(database), '--language=cpp', '--build-mode=manual',
                 '--source-root=' + str(root), '--command=' + compile_command, '--overwrite'],
                [str(codeql), 'database', 'analyze', str(database), str(suite), '--format=sarifv2.1.0',
                 '--output=' + str(native), '--threads=2', '--ram=2048']]
    steps = []
    for command in commands:
        step = execute(command, PROJECT, env, 1200)
        steps.append(step)
        (output / 'execution.json').write_text(json.dumps(dict(commit=manifest['commit'],
            dependency_commit=dep['commit'], analyzed_files=files, tool_version=version, steps=steps,
            component_snapshot_sha256=hashlib.sha256((snapshot / 'snapshot.json').read_bytes()).hexdigest(),
            dependency_snapshot_sha256=hashlib.sha256((dependency / 'snapshot.json').read_bytes()).hexdigest(),
            suite=str(suite), suite_sha256=hashlib.sha256(suite.read_bytes()).hexdigest()), indent=2))
        if step['exit_code']:
            break
    successful = len(steps) == 2 and all(not step['exit_code'] for step in steps) and native.exists()
    payload = json.loads(native.read_text()) if successful else {'runs': []}
    issues = codeql_coverage_issues(payload, files)
    if not successful:
        issues.append('Database build/query failed or timed out')
    normalized = normalize_tool_output('codeql', payload, AdapterContext(
        run_id=manifest['commit'] + ':codeql-host-bootstrap',
        target_id='current-component:' + manifest['repository'] + ':utilsbase-linux-host-bootstrap',
        commit=manifest['commit'], scope_files=len(files), scope_loc=sum(len((root / file).read_text().splitlines()) for file in files),
        elapsed_seconds=sum(step['elapsed_seconds'] for step in steps), status='blocked' if issues else 'completed',
        tool_version=version, limitations=['Real object compilation from a reconstructed Linux host profile; not product GN export.',
            'Host excludes ashmem, Rust bridge, device macros and tests; dependency not product-manifest locked.', *issues]))
    (output / 'normalized.json').write_text(json.dumps(normalized.to_dict(), indent=2))
    (output / 'summary.json').write_text(json.dumps(dict(experiment_kind='current_component', repository=manifest['repository'],
        dependency_repository=dep['repository'], dependency_commit=dep['commit'],
        commit=manifest['commit'], profile='utilsbase-linux-host-bootstrap',
        translation_units=len(files), status=normalized.status, diagnostics=len(normalized.diagnostics),
        coverage_issues=issues, validated_vulnerability=0), indent=2))
    verify_snapshot(manifest, root)
    verify_snapshot(dep, dependency / 'source', repository=dep['repository'])
    print('CodeQL host:', normalized.status, 'diagnostics:', len(normalized.diagnostics), 'coverage issues:', issues, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--codeql', type=Path, required=True)
    parser.add_argument('--suite', type=Path, required=True)
    args = parser.parse_args()
    run(args.snapshot.resolve(), args.dependency.resolve(), args.output_dir.resolve(), args.codeql, args.suite)
