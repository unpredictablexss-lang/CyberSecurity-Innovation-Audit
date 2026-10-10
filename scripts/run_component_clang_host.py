"""Analyze the GN-listed utilsbase sources using an explicit Linux host bootstrap profile.

This is a reconstructed test configuration, not a GN-exported product build.
"""

import argparse
import hashlib
import json
import os
import re
from dataclasses import asdict
from pathlib import Path, PurePosixPath

from scripts.run_graph_tool_experiments import execute
from src.baseline.clang_analyzer import parse_clang_diagnostics
from src.benchmark.component import verify_snapshot
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output


def host_sources(gn):
    match = re.search(r'\bsources_utils\s*=\s*\[([^\]]+)\]', gn)
    if not match:
        raise ValueError('GN sources_utils list is missing')
    files = re.findall(r'"([^"]+)"', match.group(1))
    if not files or len(set(files)) != len(files):
        raise ValueError('Missing or duplicated GN sources')
    if any(PurePosixPath(file).is_absolute() or '..' in PurePosixPath(file).parts
           or not file.startswith('src/') or not file.endswith('.cpp') for file in files):
        raise ValueError('Unsupported GN source path')
    return ['base/' + file for file in files]


def run(snapshot, dependency, output, compile_only=False):
    manifest = json.loads((snapshot / 'snapshot.json').read_text())
    dep = json.loads((dependency / 'snapshot.json').read_text())
    root = snapshot / 'source'
    verify_snapshot(manifest, root)
    verify_snapshot(dep, dependency / 'source', repository='openharmony/third_party_bounds_checking_function')
    gn = (root / 'base/BUILD.gn').read_text()
    files = host_sources(gn)
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    version = execute(['clang++', '--version'], root, env, 10)
    if version['exit_code']:
        raise RuntimeError('Clang compiler unavailable')
    flags = ['-std=c++17', '-I', str(root / 'base/include'), '-I', str(root / 'base/src'),
             '-I', str(dependency / 'source/include')]
    commands = [dict(directory=str(root), file=str(root / file),
                     arguments=['clang++', *flags, '-c', str(root / file)]) for file in files]
    (output / 'compile_commands.bootstrap.json').write_text(json.dumps(commands, indent=2))
    if compile_only:
        objects = output / 'objects'
        objects.mkdir(exist_ok=True)
        records = []
        for file in files:
            step = execute(['clang++', *flags, '-c', file, '-o', str(objects / (Path(file).stem + '.o'))],
                           root, env, 60)
            records.append(dict(file=file, compilation=step))
            (output / 'compile_execution.json').write_text(json.dumps(records, indent=2))
            print(file, 'compile=' + str(step['exit_code']), flush=True)
        verify_snapshot(manifest, root)
        verify_snapshot(dep, dependency / 'source', repository=dep['repository'])
        if any(item['compilation']['exit_code'] for item in records):
            raise RuntimeError('Host object compilation failed; inspect compile_execution.json')
        return
    records, diagnostics = [], []
    for file in files:
        syntax = execute(['clang++', *flags, '-fsyntax-only', file], root, env, 45)
        analysis = None
        if not syntax['exit_code']:
            analysis = execute(['clang++', '--analyze', '-Xanalyzer', '-analyzer-output=text', *flags, file],
                               root, env, 60)
            diagnostics.extend(asdict(item) for item in parse_clang_diagnostics(analysis['stderr'], root))
        records.append(dict(file=file, syntax=syntax, analysis=analysis))
        print(file, 'syntax=' + str(syntax['exit_code']),
              'analysis=' + str(analysis['exit_code']) if analysis else 'analysis=not_run', flush=True)
        # Save after each unit so interruptions retain completed work.
        (output / 'execution.json').write_text(json.dumps(records, indent=2))
    completed = sum(item['analysis'] is not None and item['analysis']['exit_code'] == 0 for item in records)
    limitations = ['GN-listed utilsbase source list; reconstructed Linux host configuration, not product GN export.',
                   'C++17 and system Clang/libstdc++ are explicit bootstrap choices.',
                   'Host excludes ashmem, Rust-generated bridge, device CONFIG_HILOG/UTILS_FDSAN and tests.',
                   'securec commit is independently pinned, not verified against a product manifest dependency lock.']
    normalized = normalize_tool_output('clang_sa', {'diagnostics': diagnostics}, AdapterContext(
        run_id=manifest['commit'] + ':clang-host-bootstrap',
        target_id='current-component:' + manifest['repository'] + ':utilsbase-linux-host-bootstrap',
        commit=manifest['commit'], scope_files=len(files),
        scope_loc=sum(len((root / file).read_text().splitlines()) for file in files),
        elapsed_seconds=sum(item['syntax']['elapsed_seconds'] + (item['analysis']['elapsed_seconds'] if item['analysis'] else 0)
                            for item in records), status='completed' if completed == len(files) else 'blocked',
        tool_version=version['stdout'].splitlines()[0], limitations=limitations))
    summary = dict(experiment_kind='current_component', profile='utilsbase-linux-host-bootstrap',
                   commit=manifest['commit'], dependency_repository=dep['repository'], dependency_commit=dep['commit'],
                   gn_sha256=hashlib.sha256((root / 'base/BUILD.gn').read_bytes()).hexdigest(),
                   translation_units=len(files), analyzed_units=completed,
                   warnings=[item for item in diagnostics if item['level'] == 'warning'],
                   failed_units=[item['file'] for item in records if item['syntax']['exit_code'] or
                                 item['analysis'] is None or item['analysis']['exit_code']],
                   limitations=limitations, validated_vulnerability=0)
    verify_snapshot(manifest, root)
    verify_snapshot(dep, dependency / 'source', repository=dep['repository'])
    (output / 'normalized.json').write_text(json.dumps(normalized.to_dict(), indent=2))
    (output / 'summary.json').write_text(json.dumps(summary, indent=2))
    print('Host analysis:', completed, '/', len(files), 'warnings:', len(summary['warnings']), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--compile-only', action='store_true', help='Compile host objects for CodeQL tracing; do not link/run')
    args = parser.parse_args()
    run(args.snapshot.resolve(), args.dependency.resolve(), args.output_dir.resolve(), args.compile_only)
