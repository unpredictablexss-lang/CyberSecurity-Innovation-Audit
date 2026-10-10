"""Assemble verified selected projects and probe the official missing-tools gate.

The workspace is explicitly incomplete. This command never runs a full product
build or downloads prebuilts; it records why real GN generation cannot start.
"""

import argparse
import json
import os
import shutil
from pathlib import Path

from scripts.run_graph_tool_experiments import execute
from src.benchmark.component import verify_snapshot
from src.benchmark.historical import _git
from src.benchmark.product_manifest import relative_path


def missing_prebuilt_gate(execution):
    native = execution['stdout'] + execution['stderr']
    return bool(execution['exit_code']) and any(text in native for text in (
        'Please execute the build/prebuilts_download.sh',
        'Node.js version mismatch. Expected 14.21.1'))


def isolated_command(native_command, read_only_paths=('/usr', '/root')):
    setup = ('set -e; probe_readonly_count=$1; shift; '
             'for ((probe_index=0; probe_index<probe_readonly_count; probe_index++)); do '
             'probe_readonly_path=$1; shift; mount --bind "$probe_readonly_path" "$probe_readonly_path"; '
             'mount -o remount,bind,ro "$probe_readonly_path"; done; exec "$@"')
    return ['unshare', '--mount', '--propagation', 'private', '--', 'bash', '-c', setup, 'product-probe',
            str(len(read_only_paths)), *read_only_paths, *native_command]


def probe(lock_file, snapshots, workspace, output):
    lock = json.loads(lock_file.read_text())
    if lock['experiment_kind'] != 'product_configuration_preflight' or lock['full_product_lock']:
        raise ValueError('This probe only accepts an explicitly partial product lock')
    projects = {item['name']: item for item in lock['projects']}
    if workspace.exists():
        raise ValueError('Use a new workspace; do not merge stale product sources')
    bindings = []
    for snapshot in snapshots:
        manifest = json.loads((snapshot / 'snapshot.json').read_text())
        name = manifest['repository'].split('/')[-1]
        project = projects[name]
        verify_snapshot(manifest, snapshot / 'source', repository='openharmony/' + name)
        if manifest['commit'] != project['resolved_commit']:
            raise ValueError('Source snapshot does not match resolved product lock')
        origin = _git(Path(manifest['source_repo']), ['remote', 'get-url', 'origin']).stdout.strip().removesuffix('.git')
        if origin != project['fetch_url'].removesuffix('.git'):
            raise ValueError('Snapshot source remote does not match official manifest')
        target = workspace / relative_path(project['path'])
        shutil.copytree(snapshot / 'source', target)
        bindings.append(dict(project=name, commit=manifest['commit'], tree=manifest['tree'], source_origin=origin))
        for operation in project['file_operations']:
            source = target / relative_path(operation['src'])
            destination = workspace / relative_path(operation['dest'])
            if not source.is_file() or destination.exists():
                raise ValueError('Manifest root operation source is absent or destination overlaps')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if operation['kind'] == 'linkfile':
                destination.symlink_to(os.path.relpath(source, destination.parent))
            else:
                shutil.copy2(source, destination)
    installed = {item['project'] for item in bindings}
    if not {'build', 'commonlibrary_c_utils', 'vendor_hihope'}.issubset(installed):
        raise ValueError('Probe requires build/component/product configuration sources')
    config_path = workspace / 'vendor/hihope' / lock['product'] / 'config.json'
    config = json.loads(config_path.read_text())
    if config['product_name'] != lock['product']:
        raise ValueError('Product config identity mismatch')
    python_candidates = list((workspace / 'prebuilts/python/linux-x86').glob('*/bin/python3'))
    if python_candidates:
        raise ValueError('Missing-tools probe must stop before official build initialization')
    if shutil.which('node') is not None:
        raise ValueError('Missing-tools probe requires Node absent so initialization cannot proceed')
    native_command = ['bash', str(workspace / 'build.sh'), '--product-name', lock['product'],
               '--build-target', 'commonlibrary/c_utils/base:utilsbase', '--build-only-gn',
               '--gn-flags=--export-compile-commands']
    # The upstream script can fall back to /bin/python3 and create /bin/python.
    # Keep system binaries and root's user configuration read-only in a private
    # mount namespace. Fail closed if namespace/mount setup is unavailable.
    command = isolated_command(native_command)
    execution = execute(command, workspace, os.environ.copy(), 30)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.with_suffix('.execution.json').write_text(json.dumps(execution, indent=2))
    if not missing_prebuilt_gate(execution):
        raise ValueError('Official entry did not stop at the expected missing-prebuilt gate')
    whitelist = json.loads((workspace / 'build/indep_component_whitelist.json').read_text())
    result = dict(experiment_kind='product_configuration_preflight', product=lock['product'],
        status='blocked', manifest_commit=lock['manifest_commit'], source_bindings=bindings,
        missing_selected_projects=sorted(set(projects) - installed),
        missing_product_inherits=[file for file in config.get('inherit', []) if not (workspace / relative_path(file)).is_file()],
        product_configuration=dict(target_cpu=config['target_cpu'], type=config['type'], board=config['board']),
        cutils_independent_build_whitelisted='c_utils' in whitelist['components'],
        independent_build_status='not_run', native_entry=execution,
        isolation=dict(private_mount_namespace=True, read_only_paths=['/usr', '/root']),
        compile_commands_status='not_generated', full_product_lock=False, validated_vulnerability=0,
        limitations=['Selected roots only, not complete transitive product dependencies.',
                     'Product prebuilt Python/Node/GN/Ninja/toolchain not installed.',
                     'Independent build also requires pinned HPM/package inputs; whitelist alone is not success.'])
    output.write_text(json.dumps(result, indent=2))
    for snapshot in snapshots:
        manifest = json.loads((snapshot / 'snapshot.json').read_text())
        project = projects[manifest['repository'].split('/')[-1]]
        verify_snapshot(manifest, workspace / project['path'], repository=manifest['repository'])
    print('Official GN entry:', result['status'], '; compile_commands:', result['compile_commands_status'], flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--snapshots', type=Path, nargs='+', required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    probe(args.lock, args.snapshots, args.workspace.resolve(), args.output)
