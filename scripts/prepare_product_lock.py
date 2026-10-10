"""Resolve a declared subset of official manifest refs; never claim a full product lock."""

import argparse
import datetime
import json
import os
import re
import signal
import subprocess
from pathlib import Path

from src.benchmark.component import verify_snapshot
from src.benchmark.product_manifest import read_manifest, select_projects, bind_resolution

PROJECTS = ('build', 'commonlibrary_c_utils', 'third_party_bounds_checking_function', 'hiviewdfx_hilog',
            'third_party_rust_cxx', 'vendor_hihope', 'device_board_hihope', 'device_soc_rockchip')


def resolve(project):
    revision = project['revision']
    if re.fullmatch(r'[0-9a-f]{40}', revision):
        return dict(fetch_url=project['fetch_url'], revision=revision, resolved_ref=revision, commit=revision,
                    method='manifest_pinned_commit; availability not checked')
    ref = 'refs/heads/' + revision
    command = ['git', '-c', 'http.version=HTTP/1.1', '-c', 'http.lowSpeedLimit=1', '-c', 'http.lowSpeedTime=10',
               'ls-remote', project['fetch_url'], ref]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               start_new_session=os.name != 'nt', env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        raise RuntimeError('Manifest ref resolution timed out: ' + project['name'])
    lines = stdout.strip().splitlines()
    if process.returncode or len(lines) != 1 or lines[0].split()[-1] != ref:
        raise RuntimeError('Unresolved manifest branch: ' + project['name'] + '; ' + stderr.strip())
    return dict(fetch_url=project['fetch_url'], revision=revision, resolved_ref=ref, commit=lines[0].split()[0],
                method='git ls-remote declared remote', command=command, stdout=stdout, stderr=stderr)


def prepare(snapshot, output):
    source = json.loads((snapshot / 'snapshot.json').read_text())
    verify_snapshot(source, snapshot / 'source', repository='openharmony/manifest')
    manifest = read_manifest(snapshot / 'source')
    selected = select_projects(manifest, PROJECTS)
    records, failures = [], []
    for project in selected:
        try:
            resolution = resolve(project)
            records.append(dict(bind_resolution(project, resolution), resolution_evidence=resolution))
            print(project['name'], resolution['commit'], flush=True)
        except RuntimeError as error:
            failures.append(dict(project=project['name'], reason=str(error)))
            print(project['name'], 'unknown:', error, flush=True)
    result = dict(schema_version=1, experiment_kind='product_configuration_preflight',
        product='rk3568', manifest_repository=source['repository'], manifest_commit=source['commit'],
        manifest_tree=source['tree'], observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_documents=manifest['documents'], manifest_project_count=len(manifest['projects']),
        selected_project_count=len(selected), projects=records, failures=failures,
        lock_scope='selected_component_and_product_roots_only', full_product_lock=False,
        limitations=['Floating master refs captured independently, not a release compatibility guarantee.',
                     'This selected subset is not the full transitive build dependency closure.'])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-snapshot', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.manifest_snapshot.resolve(), args.output)
