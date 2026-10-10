"""Read verified snapshots and inventory bundle edges without executing install scripts."""
import argparse
import hashlib
import json
from pathlib import Path

from src.benchmark.component import verify_snapshot
from src.benchmark.component_dependencies import inventory_dependencies
from src.benchmark.historical import _git


def inventory(lock_file, snapshots, output):
    lock = json.loads(lock_file.read_text())
    if lock['experiment_kind'] != 'product_configuration_preflight' or lock['full_product_lock']:
        raise ValueError('Expected a partial product preflight lock')
    projects = {item['name']: item for item in lock['projects']}
    bundles = []
    for snapshot in snapshots:
        manifest = json.loads((snapshot / 'snapshot.json').read_text())
        verify_snapshot(manifest, snapshot / 'source', repository=manifest['repository'])
        project = projects[manifest['repository'].removeprefix('openharmony/')]
        origin = _git(Path(manifest['source_repo']), ['remote', 'get-url', 'origin']).stdout.strip()
        if manifest['commit'] != project['resolved_commit'] or origin.removesuffix('.git') != project['fetch_url'].removesuffix('.git'):
            raise ValueError('Snapshot does not match official lock/source remote')
        raw = (snapshot / 'source/bundle.json').read_bytes()
        bundles.append((dict(repository=manifest['repository'], commit=manifest['commit'], tree=manifest['tree'],
                             bundle_sha256=hashlib.sha256(raw).hexdigest()), json.loads(raw)))
    result = inventory_dependencies(bundles, 'c_utils')
    result['manifest_commit'] = lock['manifest_commit']
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(dict(status=result['status'], unresolved_components=result['unresolved_components'])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--snapshots', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inventory(args.lock, args.snapshots, args.output)
