"""Verify current-component snapshots without importing historical ground truth."""

import base64
import hashlib
from pathlib import Path, PurePosixPath

from src.core.scanner import SOURCE_SUFFIXES


def git_oid(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def tree_oid(records):
    nodes = {}
    for record in records:
        node = nodes
        parts = PurePosixPath(record['path']).parts
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        if parts[-1] in node:
            raise ValueError('Duplicate snapshot path')
        node[parts[-1]] = (record['mode'], record['blob'])

    def digest(node):
        data = b''
        for name, item in sorted(node.items(), key=lambda pair: (pair[0] + ('/' if isinstance(pair[1], dict) else '')).encode()):
            mode, oid = ('40000', digest(item)) if isinstance(item, dict) else item
            data += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
        return git_oid('tree', data)
    return digest(nodes)


def verify_snapshot(manifest, root, repository='openharmony/commonlibrary_c_utils'):
    if manifest.get('experiment_kind') != 'current_component':
        raise ValueError('Current-component experiment required; historical inputs are separate')
    if manifest.get('repository') != repository:
        raise ValueError('Component repository binding mismatch')
    raw_commit = base64.b64decode(manifest['commit_object_b64'], validate=True)
    if git_oid('commit', raw_commit) != manifest['commit']:
        raise ValueError('Commit object identity mismatch')
    if raw_commit.splitlines()[0] != ('tree ' + manifest['tree']).encode():
        raise ValueError('Commit/tree binding mismatch')
    paths = set()
    for record in manifest['files']:
        path = PurePosixPath(record['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in str(path):
            raise ValueError('Unsafe snapshot path')
        expected_scope = 'cpp' if path.suffix.lower() in SOURCE_SUFFIXES else 'other'
        if record.get('language_scope') != expected_scope:
            raise ValueError('Snapshot language scope mismatch')
        target = root / str(path)
        if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
            raise ValueError('Unsafe snapshot entry')
        data = target.read_bytes()
        if git_oid('blob', data) != record['blob'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('Snapshot content changed: ' + str(path))
        paths.add(str(path))
    actual = {path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
    if actual != paths or tree_oid(manifest['files']) != manifest['tree']:
        raise ValueError('Snapshot tree or file inventory mismatch')


def file_group(file):
    return 'tests' if 'test' in PurePosixPath(file).parts else 'production'


def validate_component_report(report, manifest):
    expected = 'current-component:' + manifest['repository']
    if report['target_id'] not in (expected, expected + ':utilsbase-linux-host-bootstrap'):
        raise ValueError('Component review target mismatch')
    if report['commit'] != manifest['commit']:
        raise ValueError('Component review commit mismatch')
