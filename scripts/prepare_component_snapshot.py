"""Materialize every regular Git blob of a pinned component; never fetch/checkout."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath

from src.benchmark.historical import _git
from src.core.scanner import SOURCE_SUFFIXES


def safe_path(root, relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or '\\' in relative:
        raise ValueError('Unsafe snapshot path: ' + relative)
    target = root.joinpath(*path.parts).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError('Snapshot path escapes root')
    return target


def prepare(repo, commit, output, repository='openharmony/commonlibrary_c_utils'):
    origin = _git(repo, ['remote', 'get-url', 'origin']).stdout.strip().removesuffix('.git')
    if not (origin.endswith('/' + repository) or origin.endswith(':' + repository)):
        raise ValueError('Component repository identity mismatch')
    resolved = _git(repo, ['rev-parse', commit + '^{commit}']).stdout.strip()
    if resolved != commit:
        raise ValueError('Use the full immutable commit SHA')
    head = _git(repo, ['rev-parse', 'HEAD']).stdout.strip()
    tree = _git(repo, ['rev-parse', commit + '^{tree}']).stdout.strip()
    commit_bytes = subprocess.run(['git', '-C', str(repo), 'cat-file', 'commit', commit],
                                  capture_output=True, check=True, timeout=20).stdout
    records = []
    raw_tree = _git(repo, ['ls-tree', '-r', '-z', commit]).stdout
    for line in raw_tree.split('\0'):
        if not line:
            continue
        metadata, path = line.split('\t', 1)
        mode, kind, oid = metadata.split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('Snapshot requires explicit handling for nonregular entry: ' + path)
        records.append(dict(path=path, mode=mode, blob=oid))
    root = output / 'source'
    if root.exists():
        raise ValueError('Use a new output directory to avoid stale snapshot files')
    # Batch immutable objects; no lazy network transport even in a partial clone.
    process = subprocess.run(['git', '-c', 'remote.origin.promisor=false', '-C', str(repo), 'cat-file', '--batch'],
                             input=''.join(record['blob'] + '\n' for record in records).encode(),
                             capture_output=True, check=True, timeout=60,
                             env=dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_ALLOW_PROTOCOL=''))
    offset = 0
    for record in records:
        end = process.stdout.index(b'\n', offset)
        oid, kind, size = process.stdout[offset:end].decode().split()
        if oid != record['blob'] or kind != 'blob':
            raise ValueError('Unavailable or mismatched Git blob')
        size = int(size)
        data = process.stdout[end + 1:end + 1 + size]
        offset = end + size + 2
        if hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + data).hexdigest() != oid:
            raise ValueError('Snapshot blob hash mismatch')
        target = safe_path(root, record['path'])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        record.update(bytes=size, sha256=hashlib.sha256(data).hexdigest(),
                      language_scope='cpp' if target.suffix.lower() in SOURCE_SUFFIXES else 'other')
    if _git(repo, ['rev-parse', 'HEAD']).stdout.strip() != head:
        raise ValueError('Target HEAD changed during preparation')
    manifest = dict(schema_version=1, experiment_kind='current_component', repository=repository,
                    commit=commit, tree=tree, source_repo=str(repo), files=records,
                    commit_object_b64=base64.b64encode(commit_bytes).decode(),
                    limitations=['C/C++ scanner scope excludes Rust, build files and documentation.'])
    (output / 'snapshot.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--repository', default='openharmony/commonlibrary_c_utils')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.repo, args.commit, args.output_dir.resolve(), args.repository)
    print(json.dumps(dict(commit=result['commit'], tracked_files=len(result['files']),
                         cpp_files=sum(item['language_scope'] == 'cpp' for item in result['files']))))
