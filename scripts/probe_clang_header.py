"""Analyze c_utils pinned headers with an explicitly supplied dependency blob.

This is a supplemental header probe, not a translation-unit benchmark or a
template-instantiation harness. It never fetches sources or changes Git objects.
"""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.run_static_tool_experiments import PROJECT
from src.baseline.clang_analyzer import run_clang_analyzer
from src.benchmark.historical import _git, _show_file, load_sample


def probe(repo, dependency, output):
    sample = load_sample(PROJECT / 'benchmarks/historical/c_utils_singleton_uaf.json')
    origin = _git(repo, ['remote', 'get-url', 'origin']).stdout.strip().removesuffix('.git')
    if not (origin.endswith('/' + sample.repository) or origin.endswith(':' + sample.repository)):
        raise ValueError('Repository identity does not match c_utils sample')
    data = dependency.read_bytes()
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    for revision in ('vulnerable', 'fixed'):
        commit = getattr(sample, revision + '_commit')
        file = 'base/include/nocopyable.h'
        expected = _git(repo, ['ls-tree', commit, '--', file]).stdout.split()[2]
        if actual != expected:
            raise ValueError('Dependency does not match the pinned Git tree: ' + revision)
        root = output / ('clang_header_probe.' + revision)
        header = root / sample.affected_files[0]
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(_show_file(repo, commit, sample.affected_files[0]), encoding='utf-8')
        (root / file).write_bytes(data)
        result = run_clang_analyzer(root, sample.affected_files, extra_args=[
            '-x', 'c++', '-std=c++17', '-I', str(root / 'base/include')])
        report = dict(sample_id=sample.sample_id, commit=commit, revision=revision,
                      dependency_blob=expected, result=result.to_dict(),
                      limitations=['Header-only analysis; no template instantiation or original build configuration.'])
        (root / 'execution.json').write_text(json.dumps(report, indent=2))
        print(revision, result.failed_files, result.diagnostic_count, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    probe(args.repo, args.dependency, args.output_dir.resolve())
