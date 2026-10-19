"""Local integration regression against B's persisted, pinned audit artifacts.

Research-only verification: reads a baseline checkout and its ignored artifacts.
The production execution path is the ordinary allowlisted ohscan-run command.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-dir', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, default=Path('outputs/reports/owner_ipc_integration'))
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    project = Path(__file__).resolve().parents[1]
    implementation_files = sorted((project / 'src/ohscanner').rglob('*.py')) + [project / 'src/cli/main.py']
    implementation_hashes = {
        str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in implementation_files
    }
    (args.out_dir / 'implementation_hashes.json').write_text(json.dumps(implementation_hashes, indent=2) + '\n')
    summaries = []
    names = ('update_updateservice', 'security_access_token', 'distributeddatamgr_kv_store',
             'window_window_manager', 'communication_dsoftbus')
    for name in names:
        baseline = json.loads((args.baseline_dir / 'outputs/reports' / (name + '.json')).read_text())
        manifest_path = args.baseline_dir / 'outputs/reports' / (name + '.manifest.json')
        manifest = json.loads(manifest_path.read_text())
        repo = Path(manifest['source_repo_path'])
        # The baseline already records its exact production paths. No new scope
        # heuristic or implicit HEAD selection is introduced by this comparison.
        paths = sorted(p for shard in baseline['scope']['shards'] for p in shard['paths'])
        if len(paths) != len(set(paths)) or not paths:
            raise ValueError('Baseline must have unique explicit source paths')
        output = args.out_dir / (name + '.json')
        markdown = args.out_dir / (name + '.md')
        command = [sys.executable, '-m', 'src.cli', 'ohscan-run', '--repo-dir', str(repo),
                   '--repository', baseline['repository'], '--commit', baseline['commit'],
                   '--detector', 'ohscanner.interface.ipc', '--json-out', str(output),
                   '--md-out', str(markdown)]
        for path in paths:
            command.extend(('--include', path))
        print('START', name, 'files=', len(paths), flush=True)
        start = time.perf_counter()
        done = subprocess.run(command, text=True, capture_output=True)
        (args.out_dir / (name + '.terminal.txt')).write_text(done.stdout + done.stderr)
        if done.returncode:
            raise RuntimeError(name + ': ' + done.stderr[-2000:])
        actual = json.loads(output.read_text())
        coverage = actual['detector_coverage']['detectors']['ohscanner.interface.ipc']
        diagnostics = actual['detector_runs'][0]['diagnostics']
        # Baseline uses source-line/rule identity; compare the same immutable
        # bytes too. The enclosing report pins repository and full commit.
        def baseline_key(candidate):
            return (candidate['file'], candidate['line'], candidate['rule_id'],
                    candidate['source_sha256'])
        old = {baseline_key(c) for c in baseline['candidates']}
        new = {(d['file'], d['line'], d['rule_id'], coverage['source_sha256'][d['file']])
               for d in diagnostics}
        proofs = coverage['evidence_obligations']
        partial_proofs = [p for p in proofs if p['analysis_status'] == 'partial']
        summary = {
            'component': name, 'repository': actual['repository'], 'commit': actual['commit'],
            'git_tree': actual['git_tree'], 'snapshot_sha256': actual['snapshot_sha256'],
            'indexed_files': actual['scope']['selected_source_files'],
            'source_parsing': actual['source_parsing'],
            'coverage_counts': coverage['coverage_counts'],
            'unclaimed_files': len(actual['files_in_scope_without_a_claiming_detector']),
            'candidates': len(diagnostics), 'baseline_candidates': len(old),
            'candidate_set_equal': old == new,
            'removed': sorted(old - new), 'added': sorted(new - old),
            'candidates_with_obligations': sum(bool(p['obligations']) for p in proofs),
            'partial_candidates_with_obligations': sum(bool(p['obligations']) for p in partial_proofs),
            'validated_vulnerability': actual['validated_vulnerability'],
            'elapsed_seconds': round(time.perf_counter() - start, 3),
            'command': command,
            'baseline_manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            'artifacts': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (output, markdown)},
        }
        summaries.append(summary)
        (args.out_dir / 'verification.json').write_text(json.dumps(summaries, ensure_ascii=False, indent=2) + '\n')
        print('RESULT', name, 'candidates=', len(diagnostics), 'same=', old == new,
              'partial_with_obligations=', summary['partial_candidates_with_obligations'], flush=True)
        assert summary['indexed_files'] == len(paths), 'Source scope drift'
        assert old == new, 'Candidate set changed; investigate, do not adjust expectations'
        assert summary['candidates_with_obligations'] == len(diagnostics), 'Candidate lost obligations'
        assert sum(coverage['coverage_counts'].values()) == coverage['applicable_files'], 'Coverage does not close'
    assert implementation_hashes == {
        str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in implementation_files
    }, 'Implementation changed during experiment; rerun on stable code'
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
