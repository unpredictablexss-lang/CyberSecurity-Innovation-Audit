"""Offline D84 before/after controls and manifest-verified upstream sample replay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.detectors.data.test_sensitive_exposure import SensitiveTests, MODEL
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.detectors.data.models import DEFAULT_SOURCE
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector

BASE = '6cbec8428a5c6c1ca86aa27b62ddc4ff2d06159f'
TARGET = 'src/ohscanner/detectors/data/sensitive_exposure.py'


def baseline_detector(revision=BASE):
    source = subprocess.check_output(['git', 'show', revision + ':' + TARGET], cwd=ROOT)
    module = types.ModuleType('src.ohscanner.detectors.data._d84_baseline')
    module.__package__ = 'src.ohscanner.detectors.data'
    sys.modules[module.__name__] = module
    exec(compile(source, revision + ':' + TARGET, 'exec'), module.__dict__)
    return module.SensitiveExposureDetector


def summary(run):
    return {'candidate_count': len(run.findings), 'status': run.status,
            'file_outcomes': list(run.file_outcomes),
            'findings': [{'file': f.file, 'line': f.line, 'rule': f.rule_id,
                          'message': f.message,
                          'obligations': [o.kind for o in f.evidence_obligations]}
                         for f in run.findings]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    old = baseline_detector()
    cases = {
        'compound_statement': 'unsigned value=key; value ^= 1; HILOG_INFO(1,"%{public}u",value);',
        'compound_expression': 'unsigned value=key; auto out=(value ^= 1); HILOG_INFO(1,"%{public}u",out);',
        'ordinary_overwrite': 'unsigned value=key; value=1; HILOG_INFO(1,"%{public}u",value);',
        'safe_unrelated': 'unsigned value=3; value ^= 1; HILOG_INFO(1,"%{public}u",value);',
        'private_conditional': 'unsigned value=key; value ^= 1; HILOG_INFO(1,"%{private}u",value);',
    }
    controls = {}
    for name, body in cases.items():
        context = SensitiveTests().context('void Callback(unsigned key){' + body + '}')
        controls[name] = {label: summary(detector(MODEL).detect(context, context.units))
                          for label, detector in [('before', old), ('after', SensitiveExposureDetector)]}

    manifest = json.loads((ROOT / 'research/data_sensitive/D10_REAL_SOURCE_REPLAY.json').read_text())
    sources, verified = [], []
    for row in manifest['dsoftbus_files']:
        if not row['path'].endswith('.c'):
            continue
        data = (args.source_root / row['path']).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert digest == row['sha256'] and blob == row['git_blob'] and len(data) == row['size'], row['path']
        sources.append(GitSource(row['path'], 'c', blob, data))
        verified.append({'path': row['path'], 'sha256': digest, 'blob': blob, 'size': len(data)})
    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest('D84-source-regression', DEFAULT_SOURCE.repository, DEFAULT_SOURCE.commit,
                          snapshot_digest(units), 'current-component:' + DEFAULT_SOURCE.repository)
    context = ScanContext(request, units, {'ast': ast})
    real = {label: summary(detector().detect(context, units))
            for label, detector in [('before', old), ('after', SensitiveExposureDetector)]}
    result = {'baseline': BASE, 'detector_version': SensitiveExposureDetector.version,
              'controls': controls,
              'upstream': {'repository': DEFAULT_SOURCE.repository, 'commit': DEFAULT_SOURCE.commit,
                           'files': verified, **real},
              'limitations': ['Synthetic controls are not independent labels or precision/recall evidence.',
                              'The selected upstream files are a regression sample, not whole-component coverage.',
                              'Compound assignments retain may-flow; overloaded operators, aliasing and zeroing are not proven.',
                              'All findings remain candidates; product impact and runtime visibility are unknown.']}
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'controls': {k: [v['before']['candidate_count'], v['after']['candidate_count']]
                                   for k, v in controls.items()},
                      'upstream': [real['before']['candidate_count'], real['after']['candidate_count']],
                      'files_verified': len(verified)}))


if __name__ == '__main__':
    main()
