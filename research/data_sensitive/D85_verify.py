"""Offline D85 receiver-binding controls, compared against the D84 commit."""
import argparse
import hashlib
import json
from pathlib import Path
from D84_verify import ROOT, SensitiveTests, MODEL, ScanContext, ScanRequest, snapshot_digest
from D84_verify import index_sources, GitSource, DEFAULT_SOURCE, SensitiveExposureDetector
from D84_verify import baseline_detector, summary

BEFORE = 'e72855e970405bb8043cf4bb961207848c957a97'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    old = baseline_detector(BEFORE)
    cases = {
        'string_local': 'std::string value=key;',
        'string_brace_init': 'std::string value{key};',
        'compound_lhs': 'std::string value=key; value += "suffix";',
        'compound_rhs': 'std::string value="prefix"; value += key;',
        'safe_overwrite': 'std::string value=key; value="redacted";',
        'safe_literal': 'std::string value="safe";',
        'unrelated_same_name': 'Fake value=key;',
    }
    controls = {}
    for name, declaration in cases.items():
        source = ('struct Fake { Fake(const char *); const char *c_str(){return "safe";} }; '
                  'void Callback(const char *key){' + declaration +
                  'HILOG_INFO(1,"%{public}s",value.c_str());}')
        context = SensitiveTests().context(source)
        controls[name] = {label: summary(detector(MODEL).detect(context, context.units))
                          for label, detector in [('before', old), ('after', SensitiveExposureDetector)]}
    evidence = json.loads((ROOT / 'research/data_sensitive/D84_VALIDATION_20261020.json').read_text())
    sources = []
    for row in evidence['upstream']['files']:
        data = (args.source_root / row['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert hashlib.sha256(data).hexdigest() == row['sha256'] and blob == row['blob']
        sources.append(GitSource(row['path'], 'c', blob, data))
    units, ast, _ = index_sources(tuple(sources))
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest('D85-source-regression', DEFAULT_SOURCE.repository, DEFAULT_SOURCE.commit,
                          snapshot_digest(units), 'current-component:' + DEFAULT_SOURCE.repository)
    context = ScanContext(request, units, {'ast': ast})
    real = {label: summary(detector().detect(context, units))
            for label, detector in [('before', old), ('after', SensitiveExposureDetector)]}
    result = {'baseline': BEFORE, 'detector_version': SensitiveExposureDetector.version,
              'controls': controls, 'upstream': {
                  'repository': DEFAULT_SOURCE.repository, 'commit': DEFAULT_SOURCE.commit,
                  'verified_files': evidence['upstream']['files'],
                  'before_count': real['before']['candidate_count'],
                  'after_count': real['after']['candidate_count'],
                  'identical_findings_and_outcomes': real['before'] == real['after']},
              'limitations': ['Candidates are syntax-bound; compiler type identity and product impact remain unknown.',
                              'Only directly declared std::string local values with zero-argument dot c_str() calls are modeled.',
                              'Parenthesized constructor syntax is ambiguous in this parser and is not treated as a value declaration.',
                              'Aliases, references, pointers, temporary receivers and arbitrary same-name methods are not modeled.',
                              'The four real C files check regressions only; they do not validate C++ receiver-model completeness.',
                              'No independent accuracy labels or formal precision/recall metrics are claimed.']}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'controls': {name: [r['before']['candidate_count'], r['after']['candidate_count']]
                                   for name, r in controls.items()}, 'upstream': result['upstream']}))


if __name__ == '__main__':
    main()
