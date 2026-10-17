"""Prepare a post-freeze, unlabelled review pack; do not tune on predictions."""
import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel
from tests.detectors.ark_runtime.support import unit, wrap

FROZEN = '4ea5f4020884aed5860a88d50f5a926610e7b98a'


def prepare(output):
    output = Path(output)
    if (output / 'C3_HOLDOUT_MANIFEST.json').exists():
        raise ValueError('holdout_already_frozen_use_new_directory')
    output.mkdir(parents=True, exist_ok=True)
    cases = output / 'holdout'
    cases.mkdir(exist_ok=True)
    modules = {}
    for path in sorted((ROOT / 'src/ohscanner/detectors/ark_runtime').glob('*.py')):
        rel = path.relative_to(ROOT).as_posix()
        frozen_bytes = subprocess.check_output(['git', '-C', str(ROOT), 'show', FROZEN + ':' + rel])
        if path.read_bytes() != frozen_bytes:
            raise ValueError('algorithm_no_longer_matches_freeze:' + rel)
        modules[rel] = sha256(frozen_bytes).hexdigest()
    setup = ('GateRef seed = GetObjectType(LoadHClass(input));\n'
             'GateRef preserved = seed; NewObjectStubBuilder alloc(this);\n'
             'GateRef dst = alloc.NewTypedArray(glue, input, seed, count);\n')
    write = 'StoreTypedArrayElement(glue, dst, count, input, preserved);\n'
    fresh = 'GateRef current = GetObjectType(LoadHClass(dst));\n'
    safe_write = 'StoreTypedArrayElement(glue, dst, count, input, current);\n'
    samples = [
        ('risk_sampling_intent', setup + 'GateRef third = preserved;\n' + write.replace('preserved);', 'third);')),
        ('risk_sampling_intent', setup + 'GateRef old = preserved; preserved = GetObjectType(LoadHClass(dst));\n' + write.replace('preserved);', 'old);')),
        ('risk_sampling_intent', setup + 'GateRef targetAlias = dst; GateRef tokenAlias = preserved;\n' + write.replace('dst,', 'targetAlias,').replace('preserved);', 'tokenAlias);')),
        ('risk_sampling_intent', setup + 'Label commitWrite(GetEnvironment()); BRANCH(count, &commitWrite, exit); Bind(&commitWrite);\n' + write),
        ('same_origin_sampling_intent', setup + fresh + 'GateRef relay = current;\n' + safe_write.replace('current);', 'relay);')),
        ('same_origin_sampling_intent', setup + fresh + 'GateRef finalDst = dst;\n' + safe_write.replace('dst,', 'finalDst,')),
        ('same_origin_sampling_intent', setup + fresh + 'Label equal(GetEnvironment()); BRANCH(Int32Equal(preserved, current), &equal, exit); Bind(&equal);\n' + write),
        ('same_origin_sampling_intent', setup + fresh + 'alloc.SetParameters(glue, count);\n' + safe_write),
        ('unrelated_sampling_intent', setup + write, 'ForeignArrayBuilder'),
        ('unrelated_sampling_intent', setup + write, 'BuiltinsTypedArrayStubBuilder', 'unrelated::compiler'),
        ('unrelated_sampling_intent', 'GateRef untouched = input;\n'),
        ('unrelated_sampling_intent', setup + 'foreign.StoreTypedArrayElement(glue, dst, count, input, preserved);\n'),
        ('unknown_sampling_intent', setup + fresh + 'GateRef x = UnknownMutator(dst);\n' + safe_write),
        ('unknown_sampling_intent', setup + fresh + 'UnknownSideEffect();\n' + safe_write),
        ('unknown_sampling_intent', setup + fresh + 'GateRef &escaped = current; escaped = preserved;\n' + safe_write),
        ('unknown_sampling_intent', setup + 'Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n'
         'dst = alloc.NewTypedArray(glue, input, seed, count);\n' + write + 'LoopEnd(&again);'),
    ]
    entries, predictions = [], []
    for index, sample in enumerate(samples, 1):
        cid = 'H' + str(index).zfill(2)
        source = wrap(sample[1], *sample[2:])
        path = cases / (cid + '.cpp')
        path.write_text(source, encoding='utf-8', newline='\n')
        fixture = unit(source, 'holdout/' + path.name)
        entries.append(dict(id=cid, path='holdout/' + path.name, source_sha256=fixture.sha256,
            sampling_intent=sample[0], label=None, label_status='awaiting_independent_reviewer'))
        result = analyze_unit(fixture)
        predictions.append(dict(id=cid, source_sha256=fixture.sha256, result=result.to_dict()))
    manifest = dict(algorithm_commit=FROZEN, implementation_sha256=modules,
        model=asdict(RuntimeTypeModel()), model_sha256=RuntimeTypeModel().digest,
        cases=entries, created_after_algorithm_freeze=True, used_for_tuning=False,
        author='same development assistant; not an independent label authority',
        independence='unseen instances after code freeze only; source and mechanism independence limited',
        independent_labels_available=False, predictions_executed=True, scored=False, precision=None, recall=None)
    labels = dict(algorithm_commit=FROZEN, reviewer=None, reviewed_at=None,
        allowed_labels=['risk_mechanism', 'reliable_same_type', 'unrelated', 'unknown'],
        cases=[dict(id=e['id'], source_sha256=e['source_sha256'], label=None,
                    rationale=None, evidence=None, reviewer=None) for e in entries])
    for name, payload in [('C3_HOLDOUT_MANIFEST.json', manifest),
                           ('C3_HOLDOUT_PREDICTIONS.json', predictions),
                           ('C3_HOLDOUT_LABELS.template.json', labels)]:
        (output / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(dict(cases=len(entries), predictions_executed=True, scored=False, independent_labels=False)))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True)
    prepare(p.parse_args().output)
