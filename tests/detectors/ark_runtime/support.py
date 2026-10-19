import hashlib
import json
from pathlib import Path
from src.ohscanner.contracts import SourceUnit, ScanRequest, ScanContext
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

FIXTURES = Path(__file__).parent / 'fixtures'


def unit(text, path='src/typedarray.cpp'):
    index = parse_source(text, 'cpp')
    return SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status, tuple(json.dumps(x, sort_keys=True) for x in index.parse_issues))


def case(number):
    return unit((FIXTURES / (number + '.cpp')).read_text(encoding='utf-8'))


def context(units):
    units = tuple(sorted(units, key=lambda u: u.path))
    return ScanContext(ScanRequest('ark-cases', 'fixture/ark-runtime', 'synthetic', snapshot_digest(units),
                                  'current-component:fixture/ark-runtime'), units,
                       {'ast': {u.path: parse_source(u.text, 'cpp').to_dict() for u in units}})


def wrap(body, owner='BuiltinsTypedArrayStubBuilder', namespace='panda::ecmascript::kungfu'):
    return ('namespace ' + namespace + ' {\nvoid ' + owner + '::Filter('
            'GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {\n'
            + body + '\n}\n}\n')


PREFIX = ('GateRef inputTag = GetObjectType(LoadHClass(input));\n'
          'NewObjectStubBuilder builder(this);\n'
          'GateRef output = builder.NewTypedArray(glue, input, inputTag, count);\n')
