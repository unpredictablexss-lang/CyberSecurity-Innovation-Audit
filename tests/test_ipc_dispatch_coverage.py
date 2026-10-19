"""The entry/dispatch coverage record is an output of every run.

A candidate count cannot distinguish "no dispatcher was found" from "dispatchers
were found and every transaction was refused". The detector therefore emits one
coverage line on every run, including runs with no findings. These tests pin that
the line is present, that it carries the unresolved-dispatch count, and that it
does not read a dispatcher as a stub when the class has no readable base clause.
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

SIGNATURE = ('int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,'
             'MessageParcel &reply,MessageOption &option) {\n')
DESCRIPTOR = 'if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n'


def run(text):
    index = parse_source(text, language='cpp')
    unit = SourceUnit('sample.cpp', 'cpp', text,
                      hashlib.sha256(text.encode()).hexdigest(), index.parse_status)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:fixture/ipc')
    ctx = ScanContext(request, (unit,), {'ast': {'sample.cpp': index.to_dict()}})
    return IpcInterfaceDetector().detect(ctx, ctx.units)


def coverage(result):
    lines = [line for line in result.limitations
             if line.startswith('Entry/dispatch coverage:')]
    assert len(lines) == 1, result.limitations
    return lines[0]


class DispatchCoverageTests(unittest.TestCase):
    def test_the_record_exists_even_when_nothing_fires(self):
        text = ('#define Stub Fixture_coverage\n#include "common_types.h"\n'
                + SIGNATURE + DESCRIPTOR + 'return 0;\n}\n')
        result = run(text)
        self.assertEqual(result.findings, ())
        line = coverage(result)
        self.assertIn('dispatcher(s)', line)
        self.assertIn('unresolved dispatch', line)

    def test_the_record_names_the_transaction_resolution_and_binding_grades(self):
        line = coverage(run('#define Stub Fixture_coverage\n#include "common_types.h"\n'
                            + SIGNATURE + DESCRIPTOR + 'return 0;\n}\n'))
        self.assertIn('transactions', line)
        self.assertIn('by grade', line)
        self.assertIn('preprocessor condition', line)

    def test_a_dispatcher_without_a_readable_base_clause_is_not_counted_as_a_stub(self):
        # `Stub` here is only a macro name. The function is named like a
        # dispatcher and is counted as one, but the class states no base, so the
        # stub counter must stay 0 rather than assume the role.
        text = ('#define Stub Fixture_coverage\n#include "common_types.h"\n'
                + SIGNATURE + DESCRIPTOR + 'return 0;\n}\n')
        line = coverage(run(text))
        self.assertIn('1 dispatcher(s) (0 in stub classes', line)


if __name__ == '__main__':
    unittest.main()
