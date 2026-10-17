"""`IsSystemAppCalling` is credited by its body, not by the string.

The gap review asks that a same-named wrapper be resolved to its actual function
body rather than added to an "always trusted" list. This is the pair for the
system-application predicate specifically: where the file writes its own
`IsSystemAppCalling`, that body is what runs, and when the body derives no fact
the caller-class candidate stays. Where the file does not define the name, the
reviewed meaning is credited -- that half keeps the first from being satisfied by
refusing everything.
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

SIGNATURE = ('int SystemAppStub::OnRemoteRequest(uint32_t code,MessageParcel &data,'
             'MessageParcel &reply,MessageOption &option) {\n'
             'if (data.ReadInterfaceToken() != IFixtureSystemApp::GetDescriptor()) return -1;\n'
             'if (!IsSystemAppCalling()) return -1;\n'
             'GetReqPermissions(1, nullptr);\n'
             'return 0;\n}\n')
DECLARATIONS = ('#include "common_types.h"\n'
                'class IFixtureSystemApp {\npublic:\n'
                '    static const char *GetDescriptor();\n};\n'
                'class SystemAppStub : public IRemoteStub<IFixtureSystemApp> {\npublic:\n'
                '    int OnRemoteRequest(uint32_t code,MessageParcel &data,'
                'MessageParcel &reply,MessageOption &option);\n'
                '    bool IsSystemAppCalling() const;\n};\n')
LOCAL_BODY = 'bool SystemAppStub::IsSystemAppCalling() const { return true; }\n'


def run(text):
    index = parse_source(text, language='cpp')
    units = (SourceUnit('sample.cpp', 'cpp', text,
                        hashlib.sha256(text.encode()).hexdigest(),
                        index.parse_status),)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v2',
                          snapshot_digest(units), 'current-component:fixture/ipc')
    ctx = ScanContext(request, units, {'ast': {u.path: {}} for u in units})
    result = IpcInterfaceDetector().detect(ctx, ctx.units)
    assert result.status == 'completed', result.status
    return result


class SystemAppPredicateTests(unittest.TestCase):
    def test_a_local_body_of_the_reviewed_name_is_read_instead_of_credited(self):
        result = run(DECLARATIONS + LOCAL_BODY + SIGNATURE)
        rules = {f.rule_id for f in result.findings}
        self.assertIn('ipc.auth.caller-class', rules,
                      [f.message for f in result.findings])
        notes = [s for s in result.limitations if 'IsSystemAppCalling' in s]
        self.assertEqual(len(notes), 1, result.limitations)
        self.assertIn('defined in the scanned sources', notes[0])
        self.assertIn('not credited', notes[0])

    def test_without_a_local_definition_the_reviewed_meaning_is_credited(self):
        # The control for the test above: the same handler, no local body. If
        # this also produced the caller-class candidate, the refusal above would
        # prove nothing about reading bodies -- it would only show that the rule
        # never fires. A permission-authorization candidate may still be present
        # in both: a caller class is not a permission, and this test is about the
        # caller-class rule only.
        result = run(DECLARATIONS + SIGNATURE)
        self.assertNotIn('ipc.auth.caller-class',
                         {f.rule_id for f in result.findings},
                         [f.message for f in result.findings])
        self.assertFalse([s for s in result.limitations if 'IsSystemAppCalling' in s])


if __name__ == '__main__':
    unittest.main()
