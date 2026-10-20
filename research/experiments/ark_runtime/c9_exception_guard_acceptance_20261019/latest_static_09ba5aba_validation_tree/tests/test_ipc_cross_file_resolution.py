"""Qualified-name resolution across files, and the refusals that bound it.

A stub's guard helper often lives in another translation unit, written as
`Class::Method()`. Resolving only inside the caller's file left that body unread,
which turns a guarded entry into a candidate. The widening is deliberately narrow,
and these tests pin each edge of the bound:

* an explicitly qualified callee may resolve to another file's definition;
* an unqualified callee may not (no last-name-only search);
* two definitions of the same qualified name stay unresolved;
* a definition under a different owner is not picked up by name.
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

HEADER = '#define Stub Fixture_flow\n#include "common_types.h"\n'
SIGNATURE = ('int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,'
             'MessageParcel &reply,MessageOption &option) {\n')
DESCRIPTOR = 'if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n'
GUARD_BODY = ('bool NS::Guard::Allowed() {\n'
              'return AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),'
              ' "ohos.permission.TEST") == PERMISSION_GRANTED;\n}\n')


def entry(call):
    return HEADER + SIGNATURE + DESCRIPTOR + call + 'StartAbility();\nreturn 0;\n}\n'


def run(files):
    units = []
    for path, text in files:
        index = parse_source(text, language='cpp')
        units.append(SourceUnit(path, 'cpp', text,
                                hashlib.sha256(text.encode()).hexdigest(),
                                index.parse_status))
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v2',
                          snapshot_digest(tuple(units)), 'current-component:fixture/ipc')
    ctx = ScanContext(request, tuple(units), {'ast': {u.path: {} for u in units}})
    result = IpcInterfaceDetector().detect(ctx, ctx.units)
    assert result.status == 'completed', result.status
    return result


class QualifiedCrossFileTests(unittest.TestCase):
    def test_a_qualified_helper_defined_elsewhere_is_read(self):
        result = run([('entry.cpp', entry('if (!NS::Guard::Allowed()) return -1;\n')),
                      ('guard.cpp', GUARD_BODY)])
        rules = {f.rule_id for f in result.findings}
        self.assertNotIn('ipc.auth.missing', rules, [f.message for f in result.findings])

    def test_an_unqualified_name_is_not_resolved_by_last_name(self):
        # `Allowed()` alone says nothing about `NS::Guard::Allowed`, so the body
        # is not borrowed and the entry keeps its candidate.
        result = run([('entry.cpp', entry('if (!Allowed()) return -1;\n')),
                      ('guard.cpp', GUARD_BODY)])
        rules = {f.rule_id for f in result.findings}
        self.assertIn('ipc.auth.missing', rules)

    def test_two_definitions_of_the_qualified_name_stay_unresolved(self):
        # Either body could be the one that runs; picking one would be a guess
        # about which translation unit the linker uses.
        result = run([('entry.cpp', entry('if (!NS::Guard::Allowed()) return -1;\n')),
                      ('guard_a.cpp', GUARD_BODY),
                      ('guard_b.cpp', GUARD_BODY)])
        rules = {f.rule_id for f in result.findings}
        self.assertIn('ipc.auth.missing', rules)

    def test_a_different_owner_is_not_picked_up(self):
        # Same method name, different class: the qualifier has to agree.
        other = GUARD_BODY.replace('NS::Guard::Allowed', 'Other::Allowed')
        result = run([('entry.cpp', entry('if (!NS::Guard::Allowed()) return -1;\n')),
                      ('other.cpp', other)])
        rules = {f.rule_id for f in result.findings}
        self.assertIn('ipc.auth.missing', rules)


if __name__ == '__main__':
    unittest.main()
