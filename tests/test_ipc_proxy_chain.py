"""Cross-service calls: what identity crosses the boundary, and what does not.

A handler that obtains `iface_cast<IFoo>(remote)` leaves this process on every
call through that handle. The downstream service does not see the identity the
handler was entered with: it sees this service, unless the path explicitly set
the calling identity to the original caller's token. These tests pin the record
the analysis keeps of that change point, and the boundaries of the record:

* a proxy handle built by `iface_cast<>` makes a later call a boundary, and the
  identity recorded is the service's;
* forwarding the calling token before the call records the caller instead;
* `ResetCallingIdentity()` after forwarding takes it back to the service;
* restoring this service's own saved identity is not forwarding the caller;
* a handle that was not built that way is not claimed as a boundary.

None of these boundaries produce a candidate: the record says what crossed, and
nothing more.
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
PROXY = 'sptr<IFoo> proxy = iface_cast<IFoo>(remote);\n'


def entry(body):
    return HEADER + SIGNATURE + DESCRIPTOR + body + 'return 0;\n}\n'


def run(text):
    index = parse_source(text, language='cpp')
    units = (SourceUnit('entry.cpp', 'cpp', text,
                        hashlib.sha256(text.encode()).hexdigest(),
                        index.parse_status),)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v2',
                          snapshot_digest(units), 'current-component:fixture/ipc')
    ctx = ScanContext(request, units, {'ast': {u.path: {} for u in units}})
    result = IpcInterfaceDetector().detect(ctx, ctx.units)
    assert result.status == 'completed', result.status
    return result


def coverage(result):
    """The one boundary-coverage line, split into its three numbers."""
    lines = [line for line in result.limitations
             if line.startswith('Cross-service boundary coverage:')]
    assert len(lines) == 1, result.limitations
    line = lines[0]
    calls = int(line.split('coverage: ')[1].split(' call(s)')[0])
    carried = int(line.split('sources, ')[1].split(' carrying')[0])
    return calls, carried, len(result.findings)


class ProxyBoundaryTests(unittest.TestCase):
    def test_a_call_through_an_iface_cast_handle_is_a_boundary(self):
        calls, carried, findings = coverage(run(entry(PROXY + 'proxy->DoThing();\n')))
        self.assertEqual((calls, carried), (1, 0))
        # The boundary record is coverage, not a finding.
        self.assertEqual(findings, 0)

    def test_forwarding_the_calling_token_records_the_caller(self):
        calls, carried, _ = coverage(run(entry(
            PROXY
            + 'SetCallingIdentity(IPCSkeleton::GetCallingFullTokenID());\n'
            + 'proxy->DoThing();\n')))
        self.assertEqual((calls, carried), (1, 1))

    def test_a_reset_after_forwarding_returns_to_the_service(self):
        # The call runs as the service again: the forwarded identity was taken
        # back, so the boundary does not claim the caller crossed it.
        calls, carried, _ = coverage(run(entry(
            PROXY
            + 'SetCallingIdentity(IPCSkeleton::GetCallingFullTokenID());\n'
            + 'ResetCallingIdentity();\n'
            + 'proxy->DoThing();\n')))
        self.assertEqual((calls, carried), (1, 0))

    def test_restoring_the_services_own_identity_is_not_the_caller(self):
        # `ResetCallingIdentity()` returns this service's own identity; setting
        # it back restores the service, and the token is not the caller's.
        calls, carried, _ = coverage(run(entry(
            PROXY
            + 'auto saved = IPCSkeleton::ResetCallingIdentity();\n'
            + 'SetCallingIdentity(saved);\n'
            + 'proxy->DoThing();\n')))
        self.assertEqual((calls, carried), (1, 0))

    def test_a_client_manager_call_is_not_a_service_boundary(self):
        # A handler may call another service's client Kit. That line is a call
        # inside this process to a local manager object, not a written-out
        # boundary, so it is not recorded as one.
        calls, carried, findings = coverage(run(entry(
            'CameraManager::GetInstance().OpenCamera();\n')))
        self.assertEqual((calls, carried), (0, 0))
        self.assertEqual(findings, 0)

    def test_a_handle_not_built_by_iface_cast_is_not_claimed(self):
        # `helper` arrives from somewhere the walk does not model. Calling it is
        # not evidence that a process boundary was crossed here, so the coverage
        # line reports no boundary rather than assuming one.
        calls, carried, findings = coverage(run(entry('helper->DoThing();\n')))
        self.assertEqual((calls, carried), (0, 0))
        self.assertEqual(findings, 0)

    def test_a_service_side_call_after_a_guard_is_still_only_coverage(self):
        # The entry's authorization is for this handler; the downstream call is
        # recorded as running as the service. It does not turn the guard into
        # downstream authorization, and it does not create a candidate.
        text = entry('if (!CheckPermission()) return -1;\n'
                     + PROXY + 'proxy->DoThing();\n')
        calls, carried, findings = coverage(run(text))
        self.assertEqual((calls, carried), (1, 0))
        self.assertEqual(findings, 0)


if __name__ == '__main__':
    unittest.main()
