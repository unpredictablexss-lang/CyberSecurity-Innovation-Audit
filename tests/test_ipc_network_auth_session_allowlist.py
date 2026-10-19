"""Focused regressions for AUTH-06; fixtures are not historical recall claims."""
from pathlib import Path
import hashlib
import unittest
from unittest.mock import patch

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

from src.ohscanner.detectors.interface.network_session_allowlist import (
    find_auth_session_allowlist_candidates,
)

BASE = Path(__file__).parent / "fixtures" / "ipc" / "auth06"


class AuthSessionAllowlistTests(unittest.TestCase):
    def observations(self, name):
        return find_auth_session_allowlist_candidates(
            (BASE / name).read_text(encoding="utf-8-sig"))

    def test_missing_validator_is_candidate(self):
        found = self.observations("missing_guard.c")
        self.assertEqual([item.kind for item in found], ["missing"])

    def test_prefix_comparison_stays_candidate_after_disclosure_fix(self):
        found = self.observations("prefix_guard_candidate.c")
        self.assertEqual([item.kind for item in found], ["prefix"])
        self.assertIn("exact session-name membership is not established", found[0].message)

    def test_exact_comparison_and_negative_reject_branch_is_sufficient_for_static_suppression(self):
        self.assertEqual(self.observations("exact_guard_fixed.c"), ())

    def test_positive_validator_branch_that_exits_is_not_credited(self):
        found = self.observations("reversed_guard_positive.c")
        self.assertEqual([item.kind for item in found], ["unguarded"])

    def test_late_guard_does_not_suppress_effect_already_reached(self):
        source = """
static bool CheckAuthChannelOfPkgInfoIsValid(const AppInfo *appInfo) {
    return strcmp(appInfo->myData.sessionName, g_sessionWhiteList[0]) == 0;
}
bool OnRecvAuthChannelRequest(AppInfo *appInfo) {
    OnRequsetUpdateAuthChannel(appInfo);
    if (!CheckAuthChannelOfPkgInfoIsValid(appInfo)) goto EXIT_ERR;
    NotifyOpenAuthChannelSuccess(appInfo);
    return true;
EXIT_ERR:
    return false;
}
"""
        found = find_auth_session_allowlist_candidates(source)
        self.assertEqual([item.kind for item in found], ["unguarded"])
    def test_unrelated_function_is_not_a_candidate(self):
        source = "void unrelated(void) { NotifyOpenAuthChannelSuccess(); }"
        self.assertEqual(find_auth_session_allowlist_candidates(source), ())

    def test_detector_does_not_send_cpp_units_to_c_callback_model(self):
        source = "template <typename T> class TlvObject { public: bool ReadBasicValue(T &v) { return true; } };"
        parsed = parse_source(source, language="cpp")
        unit = SourceUnit("framework/tlv/tlv_object.h", "cpp", source, hashlib.sha256(source.encode()).hexdigest(), parsed.parse_status)
        request = ScanRequest("auth06-language-gate", "test/repo", "a" * 40, snapshot_digest((unit,)), "current-component:test/repo")
        context = ScanContext(request, (unit,), {"ast": {unit.path: parsed.to_dict()}})
        with patch("src.ohscanner.detectors.interface.detector.find_auth_session_allowlist_candidates", side_effect=AssertionError("C-only AUTH-06 parser called for C++")) as auth06:
            IpcInterfaceDetector().detect(context, (unit,))
            auth06.assert_not_called()



if __name__ == "__main__":
    unittest.main()
