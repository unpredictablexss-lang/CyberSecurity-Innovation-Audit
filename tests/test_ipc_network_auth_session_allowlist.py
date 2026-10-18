import unittest

from src.ohscanner.detectors.interface.network_session_allowlist import (
    find_missing_auth_session_allowlist,
)


VULNERABLE = r"""
static void OnRecvAuthChannelRequest(int64_t authId, const char *data, int32_t len)
{
    AppInfo appInfo;
    int32_t ret = TransAuthChannelMsgUnpack(data, &appInfo);
    if (ret != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    ret = OnRequsetUpdateAuthChannel(authId, &appInfo);
    if (ret != SOFTBUS_OK) {
        goto EXIT_ERR;
    }
    ret = NotifyOpenAuthChannelSuccess(&appInfo, true);
    return;
EXIT_ERR:
    AuthCloseChannel(authId);
    return;
}
"""

FIXED = r"""
static const char g_sessionWhiteList[2][SESSION_NAME_SIZE_MAX] = {"system.a", "system.b"};
static bool CheckAuthChannelOfPkgInfoIsValid(const AppInfo *appInfo)
{
    if (appInfo == NULL) return false;
    for (uint16_t index = 0; index < 2; ++index) {
        if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0) {
            return true;
        }
    }
    return false;
}
static void OnRecvAuthChannelRequest(int64_t authId, const char *data, int32_t len)
{
    AppInfo appInfo;
    int32_t ret = TransAuthChannelMsgUnpack(data, &appInfo);
    if (ret != SOFTBUS_OK) goto EXIT_ERR;
    if (!CheckAuthChannelOfPkgInfoIsValid(&appInfo)) goto EXIT_ERR;
    ret = OnRequsetUpdateAuthChannel(authId, &appInfo);
    if (ret != SOFTBUS_OK) goto EXIT_ERR;
    ret = NotifyOpenAuthChannelSuccess(&appInfo, true);
    return;
EXIT_ERR:
    AuthCloseChannel(authId);
    return;
}
"""


class NetworkAuthSessionAllowlistTests(unittest.TestCase):
    def test_unvalidated_peer_identity_before_state_update_is_candidate(self):
        findings = find_missing_auth_session_allowlist(VULNERABLE)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][1], "OnRecvAuthChannelRequest")

    def test_source_derived_rejecting_whitelist_guard_suppresses_candidate(self):
        self.assertEqual(find_missing_auth_session_allowlist(FIXED), ())

    def test_logging_only_check_does_not_count_as_rejection(self):
        source = FIXED.replace(
            "if (!CheckAuthChannelOfPkgInfoIsValid(&appInfo)) goto EXIT_ERR;",
            "if (!CheckAuthChannelOfPkgInfoIsValid(&appInfo)) SoftBusLog(1, 1, \"bad\");",
        )
        self.assertEqual(len(find_missing_auth_session_allowlist(source)), 1)

    def test_prefix_only_whitelist_is_not_treated_as_exact_identity_match(self):
        source = FIXED.replace(
            "if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0)",
            "if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], "
            "strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX)) == 0)",
        )
        self.assertEqual(len(find_missing_auth_session_allowlist(source)), 1)

    def test_guard_after_state_update_does_not_suppress_candidate(self):
        source = FIXED.replace(
            "    if (!CheckAuthChannelOfPkgInfoIsValid(&appInfo)) goto EXIT_ERR;\n"
            "    ret = OnRequsetUpdateAuthChannel(authId, &appInfo);",
            "    ret = OnRequsetUpdateAuthChannel(authId, &appInfo);\n"
            "    if (!CheckAuthChannelOfPkgInfoIsValid(&appInfo)) goto EXIT_ERR;",
        )
        self.assertEqual(len(find_missing_auth_session_allowlist(source)), 1)

    def test_unrelated_callback_shape_is_outside_rule_scope(self):
        self.assertEqual(find_missing_auth_session_allowlist(
            "void Callback(const char *data) { consume(data); }"), ())


if __name__ == "__main__":
    unittest.main()
