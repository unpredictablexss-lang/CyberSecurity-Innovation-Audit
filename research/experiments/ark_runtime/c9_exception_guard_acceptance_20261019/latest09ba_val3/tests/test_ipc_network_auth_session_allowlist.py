import unittest

from src.ohscanner.detectors.interface.network_session_allowlist import (
    find_auth_session_allowlist_candidates,
    find_missing_auth_session_allowlist,
    has_exact_registered_session_resolution,
)
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from tests.test_ipc_detector import context


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


EXACT_REGISTERED_SESSION_CONTEXT = r"""
int32_t TransGetUidAndPid(const char *sessionName, int32_t *uid, int32_t *pid)
{
    for (SessionServer *pos = list; pos != NULL; pos = pos->next) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            *uid = pos->uid;
            *pid = pos->pid;
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}
int32_t TransGetPkgNameBySessionName(const char *sessionName, char *pkgName, uint16_t len)
{
    for (SessionServer *pos = list; pos != NULL; pos = pos->next) {
        if (strcmp(pos->sessionName, sessionName) == 0) {
            copy(pkgName, len, pos->pkgName);
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_ERR;
}
int32_t GetAppInfo(const char *sessionName, AppInfo *info)
{
    if (TransGetUidAndPid(sessionName, &info->uid, &info->pid) != SOFTBUS_OK) return SOFTBUS_ERR;
    if (TransGetPkgNameBySessionName(sessionName, info->pkgName, sizeof(info->pkgName)) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
AuthChannelInfo *CreateAuthChannelInfo(const char *sessionName)
{
    AuthChannelInfo *info = allocate();
    if (GetAppInfo(sessionName, info) != SOFTBUS_OK) goto EXIT_ERR;
    return info;
EXIT_ERR:
    SoftBusFree(info);
    return NULL;
}
int32_t OnRequsetUpdateAuthChannel(int64_t authId, AppInfo *appInfo)
{
    AuthChannelInfo *item = CreateAuthChannelInfo(appInfo->myData.sessionName);
    if (item == NULL) return SOFTBUS_ERR;
    AddAuthChannelInfo(item);
    return SOFTBUS_OK;
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
        findings = find_auth_session_allowlist_candidates(source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][2], "prefix")

    def test_arbitrary_strncmp_length_is_not_misreported_as_allowlist_length_prefix(self):
        source = FIXED.replace(
            "if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0)",
            "if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], 1) == 0)",
        )
        findings = find_auth_session_allowlist_candidates(source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][2], "missing")

    def test_exact_rejecting_whitelist_is_not_a_candidate(self):
        self.assertEqual(find_auth_session_allowlist_candidates(FIXED), ())

    def test_prefix_candidate_keeps_impact_unknown_and_names_the_limitation(self):
        source = FIXED.replace(
            "if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0)",
            "if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], "
            "strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX)) == 0)",
        )
        ctx = context(source)
        run = IpcInterfaceDetector().detect(ctx, ctx.units)
        finding = next(item for item in run.findings
                       if item.rule_id == "ipc.network.auth-session-whitelist")
        self.assertEqual(finding.consequence_impact, "unknown")
        self.assertIn("allowlist-length prefix", finding.message)

    def test_prefix_candidate_is_retained_with_exact_registry_chain_without_allowlist_binding(self):
        prefix = FIXED.replace(
            "if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0)",
            "if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], "
            "strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX)) == 0)",
        )
        self.assertTrue(has_exact_registered_session_resolution(
            (prefix, EXACT_REGISTERED_SESSION_CONTEXT)))
        ctx = context(prefix + EXACT_REGISTERED_SESSION_CONTEXT)
        finding = next(item for item in IpcInterfaceDetector().detect(ctx, ctx.units).findings
                       if item.rule_id == "ipc.network.auth-session-whitelist")
        self.assertEqual(finding.consequence_impact, "unknown")
        self.assertIn("does not prove it is an exact allowlist member", finding.message)

    def test_prefix_candidate_remains_when_registered_session_context_is_missing(self):
        prefix = FIXED.replace(
            "if (strcmp(appInfo->myData.sessionName, g_sessionWhiteList[index]) == 0)",
            "if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], "
            "strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX)) == 0)",
        )
        self.assertFalse(has_exact_registered_session_resolution((prefix,)))
        self.assertEqual(find_auth_session_allowlist_candidates(prefix)[0][2], "prefix")

    def test_exact_name_lookups_do_not_suppress_without_fail_closed_update_chain(self):
        weakened = EXACT_REGISTERED_SESSION_CONTEXT.replace(
            "if (item == NULL) return SOFTBUS_ERR;", "if (item == NULL) publish(item);")
        self.assertFalse(has_exact_registered_session_resolution((weakened,)))

    def test_ignored_registry_lookup_failure_does_not_suppress_prefix_candidate(self):
        weakened = EXACT_REGISTERED_SESSION_CONTEXT.replace(
            "if (TransGetUidAndPid(sessionName, &info->uid, &info->pid) != SOFTBUS_OK) return SOFTBUS_ERR;",
            "TransGetUidAndPid(sessionName, &info->uid, &info->pid);",
        )
        self.assertFalse(has_exact_registered_session_resolution((weakened,)))

    def test_open_default_for_registry_lookup_does_not_suppress_prefix_candidate(self):
        needle = "    return SOFTBUS_ERR;" + chr(10) + "}" + chr(10)
        needle += "int32_t TransGetPkgNameBySessionName"
        replacement = "    return SOFTBUS_OK;" + chr(10) + "}" + chr(10)
        replacement += "int32_t TransGetPkgNameBySessionName"
        weakened = EXACT_REGISTERED_SESSION_CONTEXT.replace(needle, replacement, 1)
        self.assertFalse(has_exact_registered_session_resolution((weakened,)))

    def test_ambiguous_registered_session_resolver_keeps_prefix_candidate(self):
        duplicate = "\nint32_t TransGetUidAndPid(const char *sessionName, int *uid, int *pid) "
        duplicate += "{ (void)sessionName; return SOFTBUS_OK; }\n"
        self.assertFalse(has_exact_registered_session_resolution(
            (EXACT_REGISTERED_SESSION_CONTEXT + duplicate,)))

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
