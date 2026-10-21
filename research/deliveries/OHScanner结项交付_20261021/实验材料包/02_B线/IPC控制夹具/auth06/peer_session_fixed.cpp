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
