static bool CheckAuthChannelOfPkgInfoIsValid(const AppInfo *appInfo)
{
    if (appInfo == NULL) return false;
    for (int index = 0; index < SESSION_WHITE_LIST_MAX; ++index) {
        size_t len = strnlen(g_sessionWhiteList[index], SESSION_NAME_SIZE_MAX);
        if (strncmp(appInfo->myData.sessionName, g_sessionWhiteList[index], len) == 0) return true;
    }
    return false;
}
bool OnRecvAuthChannelRequest(AppInfo *appInfo)
{
    if (!CheckAuthChannelOfPkgInfoIsValid(appInfo)) goto EXIT_ERR;
    OnRequsetUpdateAuthChannel(appInfo);
    NotifyOpenAuthChannelSuccess(appInfo);
    return true;
EXIT_ERR:
    return false;
}
