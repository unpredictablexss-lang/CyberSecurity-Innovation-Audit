static bool CheckAuthChannelOfPkgInfoIsValid(const AppInfo *appInfo)
{
    return strcmp(appInfo->myData.sessionName, g_sessionWhiteList[0]) == 0;
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
