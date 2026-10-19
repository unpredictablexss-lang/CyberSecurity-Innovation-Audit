bool OnRecvAuthChannelRequest(AppInfo *appInfo)
{
    OnRequsetUpdateAuthChannel(appInfo);
    NotifyOpenAuthChannelSuccess(appInfo);
    return true;
}
