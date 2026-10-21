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
