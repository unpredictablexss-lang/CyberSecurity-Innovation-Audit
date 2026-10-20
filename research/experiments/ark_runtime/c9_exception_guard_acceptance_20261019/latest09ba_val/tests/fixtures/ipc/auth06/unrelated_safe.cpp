static void OnRecvAuthChannelReply(int64_t authId, const char *data, int32_t len)
{
    AuthChannelInfo info;
    if (GetChannelInfoByAuthId(authId, &info) != SOFTBUS_OK) {
        return;
    }
    if (TransAuthChannelMsgUnpack(data, &info.appInfo) != SOFTBUS_OK) {
        AuthCloseChannel(authId);
        return;
    }
    NotifyOpenAuthChannelSuccess(&info.appInfo, false);
}
