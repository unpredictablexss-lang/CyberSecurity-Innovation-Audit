int32_t NetStatsServiceStub::OnResetFactory(MessageParcel &data, MessageParcel &reply)
{
    if (!NetManagerPermission::IsSystemCaller()) {
        if (!reply.WriteInt32(NETMANAGER_ERR_NOT_SYSTEM_CALL)) {
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return NETMANAGER_ERR_NOT_SYSTEM_CALL;
    }
    return NETMANAGER_SUCCESS;
}
