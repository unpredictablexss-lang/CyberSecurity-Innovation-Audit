int32_t ReadStatus(MessageParcel &data, MessageParcel &reply)
{
    if (!data.ReadInt32(value)) {
        if (!reply.WriteInt32(NETMANAGER_ERR_READ_DATA_FAIL)) {
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return NETMANAGER_SUCCESS;
    }
    return NETMANAGER_SUCCESS;
}
