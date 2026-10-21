int ContactsDataAbility::HandleContactPortrait(DataShare::DataShareValuesBucket &value)
{
    std::string portraitFileName = "";
    std::string contactId =  "";
    std::string rawContactId = "";
    bool isValid = false;
    GetPortraitValue(value, portraitFileName, contactId, rawContactId, isValid);
    if (!isValid || portraitFileName.empty() || contactId.empty() || rawContactId.empty()) {
        return Contacts::OPERATION_OK;
    }
    std::string groupPath;
    Contacts::FileUtils fileUtils;
    if (!fileUtils.GetGroupPath(groupPath) || groupPath.empty()) {
        HILOG_ERROR("HandleContactPortrait GetGroupPath failed");
        return Contacts::OPERATION_ERROR;
    }
    std::string srcFilePath = groupPath + portraitFileName;
    std::string filePath = groupPath + contactId + "_" + rawContactId;
    std::vector<uint8_t> blob;
    int32_t blobSource = -1;
    if (SavePortraitFileAndBlob(srcFilePath, filePath, blob, blobSource) != Contacts::OPERATION_OK) {
        // 保存失败时删除客户端存储的srcFilePath 和 服务端生成的filePath
        fileUtils.DeleteFile(srcFilePath);
        fileUtils.DeleteFile(filePath);
        return Contacts::OPERATION_ERROR;
    };
    // 保存成功仅删除 客户端保存的srcFilePath
    fileUtils.DeleteFile(srcFilePath);
    BuildPortraitValue(value, contactId, rawContactId, blob, blobSource);
    return Contacts::OPERATION_OK;
}
