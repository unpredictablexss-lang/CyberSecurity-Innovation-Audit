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

int ContactsDataAbility::SavePortraitFileAndBlob(const std::string &srcFilePath, const std::string &filePath,
    std::vector<uint8_t> &blob, int32_t &blobSource)
{
    mode_t filePermissions = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    auto pixelMap = Contacts::PixelMapUtil::GetPixelMapFromFile(srcFilePath);
    if (pixelMap == nullptr) {
        HILOG_ERROR("SavePortraitFileAndBlob GetPixelMapFromFile failed");
        return Contacts::OPERATION_ERROR;
    }
    int srcFd = open(srcFilePath.c_str(), O_RDONLY, filePermissions);
    if (srcFd == Contacts::OPEN_FILE_FAILED) {
        HILOG_ERROR("SavePortraitFileAndBlob open srcFilePath failed");
        return Contacts::OPERATION_ERROR;
    }
    Contacts::PixelMapUtil::GetThumbnailPixelMap(pixelMap, srcFd);
    close(srcFd);
    if (pixelMap == nullptr) {
        HILOG_ERROR("SavePortraitFileAndBlob GetThumbnailPixelMap failed");
        return Contacts::OPERATION_ERROR;
    }
    int fd = open(filePath.c_str(), O_CREAT | O_WRONLY, filePermissions);
    if (fd == Contacts::OPEN_FILE_FAILED) {
        HILOG_ERROR("SavePortraitFileAndBlob open filePath failed");
        return Contacts::OPERATION_ERROR;
    }
    uint32_t errCode = Contacts::PixelMapUtil::SavePixelMapToFile(pixelMap, fd);
    close(fd);
    if (errCode != Contacts::OPERATION_OK) {
        HILOG_ERROR("SavePortraitFileAndBlob pixelMapTofile failed");
        return Contacts::OPERATION_ERROR;
    }
    blobSource = Contacts::PixelMapUtil::GetBlobSourceFromPixelMap(pixelMap);
    
    errCode = Contacts::PixelMapUtil::GetArrayBufferFromPixelMap(pixelMap, blob);
    if (errCode != Contacts::OPERATION_OK) {
        HILOG_ERROR("SavePortraitFileAndBlob get blob failed");
        return Contacts::OPERATION_ERROR;
    }
    return Contacts::OPERATION_OK;
}

void ContactsDataAbility::BuildPortraitValue(DataShare::DataShareValuesBucket &value, const std::string &contactId,
    const std::string &rawContactId, const std::vector<uint8_t> &blob, int32_t blobSource)
{
    value.Clear();
    value.Put("raw_contact_id", rawContactId);
    value.Put("blob_data", blob);
    value.Put("type_id", Contacts::ContentTypeData::PHOTO_INT_VALUE);
    std::string fileName = "photo/" + contactId + "_" + rawContactId;
    value.Put("blob_source", blobSource);
    value.Put("detail_info", fileName);
}

void ContactsDataAbility::GetPortraitValue(const DataShare::DataShareValuesBucket &dataShareValue,
    std::string &portraitFileName, std::string &contactId, std::string &rawContactId, bool &isValid)
{
    portraitFileName = GetStringValueFromDataShareValue(dataShareValue, "PortraitFileName", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have portraitFileName");
        return;
    }
    contactId = GetStringValueFromDataShareValue(dataShareValue, "contactId", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have contactId");
        return;
    }
    rawContactId = GetStringValueFromDataShareValue(dataShareValue, "rawContactId", isValid);
    if (!isValid) {
        HILOG_DEBUG("not have rawContactId");
        return;
    }

}

std::string ContactsDataAbility::GetStringValueFromDataShareValue(
    const DataShare::DataShareValuesBucket &dataShareValue, const std::string &valueName, bool &isValid)
{
    std::string value;
    DataShare::DataShareValueObject valueObject = dataShareValue.Get(valueName, isValid);
    if (!isValid) {
        return value;
    }
    
    if (const auto* stringPtr = std::get_if<std::string>(&valueObject.value)) {
        value = *stringPtr;
    }
    if (value.empty()) {
        isValid = false;
    }
    return value;
}
