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
