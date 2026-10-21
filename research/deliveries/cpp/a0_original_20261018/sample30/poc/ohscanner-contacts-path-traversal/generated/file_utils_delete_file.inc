bool FileUtils::DeleteFile(const std::string &filePath)
{
    if (unlink(filePath.c_str()) != 0) {
        HILOG_ERROR("FileUtils DeleteFile failed");
        return false;
    }
    return true;
}
