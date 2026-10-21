bool FileUtils::GetGroupPath(std::string &groupPath)
{
    std::string appDir;
    if (!GetGroupDir(appDir)) {
        HILOG_ERROR("FileUtils GetGroupDir failed");
        return false;
    }
    if (appDir.size() == 0 || appDir.find(APP_PATH_PREFIX) != 0) {
        return false;
    }
    size_t lastSlashPos = appDir.rfind('/');
    if (lastSlashPos == std::string::npos || lastSlashPos >= appDir.size() - 1) {
        return false;
    }
    std::string lastPart = appDir.substr(lastSlashPos + 1);
    groupPath = GROUP_PATH_PREFIX + lastPart + PHOTO_STR;
    if (IsFolderExist(groupPath) == OPERATION_ERROR) {
        Mkdir(groupPath, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH);
    }
    return true;
}
