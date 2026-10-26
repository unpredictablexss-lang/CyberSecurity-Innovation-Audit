void OpenUserFile() { if (!IsUnderAppBase(userPath_)) return; int fd = open(userPath_.c_str(), O_RDONLY | O_NOFOLLOW); use(fd); }
