void WriteFile() { write(fd_, data_, size_); close(fd_); fd_ = -1; cleanup(); }
