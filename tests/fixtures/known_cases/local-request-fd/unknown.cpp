void WriteFile() { write(fd_, data_, size_); close(fd_); cleanup(fd_); close(fd_); }
