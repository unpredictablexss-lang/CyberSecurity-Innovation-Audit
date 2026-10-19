void WriteFile() { int copy = dup(fd_); write(copy, data_, size_); close(copy); close(fd_); }
