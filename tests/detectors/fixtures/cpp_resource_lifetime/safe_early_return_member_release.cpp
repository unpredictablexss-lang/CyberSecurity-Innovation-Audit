struct Buffer {
    unsigned char *bytes;
};

void ReleaseBufferIfFailed(Buffer *buffer, bool failed)
{
    if (failed) {
        delete[] buffer->bytes;
        buffer->bytes = nullptr;
        delete buffer;
        return;
    }
    buffer->bytes[0] = 0;
}
