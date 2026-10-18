struct Buffer {
    unsigned char *bytes;
};

void ReleaseBuffer(Buffer *buffer)
{
    delete[] buffer->bytes;
    buffer->bytes = nullptr;
    delete buffer;
}
