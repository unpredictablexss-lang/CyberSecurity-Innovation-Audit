void safe_new_index()
{
    char *dst = new char[8];
    dst[7] = 1;
    delete[] dst;
}
