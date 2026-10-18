void positive_new_index()
{
    char *dst = new char[4];
    dst[4] = 1;
    delete[] dst;
}
