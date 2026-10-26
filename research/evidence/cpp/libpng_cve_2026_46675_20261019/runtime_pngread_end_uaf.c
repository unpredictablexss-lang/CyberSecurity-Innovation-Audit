#include <png.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    png_bytep bytes;
    size_t size;
    size_t offset;
} memory_reader;

static void read_from_memory(png_structp png_ptr, png_bytep output, png_size_t amount)
{
    memory_reader *reader = (memory_reader *)png_get_io_ptr(png_ptr);
    if (reader == NULL || reader->offset > reader->size || amount > reader->size - reader->offset)
        png_error(png_ptr, "truncated in-memory PNG");
    memcpy(output, reader->bytes + reader->offset, amount);
    reader->offset += amount;
}

int main(int argc, char **argv)
{
    FILE *file;
    long length;
    memory_reader reader;
    png_structp png_ptr;
    png_infop info_ptr;
    png_bytep row = NULL;
    png_size_t rowbytes;
    int read_rows;

    if (argc != 3 || (strcmp(argv[2], "no-rows") != 0 && strcmp(argv[2], "read-rows") != 0))
        return 2;
    read_rows = strcmp(argv[2], "read-rows") == 0;
    file = fopen(argv[1], "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0)
        return 3;
    length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0)
        return 4;
    reader.bytes = (png_bytep)malloc((size_t)length);
    if (reader.bytes == NULL || fread(reader.bytes, 1, (size_t)length, file) != (size_t)length)
        return 5;
    fclose(file);
    reader.size = (size_t)length;
    reader.offset = 0;

    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL)
        return 6;
    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL)
        return 7;
    if (setjmp(png_jmpbuf(png_ptr))) {
        free(row);
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(reader.bytes);
        return 8;
    }

    png_set_read_fn(png_ptr, &reader, read_from_memory);
    png_read_info(png_ptr, info_ptr);
    if (read_rows) {
        rowbytes = png_get_rowbytes(png_ptr, info_ptr);
        row = (png_bytep)malloc(rowbytes ? rowbytes : 1);
        if (row == NULL)
            png_error(png_ptr, "row allocation failed");
        png_read_row(png_ptr, row, NULL);
        free(row);
        row = NULL;
    }
    fprintf(stderr, "calling png_read_end read_rows=%d\n", read_rows);
    png_read_end(png_ptr, info_ptr);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(reader.bytes);
    puts("png_read_end completed");
    return 0;
}
