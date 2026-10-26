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
    if (reader == NULL || amount > reader->size - reader->offset)
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
    png_bytep row;
    png_size_t rowbytes;
    if (argc != 2 && argc != 3) return 2;
    file = fopen(argv[1], "rb");
    if (!file || fseek(file, 0, SEEK_END) != 0) return 3;
    length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) return 4;
    reader.bytes = (png_bytep)malloc((size_t)length);
    if (!reader.bytes || fread(reader.bytes, 1, (size_t)length, file) != (size_t)length) return 5;
    fclose(file);
    reader.size = (size_t)length;
    reader.offset = 0;

    png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return 6;
    info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) return 7;
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        free(reader.bytes);
        return 8;
    }
    png_set_read_fn(png_ptr, &reader, read_from_memory);
    png_read_info(png_ptr, info_ptr);
    /* Reproduce the advisory's documented caller sequence. */
    if (argc == 2 || strcmp(argv[2], "safe") != 0) {
        png_uint_32 free_mask = (argc == 3 && strcmp(argv[2], "palette") == 0)
            ? PNG_FREE_PLTE : PNG_FREE_TRNS;
        png_free_data(png_ptr, info_ptr, free_mask, 0);
    }
    png_set_expand(png_ptr);
    png_read_update_info(png_ptr, info_ptr);
    rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    row = (png_bytep)malloc(rowbytes);
    png_read_row(png_ptr, row, NULL);
    free(row);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    free(reader.bytes);
    puts("decode completed");
    return 0;
}

