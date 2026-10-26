#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <tiffio.h>

int main(int argc, char **argv)
{
    if (argc != 3) return 64;
    const char *path = argv[1];
    char *end = NULL;
    unsigned long requested_height = strtoul(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || requested_height < 1 || requested_height > 2) return 64;
    TIFF *out = TIFFOpen(path, "w");
    if (out == NULL) return 10;
    TIFFSetField(out, TIFFTAG_IMAGEWIDTH, 1);
    TIFFSetField(out, TIFFTAG_IMAGELENGTH, 2);
    TIFFSetField(out, TIFFTAG_SAMPLESPERPIXEL, 3);
    TIFFSetField(out, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(out, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(out, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(out, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_RGB);
    TIFFSetField(out, TIFFTAG_ROWSPERSTRIP, 2);
    TIFFSetField(out, TIFFTAG_COMPRESSION, COMPRESSION_NONE);
    uint8_t row[3] = { 0x44, 0x88, 0xcc };
    for (uint32_t y = 0; y < 2; ++y) {
        if (TIFFWriteScanline(out, row, y, 0) < 0) { TIFFClose(out); return 11; }
    }
    TIFFClose(out);

    TIFF *in = TIFFOpen(path, "r");
    if (in == NULL) return 12;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) { TIFFClose(in); return 13; }
    uint8_t *region = mmap(NULL, (size_t)page * 2, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { TIFFClose(in); return 14; }
    uint32_t *raster = (uint32_t *)(region + page);
    if (mprotect(raster, (size_t)page, PROT_READ | PROT_WRITE) != 0) {
        munmap(region, (size_t)page * 2); TIFFClose(in); return 15;
    }
    int ok = TIFFReadRGBAImageOriented(in, 1, (uint32_t)requested_height,
                                       raster, ORIENTATION_TOPLEFT, 0);
    if (ok) printf("read_ok requested_height=%lu pixel=%08x\n", requested_height, raster[0]);
    else fprintf(stderr, "read_failed requested_height=%lu\n", requested_height);
    TIFFClose(in);
    munmap(region, (size_t)page * 2);
    return ok ? 0 : 20;
}
