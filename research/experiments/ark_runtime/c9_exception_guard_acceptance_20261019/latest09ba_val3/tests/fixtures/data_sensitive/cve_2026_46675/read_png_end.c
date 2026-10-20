#include <png.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
 FILE *input; png_structp png; png_infop info;
 png_uint_32 width, height; int bit_depth, color_type, interlace, compression, filter;
 if (argc != 3 || (strcmp(argv[2], "read-end") != 0 && strcmp(argv[2], "read-rows") != 0)) {
  fprintf(stderr, "usage: %s FILE.png read-end|read-rows\n", argv[0]); return 64;
 }
 input=fopen(argv[1],"rb"); if (!input) return 66;
 png=png_create_read_struct(PNG_LIBPNG_VER_STRING,NULL,NULL,NULL); if (!png) { fclose(input); return 70; }
 info=png_create_info_struct(png); if (!info) { png_destroy_read_struct(&png,NULL,NULL); fclose(input); return 71; }
 if (setjmp(png_jmpbuf(png))) { fprintf(stderr,"PNG_ERROR\n"); png_destroy_read_struct(&png,&info,NULL); fclose(input); return 2; }
 png_init_io(png,input); png_read_info(png,info); fprintf(stderr,"PNG_INFO_OK\n");
 if (strcmp(argv[2],"read-rows")==0) {
  png_bytep *rows; png_bytep pixels; png_size_t rowbytes;
  png_get_IHDR(png,info,&width,&height,&bit_depth,&color_type,&interlace,&compression,&filter);
  png_read_update_info(png,info); rowbytes=png_get_rowbytes(png,info);
  pixels=(png_bytep)malloc(rowbytes*height); rows=(png_bytep*)malloc(sizeof(png_bytep)*height);
  if (!pixels || !rows) { free(rows); free(pixels); png_error(png,"allocation failed"); }
  for (png_uint_32 y=0;y<height;++y) rows[y]=pixels+y*rowbytes;
  png_read_image(png,rows); free(rows); free(pixels); fprintf(stderr,"PNG_ROWS_OK\n");
 }
 png_read_end(png,info); fprintf(stderr,"PNG_READ_END_OK\n");
 png_destroy_read_struct(&png,&info,NULL); fclose(input); return 0;
}