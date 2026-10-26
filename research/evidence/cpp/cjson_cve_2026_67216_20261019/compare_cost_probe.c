#define _POSIX_C_SOURCE 200809L
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { char *data; size_t len; size_t cap; } buffer;

static int append(buffer *b, const char *s)
{
    size_t n = strlen(s);
    if(b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        char *p;
        while(cap < b->len + n + 1)
            cap *= 2;
        p = (char *)realloc(b->data, cap);
        if(p == NULL)
            return 0;
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, s, n + 1);
    b->len += n;
    return 1;
}

static int make_tree(buffer *b, int depth, int duplicate)
{
    int i;
    if(depth == 0)
        return append(b, "0");
    if(!append(b, "{"))
        return 0;
    for(i = 0; i < 2; ++i) {
        if(i && !append(b, ","))
            return 0;
        if(!append(b, duplicate ? "\"x\":" : (i ? "\"y\":" : "\"x\":")))
            return 0;
        if(!make_tree(b, depth - 1, duplicate))
            return 0;
    }
    return append(b, "}");
}

static double elapsed_ms(struct timespec a, struct timespec b)
{
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 +
           (double)(b.tv_nsec - a.tv_nsec) / 1000000.0;
}

int main(int argc, char **argv)
{
    int depth, duplicate, mismatch = 0;
    buffer input = {0}, other = {0};
    cJSON *a, *b;
    struct timespec start, end;
    cJSON_bool equal;
    if(argc != 3 && argc != 4)
        return 2;
    depth = atoi(argv[1]);
    duplicate = atoi(argv[2]);
    if(argc == 4)
        mismatch = atoi(argv[3]);
    if(depth < 1 || depth > 16 || (duplicate != 0 && duplicate != 1))
        return 2;
    if(!make_tree(&input, depth, duplicate))
        return 3;
    if(!append(&other, mismatch ? "[]" : input.data))
        return 3;
    a = cJSON_Parse(input.data);
    b = cJSON_Parse(other.data);
    if(a == NULL || b == NULL) {
        fprintf(stderr, "parse failed at depth=%d\n", depth);
        return 4;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    equal = cJSON_Compare(a, b, 1);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("depth=%d duplicate_keys=%d mismatch=%d bytes_each=%zu equal=%d compare_ms=%.3f\n",
           depth, duplicate, mismatch, input.len, (int)equal, elapsed_ms(start, end));
    cJSON_Delete(a);
    cJSON_Delete(b);
    free(input.data);
    free(other.data);
    return equal ? 0 : 5;
}
