#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cJSON_Utils.h"

static int allocation_count = 0;
static int fail_on_allocation = 0;

static void *test_malloc(size_t size)
{
    allocation_count++;
    if ((fail_on_allocation > 0) && (allocation_count == fail_on_allocation))
    {
        return NULL;
    }
    return malloc(size);
}

static void test_free(void *pointer)
{
    free(pointer);
}

static int run_case(int object_case, int inject_failure)
{
    cJSON *root = NULL;
    cJSON *target = NULL;
    char *pointer = NULL;
    cJSON_Hooks hooks = { test_malloc, test_free };

    root = object_case ? cJSON_CreateObject() : cJSON_CreateArray();
    target = cJSON_CreateString("value");
    if ((root == NULL) || (target == NULL))
    {
        cJSON_Delete(root);
        cJSON_Delete(target);
        return 10;
    }

    if (object_case)
    {
        cJSON_AddItemToObject(root, "child", target);
    }
    else
    {
        cJSON_AddItemToArray(root, target);
    }

    allocation_count = 0;
    fail_on_allocation = inject_failure ? 2 : 0;
    cJSON_InitHooks(inject_failure ? &hooks : NULL);

    pointer = cJSONUtils_FindPointerFromObjectTo(root, target);

    if (pointer != NULL)
    {
        printf("pointer=%s\n", pointer);
        cJSON_free(pointer);
    }
    else
    {
        printf("pointer=NULL\n");
    }

    cJSON_InitHooks(NULL);
    cJSON_Delete(root);
    return 0;
}

int main(int argc, char **argv)
{
    int object_case = 0;
    int inject_failure = 0;

    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <array|object> <normal|fail-second>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "array") == 0)
    {
        object_case = 0;
    }
    else if (strcmp(argv[1], "object") == 0)
    {
        object_case = 1;
    }
    else
    {
        fprintf(stderr, "unknown path: %s\n", argv[1]);
        return 2;
    }

    if (strcmp(argv[2], "normal") == 0)
    {
        inject_failure = 0;
    }
    else if (strcmp(argv[2], "fail-second") == 0)
    {
        inject_failure = 1;
    }
    else
    {
        fprintf(stderr, "unknown allocator mode: %s\n", argv[2]);
        return 2;
    }

    return run_case(object_case, inject_failure);
}
