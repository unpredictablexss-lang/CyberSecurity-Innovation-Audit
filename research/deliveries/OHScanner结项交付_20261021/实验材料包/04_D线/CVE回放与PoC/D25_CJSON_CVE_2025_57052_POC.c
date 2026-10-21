#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

/* Uses only synthetic JSON and a deliberately malformed JSON Pointer. */
int main(void)
{
    const char *json = "[\"public-0\",\"public-1\",\"D_SYNTHETIC_SECRET\"]";
    const char *pointer = "/1844674407370955160B";
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        return 2;
    }

    cJSON *item = cJSONUtils_GetPointer(root, pointer);
    char *rendered = item ? cJSON_PrintUnformatted(item) : NULL;
    printf("resolved=%d synthetic_secret=%d value=%s\n", item != NULL,
           rendered && strstr(rendered, "D_SYNTHETIC_SECRET") != NULL,
           rendered ? rendered : "<null>");

    cJSON_free(rendered);
    cJSON_Delete(root);
    return 0;
}
