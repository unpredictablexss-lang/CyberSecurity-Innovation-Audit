#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char *end = NULL;
    long depth;
    long i;
    curl_mime *root;
    curl_mime *current;
    CURLcode result;
    if(argc != 2) {
        fprintf(stderr, "usage: %s depth\n", argv[0]);
        return 2;
    }
    errno = 0;
    depth = strtol(argv[1], &end, 10);
    if(errno || end == argv[1] || *end || depth < 1 || depth > 100000)
        return 2;
    if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
        return 3;
    root = curl_mime_init(NULL);
    if(!root)
        return 4;
    current = root;
    for(i = 0; i < depth; ++i) {
        curl_mimepart *part = curl_mime_addpart(current);
        curl_mime *sub = curl_mime_init(NULL);
        if(!part || !sub) {
            curl_mime_free(root);
            curl_global_cleanup();
            return 5;
        }
        result = curl_mime_subparts(part, sub);
        if(result != CURLE_OK) {
            curl_mime_free(sub);
            curl_mime_free(root);
            curl_global_cleanup();
            return 6;
        }
        current = sub;
    }
    fprintf(stderr, "created nested MIME depth=%ld; freeing root\n", depth);
    curl_mime_free(root);
    puts("cleanup completed");
    curl_global_cleanup();
    return 0;
}
