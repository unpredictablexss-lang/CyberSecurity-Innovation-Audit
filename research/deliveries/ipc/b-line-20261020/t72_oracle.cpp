#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
static bool check_read_length(size_t count, size_t type_size, size_t remaining) {
    return count <= remaining && count * type_size <= remaining;
}
static void vulnerable(const char* which, int32_t count) {
    size_t remaining = static_cast<size_t>(count) * 4;
    if (count <= 0 || !check_read_length(static_cast<size_t>(count), 4, remaining)) return;
    if (std::strcmp(which, "type") == 0) {
        int32_t* p = static_cast<int32_t*>(std::malloc(static_cast<size_t>(count)));
        if (!p) std::abort();
        for (int32_t i = 0; i < count; ++i) p[i] = i;
        std::printf("last=%d\n", p[count - 1]);
        std::free(p);
    } else {
        int64_t* p = static_cast<int64_t*>(std::malloc(static_cast<size_t>(count)));
        if (!p) std::abort();
        for (int32_t i = 0; i < count; ++i) p[i] = i;
        std::printf("last=%lld\n", static_cast<long long>(p[count - 1]));
        std::free(p);
    }
}
static void fixed(int32_t count, size_t remaining) {
    if (count <= 0 || !check_read_length(static_cast<size_t>(count), 4, remaining)) return;
    int32_t* type = static_cast<int32_t*>(std::malloc(sizeof(int32_t) * static_cast<size_t>(count)));
    int64_t* id = static_cast<int64_t*>(std::malloc(sizeof(int64_t) * static_cast<size_t>(count)));
    if (!type || !id) std::abort();
    for (int32_t i = 0; i < count; ++i) { type[i] = i; id[i] = i; }
    if (count > 0) std::printf("last=%d,%lld\n", type[count - 1], static_cast<long long>(id[count - 1]));
    std::free(type); std::free(id);
}
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    std::string mode = argv[1];
    int32_t count = argc > 2 ? std::atoi(argv[2]) : 1;
    if (mode == "old-type" || mode == "old-id") vulnerable(mode == "old-type" ? "type" : "id", count);
    else if (mode == "fixed") fixed(count, static_cast<size_t>(count > 0 ? count * 4 : 0));
    else if (mode == "safe-zero") fixed(0, 0);
    else if (mode == "reject-short") fixed(count, count > 0 ? static_cast<size_t>(count * 4 - 1) : 0);
    else return 2;
    std::puts("completed_without_asan_report");
    return 0;
}
