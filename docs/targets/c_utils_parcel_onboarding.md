# c_utils parcel 子模块独立编译与模糊测试探测

> 目标：commonlibrary_c_utils（OpenHarmony 第一方 C++ 基础库）
> Commit: 3bdc11e00e7bf6e577cee300ad51045ca9958efd
> 日期：2026-10-04
> 结论：parcel 子模块可在宿主机独立编译 + libFuzzer 模糊测试，无需整树 OpenHarmony GN/Ninja 构建。

## 结论摘要

c_utils 的 parcel（IPC 序列化/反序列化）子模块可以在 Ubuntu 22.04 WSL2 上独立编译并运行 libFuzzer，只需一个最小 securec stub 和一个 fuzz_log override，不依赖 OpenHarmony 整树构建环境。这是第一方组件里最有价值的输入处理攻击面之一，可作为 cJSON 之后的下一个真实目标。

## 仓库结构

- Rust + C++ 混合：`base/src/rust/`（ashmem/directory/file，CXX 桥接）+ `base/src/*.cpp`（C++ 实现）。
- C++ 核心约 7201 行、30 个 .cpp。
- 7 个 fuzz target：parcel / refbase / string / thread / timer / ashmem / directory。
- 无顶层 CMake；官方构建途径为 OpenHarmony 整树 `build.sh --product-name rk3568 --build-target c_utils`。

## 依赖分析（为何能独立编译）

| 依赖 | 情况 | 处理 |
|---|---|---|
| securec（bounds_checking_function） | parcel.cpp 仅用 `memcpy_s`（2 处） | 最小 stub |
| hilog | `utils_log.h` 仅在 `CONFIG_HILOG` 下引入 | 不定义该宏，日志宏退化为空 |
| FuzzedDataProvider.h | clang-14 自带 | `-I /usr/lib/llvm-14/lib/clang/14.0.0/include` |
| refbase / flat_obj / nocopyable / string_ex / unicode_ex | 本地头文件 + 实现 | 与 parcel 一起编译 |

`strcpy_s` 仅出现在 ashmem.cpp / directory_ex.cpp（Rust 桥接文件），parcel 链路不需要。

## 上游小 bug

`base/test/fuzztest/fuzz_log.h` 的 `#else` 分支把宏误写成 `PARCEL_LOG*` 而非 `FUZZ_LOG*`，导致 `DEBUG_FUZZ` 未定义时 `FUZZ_LOGI` 等未定义。用 override 头文件规避，不改上游源码。

## 可复现编译命令

~~~bash
cd /home/audit/openharmony-targets/commonlibrary_c_utils

# 1. 最小 securec stub（memcpy_s + strcpy_s）
mkdir -p /tmp/cutils_compile_test
cat > /tmp/cutils_compile_test/securec.h <<'EOF'
#ifndef SECUREC_STUB_H
#define SECUREC_STUB_H
#include <stddef.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef int errno_t;
#define EOK 0
static inline errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL) { return -1; }
    if (destMax < count) { return -1; }
    memcpy(dest, src, count);
    return 0;
}
static inline errno_t strcpy_s(char *dest, size_t destMax, const char *src) {
    if (dest == NULL || src == NULL) { return -1; }
    size_t n = strlen(src);
    if (destMax <= n) { return -1; }
    memcpy(dest, src, n + 1);
    return 0;
}
#ifdef __cplusplus
}
#endif
#endif
EOF

# 2. fuzz_log override（规避上游 FUZZ_LOG* 宏 bug 与 hilog 依赖）
cat > /tmp/cutils_compile_test/fuzz_log_override.h <<'EOF'
#ifndef FUZZ_LOG_H
#define FUZZ_LOG_H
#define FUZZ_LOGF(...)
#define FUZZ_LOGE(...)
#define FUZZ_LOGW(...)
#define FUZZ_LOGI(...)
#define FUZZ_LOGD(...)
#endif
EOF

# 3. 编译 libFuzzer target
clang++ -std=c++17 -fsanitize=fuzzer,address -g -O1   -include /tmp/cutils_compile_test/fuzz_log_override.h   -I base/include -I base/src -I base/test/fuzztest   -I /tmp/cutils_compile_test   -I /usr/lib/llvm-14/lib/clang/14.0.0/include   base/test/fuzztest/parcel_fuzzer/parcel_fuzzer.cpp   base/src/parcel.cpp base/src/refbase.cpp base/src/string_ex.cpp base/src/unicode_ex.cpp   -o /tmp/parcel_fuzzer
~~~

## 模糊测试结果（首次 sanity run）

~~~text
timeout 15 /tmp/parcel_fuzzer -max_total_time=10 -print_final_stats=1
Done 780877 runs in 11 second(s)
stat::average_exec_per_sec: 70988
stat::new_units_added: 5817
stat::peak_rss_mb: 584
RUN_EXIT=0（无 crash）
~~~

这是首轮 10 秒 sanity run，仅证明 fuzzer 可跑、覆盖率在增长，不代表已穷尽或已发现漏洞。

## 攻击面价值

parcel_fuzzer.cpp 覆盖大量真实 IPC 输入处理：ReadBuffer/ReadString/ReadInt32Vector/ReadParcelable/ReadObject/ParseFrom/InjectOffsets 等，对应 `parcel.cpp`（1686 行）的反序列化路径，是内存安全（越界读写、整数溢出、未对齐访问）的高发区。fuzzer 源码里还明确标注了两类已知会 SIGBUS 的未对齐场景（ReadDouble after ReadBuffer、WriteDouble after RewindWrite），可作为后续验证的对照。

## 下一步

1. 长时间 libFuzzer（数小时）+ 多种 seed，收集 crash 并 triage。
2. 用本项目 scanner + triage 对 parcel.cpp / refbase.cpp 做文本候选 + 上下文，与 fuzz 结果互证。
3. 对 refbase.cpp 单独做 UAF/double-free 生命周期分析（引用计数是第二高价值攻击面）。
4. 若发现 crash，用 ASan 栈帧确认来自目标组件而非 harness，再评估安全影响与版本范围。
