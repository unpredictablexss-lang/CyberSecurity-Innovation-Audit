# OpenHarmony 真实目标组件筛选记录

> 2026-10-03 实测。源码位于 WSL 的 /home/audit/openharmony-targets/，不提交完整目标仓库。本文的扫描命中都是文本候选，不是漏洞结论；未运行的步骤保持 unknown / not_started。

## 决策

T1 cJSON 是**首条工程闭环主目标**：固定提交、局部宿主机构建和测试已验证，可以马上接真实扫描与人工复核。它是 OpenHarmony 组织维护的第三方集成，竞赛的 OpenHarmony 特有性较弱，因此 T2 c_utils 是第一方组件备选，需要尽早探测其可独立编译的子模块。T3 lwIP 适合网络输入方向，但当前宿主机测试构建被工具链/代码兼容问题阻断，暂不占用主线时间。**工程主目标不等于最终参赛漏洞目标。**赛题以 [OpenHarmony 下载页](https://www.openharmony.cn/download) 所介绍的社区仓库为范围依据；三个 GitHub 镜像与指定版本是否满足最终提交口径，还需在确定报告目标时核对官方清单/赛方说明。

| ID | 仓库 | 固定 master commit | 输入面 | 实测构建/测试 | fuzz | 决定 |
|---|---|---|---|---|---|---|
| T1 | [third_party_cJSON](https://github.com/openharmony/third_party_cJSON)（C，第三方集成） | 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 | JSON 解析/打印及路径工具 | cJSON_test 构建成功，ctest 1/1；全目标构建失败 | 有入口，未运行 | primary_target |
| T2 | [commonlibrary_c_utils](https://github.com/openharmony/commonlibrary_c_utils)（C/C++，第一方工具） | 3bdc11e00e7bf6e577cee300ad51045ca9958efd | 字符串、文件/路径、序列化 | 未运行；需 OpenHarmony GN 整树依赖 | 有 fuzztest 目录，未运行 | backup_target |
| T3 | [third_party_lwip](https://github.com/openharmony/third_party_lwip)（C，网络协议栈） | 83886e5c2bebe98dc85976deceaccecfd627b950 | 网络包及协议字段 | 宿主 CMake 配置成功，单测编译失败 | 有相关文件，未运行 | candidate / blocked |

三者均已浅克隆且以 git rev-parse HEAD 核对提交；浅克隆并不提供完整历史。三者的历史安全修复状态均为 **unknown**，本轮尚未做补丁回放。决策不是漏洞数量排名，而是两周内能否取得可复现证据。

## T1：cJSON

- 源码：[固定提交](https://github.com/openharmony/third_party_cJSON/tree/0c2c9dff82cc85539c8362132d7a5f6bf7d1e748)；本地 /home/audit/openharmony-targets/third_party_cJSON，工作树干净。
- 主体文件：cJSON.c、cJSON_Utils.c、同名头文件；仓库另含 tests、fuzzing。LICENSE 为 MIT 风格，后续保留原许可。
- 环境：Ubuntu 22.04 WSL2、GCC 11.4、CMake 3.22、Ninja 1.10；本轮没有准确记录耗时/峰值内存。

实际执行的构建/测试命令：

~~~bash
cmake -S /home/audit/openharmony-targets/third_party_cJSON -B /home/audit/openharmony-targets/third_party_cJSON-build -G Ninja -DENABLE_CJSON_TEST=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build /home/audit/openharmony-targets/third_party_cJSON-build --target cJSON_test -j 4
ctest --test-dir /home/audit/openharmony-targets/third_party_cJSON-build -R '^cJSON_test$' --output-on-failure
cmake --build /home/audit/openharmony-targets/third_party_cJSON-build -j 4
~~~

前三条成功，cJSON_test 1/1 通过。最后的**完整构建失败**：tests/unity/src/unity_internals.h 引用缺失的 test_fwk.h。局部通过不能写成完整测试套件通过。本地原始日志在 outputs/logs/cjson_{configure,target_build,test,full_build}.log；它们被 Git 忽略，复现时重新运行命令。

实际扫描命令：

~~~bash
.venv/bin/python -m src.cli scan /home/audit/openharmony-targets/third_party_cJSON --json-out outputs/reports/cjson_candidate.json --md-out outputs/reports/cjson_candidate.md
~~~

结果：99 个源码文件、22,377 行、跳过 0 个、49 条文本候选；sprintf 18、memcpy 16、strcpy 14、strcat 1。按目录：核心 cJSON.c 与 cJSON_Utils.c 共 26 条，tests 22 条，fuzzing 1 条。扫描器暂不支持用户指定排除目录，分母包括仓库内 Unity 测试框架；49 **不能**当成核心库漏洞数或准确率分子。完整运行报告只在本地忽略目录 outputs/reports/。

成熟工具基线：clang-tidy、Clang Static Analyzer 均 not_started。fuzzing/cjson_read_fuzzer.c 有 LLVMFuzzerTestOneInput 入口，但未运行。ASan/UBSan 原组件验证也尚未开始。

### 第一批核心调用初筛

阅读固定提交的调用点、紧邻分配与边界代码后，对 10 条核心候选做初筛。likely_safe 不是严格安全证明；interesting 不是漏洞确认。

| 位置 | 规则 | 状态 | 初筛依据 / 待验证点 |
|---|---|---|---|
| cJSON.c:204 | memcpy | likely_safe | 分配与拷贝均用 strlen+终止符长度；依赖有效输入字符串。 |
| cJSON.c:367 | memcpy | needs_context | 按 number_string_length+1 分配；待追踪长度与输入 offset 上界。 |
| cJSON.c:465 | strcpy | likely_safe | 新串长度不超过旧串且有重叠检查；依赖对象缓冲有效。 |
| cJSON.c:570 | memcpy | needs_context | 扩容后拷贝 offset+1；待验证上游 offset 不变量。 |
| cJSON.c:618 | sprintf | likely_safe | 固定字面量 null 写入 26 字节缓冲。 |
| cJSON.c:622 | sprintf | likely_safe | int 十进制文本写入 26 字节缓冲；保留平台类型假设。 |
| cJSON.c:980 | strcpy | likely_safe | ensure 先申请空串字面量所需空间并检查。 |
| cJSON.c:1021 | memcpy | needs_context | ensure 申请 output_length+常量；待查整数溢出与 ensure 约束。 |
| cJSON_Utils.c:234 | sprintf | interesting | full_pointer 分配后未见空指针检查；需失败分配器验证及长度溢出分析。 |
| cJSON_Utils.c:245 | strcat | interesting | full_pointer 分配后立即写入；需验证错误路径的实际可达性与影响。 |

计数：likely_safe 5、needs_context 3、interesting 2、validated 0。最后两条仅是内存不足路径调查点，尚无安全影响、可控触发或未公开缺陷的证据。赛题原文明确不鼓励没有实际安全危害的普通 DoS；因此即便失败分配器能使其崩溃，也不得自动列为参赛漏洞。下一步核对完整调用链与现有测试，再决定是否值得做失败分配实验。

## T2：c_utils

- [固定提交](https://github.com/openharmony/commonlibrary_c_utils/tree/3bdc11e00e7bf6e577cee300ad51045ca9958efd)；本地 /home/audit/openharmony-targets/commonlibrary_c_utils。
- 仓库有 base/BUILD.gn、base/test/BUILD.gn、base/test/unittest 与 base/test/fuzztest。文档给出的构建途径为 OpenHarmony 整树 GN/Ninja；尚未找到顶层 host CMake 工程。
- build/test/fuzz 的运行结果均 **unknown / not_started**。测试目录存在不等于测试已通过。
- 第一方价值高，但完整产品依赖可能超出两周时间窗。后续只选一个输入处理子模块探测编译闭环，设时间上限。

## T3：lwIP

- [固定提交](https://github.com/openharmony/third_party_lwip/tree/83886e5c2bebe98dc85976deceaccecfd627b950)；本地 /home/audit/openharmony-targets/third_party_lwip。
- contrib/ports/unix/check/CMakeLists.txt 提供宿主机单测入口。本机为探测安装了 Ubuntu check 与 libsubunit-dev。
- CMake 配置成功；编译被严格 -Werror 与当前工具链/源码组合阻断，包括 -fstack-check 和栈保护标志冲突、空翻译单元、C90 对注释的限制。Clang 探测还碰到该 CMakeLists.txt:19 的 list 参数顺序问题。没有测试通过证据。
- build: blocked；test/fuzz: not_started。网络输入价值高，但当前不继续在主线上修第三方构建问题。

## 下一步与验收

1. 保存 T1 TargetSnapshot、固定提交、局部构建与测试结果；不夸大全目标构建状态。
2. 为扫描器加入明确源码范围，重新扫描核心文件并保留当前 49 条全仓基线作对照。
3. 用一个成熟静态工具做基线，对首批初筛候选逐项复核；不要把 warning 数量相加成漏洞数。
4. 选一个有正常输入对照的真实调用路径，必要时用 ASan/UBSan 和失败分配器重复验证。无法复现时标 inconclusive/blocked。
5. 同时探测 T2 的可独立编译子模块，避免最终作品只停留在通用第三方库。
