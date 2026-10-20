# D 线已披露 CVE 的 PoC 与修复证据索引

更新日期：2026-10-19。本文汇总现有源码回放、组件 PoC/ASan Harness、上游修复对照及 Workbench 链路证据，方便从报告中心和仓库内定位复现材料。

## 结论口径

这里的“confirmed”只用于明确限定的对象：公开 CVE 是否披露、固定上游组件源码是否存在根因、或组件级 PoC 是否重现了具体内存错误。它不表示某个 OpenHarmony 产品包含该版本，也不表示产品入口可达或攻击者能触发。扫描报告仍是 `candidate`；产品 `validated_vulnerability=0`。凡是只有静态形态命中而无对应组件动态复现的项目，按 `candidate` 处理。产品构建、调用链和影响证据缺失时为 `unknown`。

## 已写 PoC/修复材料（各自结论严格限定在证据范围）

| CVE | 证据结论 | PoC 与修复对照 | 产品状态 |
|---|---|---|---|
| CVE-2025-57052 (cJSON) | 固定旧版组件 API 将畸形 JSON Pointer 解析到合成数组标记；修复版拒绝。组件行为 confirmed。 | [报告](D25_CJSON_CVE_2025_57052_REPORT.md)、[C PoC](D25_CJSON_CVE_2025_57052_POC.c)、[回放 JSON](D25_CJSON_CVE_2025_57052_REPLAY.json)。修复将循环检查从 `pointer[0]` 改为 `pointer[position]`。 | `unknown`；无产品依赖版本、产品调用入口或产品复测。 |
| CVE-2026-46675 (libpng) | 固定 libpng 1.6.55 归档在指定 `png_read_end()` 调用顺序下由 ASan 重现 heap-use-after-free 3/3；应用上游修复提交后同一输入 0/3。组件复现 confirmed。 | [报告](D30_LIBPNG_CVE_2026_46675_REPORT.md)、[回放 JSON](D30_LIBPNG_CVE_2026_46675_REPLAY.json)。修复对照是在 1.6.55 临时副本应用 `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`，不是完整 1.6.59 发布树。 | `unknown`；未确认产品是否采用该归档，也未验证产品调用顺序、入口或影响。 |
| CVE-2025-9900 (libtiff) | 固定 libtiff 4.7.0 组件 API 对尺寸不匹配的 raster 发生 ASan 越界写；官方修复对照无报告，旧版安全尺寸控制无报告。组件内存错误 confirmed；任意地址控制未证实。 | [报告](D31_LIBTIFF_CVE_2025_9900_REPORT.md)、[回放 JSON](D31_LIBTIFF_CVE_2025_9900_REPLAY.json)。建议升级至含上游 MR !732 的版本或审查并回移等价完整尺寸处理。 | `unknown`；产品是否包含该快照及调用参数可控性未证实。 |
| CVE-2026-28733 (storage statistics) | 固定服务源码存在 map iterator 逃逸锁作用域、另一路径清空同一 map 的候选形态；合成 source-shaped ASan Harness 重现 UAF 仅确认该容器时序模型，不是服务组件复现或 CVE 根因确认。 | [报告](D36_CVE_2026_28733_REPORT.md)、[源码回放](D36_CVE_2026_28733_REPLAY.json)、[ASan Harness](D36_CVE_2026_28733_ITERATOR_ASAN.cpp)、[ASan 结果](D36_CVE_2026_28733_ASAN_REPLAY.json)。建议避免返回锁外迭代器，让读取/更新和快照清空在同一同步策略内完成。 | `unknown`；没有对完整服务构建做因果复现，产品入口、竞态调度和影响未证实。 |
| CVE-2026-28751 (MTP xattr) | 固定旧源码具有满容量 xattr 值未终止便作为 C 字符串使用的候选形态；source-shaped ASan Harness 旧形态 3/3 越界读、修复形态 0/3，仅确认此输入/代码形态模型，不是 filemanagement 服务构建或产品复现。 | [报告](D37_CVE_2026_28751_REPORT.md)、[源码回放](D37_CVE_2026_28751_REPLAY.json)、[ASan 结果](D37_CVE_2026_28751_ASAN_REPLAY.json)。修复预留终止字节并允许满容量边界写 NUL。 | `unknown`；Harness 为源形态，不是完整服务或产品利用。 |
| CVE-2026-58313 (LRU cache) | 固定旧 LRU 组件头文件的并发 Get/Put/Clear Harness 在 ASan 下 3/3 double-free；锁修复版 3/3 无 Sanitizer 报告。组件内存错误 confirmed，不等同公开公告所述产品 UAF 已验证。 | [报告](D39_CVE_2026_58313_REPORT.md)、[ASan Harness](D39_CVE_2026_58313_ASAN.cpp)、[ASan 结果](D39_CVE_2026_58313_ASAN_REPLAY.json)、[面板两轮回放](D39_CVE_2026_58313_PANEL_REPLAY.json)。修复版为所有共享容器访问使用同一互斥量。 | `unknown`；产品调用可达、产品构建和攻击者影响未证实。 |
| CVE-2022-45877 (device manager PIN) | OpenHarmony 公告及固定旧/修复源码差分支持历史组件根因 confirmed；本地仅做源码回放，未做网络或服务级 PoC。 | [报告](D33_CVE_2022_45877_REPORT.md)、[源码回放 JSON](D33_CVE_2022_45877_REPLAY.json)。修复是不再把 PIN 放入响应 token，改由本地认证交互处理。 | `unknown`；无本地产品版本、设备抓包或产品影响验证。 |

其余已披露 CVE 的窄源码规则和旧/修复源码回放见 [扫描记录](D_KNOWN_CVE_SCAN_20261019.md) 与对应的 `D23`、`D24`、`D28`、`D29`、`D30`、`D35`、`D38` 报告/回放文件。它们以源码候选和修复形态区分为主；没有单独列入上表的，不应据此声称组件动态 PoC confirmed。

## 静态扫描器与面板

仓库安全扫描页中 `D 敏感数据到日志` 和 `D 已披露 CVE 组件源码规则` 均为显式勾选、默认关闭的研究规则。CVE 规则经 Catalog 进入扫描计划，再由 Worker 产出固定源码候选、证据义务和 JSON/Markdown 报告；固定源码查看器校验哈希。D39 两轮 Workbench API→Worker→报告→源码查看链路对旧版各得到 1 条候选、修复版 0 条，viewer SHA 与固定输入一致。D42 另记录了仓库扫描页的真实浏览器验收，覆盖显式选规则、预览、提交、候选详情和报告下载；该证据验证页面与 Worker 数据链，不等同产品 PoC。

复现入口以各报告中记载的命令和固定 commit 为准。不要直接在原始目标源码仓库切换版本；D replay 脚本从固定 Git 对象读取或校验文件，组件 Harness 只使用合成输入，除报告说明外不访问产品设备或网络。