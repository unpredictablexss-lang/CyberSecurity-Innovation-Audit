# 检测器能力与改进报告

| 检测线 | 检测器 | 准入状态 | 候选数 | 完成 | 部分 | 阻塞 | 失败 | 已分析文件 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C | ohscanner.ark.runtime.type_safety | research_unadmitted | 0 | 0 | 311 | 7 | 0 | 58680 |
| A | ohscanner.cpp.bounds | production_research_candidate | 1284 | 0 | 310 | 3 | 9 | 82 |
| A | ohscanner.cpp.integer_bounds | production_research_candidate | 516 | 0 | 319 | 3 | 0 | 82 |
| A | ohscanner.cpp.lifetime | production_research_candidate | 9 | 0 | 311 | 7 | 0 | 57913 |
| A | ohscanner.cpp.null_dereference | production_research_candidate | 403359 | 0 | 335 | 0 | 0 | 23526 |
| A | ohscanner.cpp.resource_lifetime | production_research_candidate | 324 | 0 | 319 | 3 | 0 | 82 |
| A | ohscanner.cpp.shared_ptr_race | production_research_candidate | 1415 | 0 | 308 | 7 | 3 | 57597 |
| A | ohscanner.cpp.unsafe_memory_call | production_research_candidate | 9323 | 0 | 318 | 3 | 1 | 82 |
| D | ohscanner.data.sensitive_exposure | research_unadmitted | 0 | 0 | 0 | 338 | 0 | 0 |
| B | ohscanner.interface.ipc | production_research_candidate | 314 | 0 | 322 | 0 | 0 | 64745 |
| B | ohscanner.oh.arkts_js | production_research_candidate | 31 | 0 | 114 | 0 | 0 | 11262 |

## 优先改进

1. 为 CWE-476 增加函数内空值来源、参数约束、RAII 和跨函数摘要，减少无条件路径噪声。
2. 增加 C/C++ 预处理、宏展开、条件编译和构建数据库支持，扩大可解析文件覆盖。
3. 对 Rust、ArkTS/JS、Kernel 和大型仓建立语言专用前端与分片调度，避免统一超时造成 partial。
4. 将证据从单一模式匹配升级为源到汇数据流、别名、生命周期和并发事件序分析。
5. 引入可重复 ground truth 基准、分层指标和回归门槛，才能量化识别率、漏报率和精确率。
6. 增加增量扫描、并行缓存、文件级超时和失败恢复，降低全量扫描时延。
