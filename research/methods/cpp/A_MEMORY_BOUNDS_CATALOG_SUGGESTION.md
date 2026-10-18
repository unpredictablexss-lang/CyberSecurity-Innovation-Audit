# A memory-safety catalog registration suggestion

这是队友 A 的建议，不是已合入的公共契约变更。当前 Catalog 仍由公共负责人维护。

- `ohscanner.cpp.bounds` -> `src.ohscanner.detectors.cpp.bounds_detector.CppBoundsDetector`, version `0.2.5`, kind `research_candidate`.
- `ohscanner.cpp.integer_bounds` -> `src.ohscanner.detectors.cpp.integer_bounds_detector.CppIntegerBoundsDetector`, version `0.2.1`, kind `research_candidate`.
- 必须保持 source-bound schema v2、legacy v1 只读兼容、candidate/unassessed 默认状态。
- 必须新增正/固定/安全/非相关/unknown 回归后再由负责人审查；不要把研究脚本的候选数当成漏洞数。


- `ohscanner.cpp.resource_lifetime` -> `src.ohscanner.detectors.cpp.resource_lifetime_detector.CppResourceLifetimeDetector`, version `0.1.2`, kind `research_candidate`; keep branch/label transitions unknown and require the A-RES-01 controls before owner review.

- `ohscanner.cpp.unsafe_memory_call` -> `src.ohscanner.detectors.cpp.unsafe_memory_call_detector.CppUnsafeMemoryCallDetector`, version `0.1.2`, kind `research_candidate`; macro-only format expressions remain unknown rather than candidates.
