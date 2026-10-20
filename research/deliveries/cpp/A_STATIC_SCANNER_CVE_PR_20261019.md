# A 线静态扫描器已披露漏洞覆盖改进

## 本次合入范围

- 默认可达的 `integer_bounds` 增加无符号尺寸相减进入缩放指针偏移的候选规则，覆盖 libtiff CVE-2025-9900 根因形态。
- 默认可达的 `resource_lifetime` 增加跨结构成员别名释放后读取和 callback-mediated recursive cleanup 关系，覆盖 libpng CVE-2026-33416、curl CVE-2026-92391 的候选根因形态；Runner partial finding 归一化保留 blocked 状态和 finding。
- 增加 `ohscanner.cpp.path_source_file_sink` 的静态候选模块与安全/无关/partial 回归。它尚未 Catalog 注册，不会被普通生产 profile 调度；注册和具名 profile 由 shared owner 后续审查。
- 增加 `run_a_disclosed_cve_scan.ps1`，通过 M2 CLI 显式调用默认内存/生命周期检测器和已注册的 `ohscanner.known_disclosed_cves`，用于定向静态扫描，不改变全局默认 detector 集。
- 补充 exact-source / fixed / safe / unrelated / partial CLI 结果与整合报告全文 24 个 CVE 编号的 A 线可达性矩阵。Ark CVE-2025-0587 和 CVE-2025-23420 的当前 CLI vulnerable/fixed 结果分别为 1/0、5/0；旧 23420 patch digest 分歧保留为审计项。

## 本地验证

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors tests.detectors.test_cpp_path_safety_detector tests.detectors.test_cpp_resource_lifetime_detector tests.detectors.test_cpp_cross_member_alias_regression tests.detectors.test_cpp_recursive_cleanup_regression tests.detectors.test_cpp_pointer_offset_underflow tests.detectors.test_known_disclosed_cves -q` — 70 项通过。
- A profile wrapper source-shaped CLI control：漏洞形状 3 diagnostics、fixed 0；漏洞侧 `completed_with_limitations`，fixed 侧 `completed`，两侧 `validated_vulnerability=0`。
- Ark exact pinned-source replay：CVE-2025-0587 1/0、CVE-2025-23420 5/0；safe/unrelated 0，truncated input partial/blocked。
- `git diff --check` 通过；`python -m scripts.check_change_scope --base db77164fdc2af0da02e4d3efc056d84694fd68e8 --lane cpp` 检查 102 个路径且零越界。

## 状态边界

所有 findings 都是静态候选，不是产品漏洞确认。libtiff/libpng exact translation-unit replay 仍有 partial/blocked；CVE-2026-46675 根因、cJSON 67216/67215 exact-source coverage、DSoftBus 26690 current replay仍未闭环。CJSON 复杂度和 libpng shared-state 原型尚未注册，且未通过 exact-source CLI discrimination，因此不在本次生产代码合入范围。`known_disclosed_cves` 仍显式 opt-in；普通默认 profile 不会自动启用它。此 PR 不修改 Catalog、Runner、contracts 或 API。
