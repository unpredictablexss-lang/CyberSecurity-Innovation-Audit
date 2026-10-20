# A-BOF-01 / A-INT-01 memory-safety detector specification

更新：2026-10-20。`ohscanner.cpp.bounds` 0.3.0 与 `ohscanner.cpp.integer_bounds` 0.2.1 已在生产 Catalog 注册，均作为候选规则运行。结果保持 `candidate/unassessed`；本地 CLI 回归不会设置 `validated_vulnerability`。

## Identity

| Detector | Version | Languages | Rules | Candidate CWE |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `0.3.0` | `c`, `cpp` | `ohcpp-memory-bounds-copy-candidate-001`, `ohcpp-memory-bounds-index-candidate-002`, `ohcpp-memory-bounds-element-access-candidate-003`, `ohcpp-memory-bounds-pointer-offset-candidate-004`, `ohcpp-memory-bounds-vector-index-candidate-005` | CWE-119/125/787 |
| `ohscanner.cpp.integer_bounds` | `0.2.1` | `c`, `cpp` | `ohcpp-integer-bounds-arithmetic-candidate-001`, `ohcpp-integer-bounds-truncation-candidate-002`, `ohcpp-integer-bounds-narrow-index-candidate-003` | CWE-190/191/681/680 |

实现入口：

- `src/ohscanner/detectors/cpp/memory_safety.py`
- `src/ohscanner/detectors/cpp/bounds_detector.py`
- `src/ohscanner/detectors/cpp/integer_bounds_detector.py`

源码绑定字段包括 `source_sha256`、`rule_version`、`rule_lineage_id` 和 `identity_quality=partial`。公共契约没有改变。两项 Detector 在 Catalog 的普通默认集合中启用，仍只产生候选。

## A-BOF-01 触发和排除

支持的局部形状：

1. 固定 C 数组或 `std::array<T,N>` 的 `memcpy`、`memmove`、`strncpy`、`snprintf`、`strcpy`、`strcat`。
2. 固定数组索引，包含常量越界和未证明上界的符号索引。
3. 识别 `if (n >= cap) return`、`if (n > cap) return`、`if (n < 0) return` 等单函数分支收窄。`SortElements*` 中未被 stable-array/index guard 保护的直接 `ElementAccessor::Get/Set` 作为历史 OOB 候选。

候选只在目的地容量可归属、常量越界或复制/索引上界未证明时产生。0.3.0 增加两种窄形状：无支配式尺寸守卫的 `std::vector` 下标，以及 unsigned 尺寸相减进入指针偏移；识别到直接前置下溢守卫或精确容量时保持安静。`sizeof(destination)` 精确容量、完整上界守卫、动态目的地、宏/别名未知和 `partial/failed/not_run` 不产生强结论。字节/元素单位、指针别名、包装函数、跨函数参数、模板和完整 CFG dominance 仍是 unknown。

## A-INT-01 触发和排除

支持的局部形状：

1. `size * count`、`offset + len`、`len - header` 等算术进入 `malloc/calloc/new[]`、copy length 或后续敏感 size 变量。
2. `uint8_t x = 255 + 1` 等常量结果超出目标类型范围的截断候选；`int32_t index = DoubleInRangeInt32(...)` 后再做 bounds check/offset multiply 的 narrowing-index 候选。
3. `__builtin_*overflow`、`SIZE_MAX /`、明确 checked arithmetic guard 作为安全对照。
4. `strnlen` + `if (len >= MAX) return` 的窄安全形状和 `uint8_t/uint16_t + 1` 整数提升安全形状不告警。
5. `MAX_KEY_PATH + 1` 这类宏值未知保持 unknown，不按宏值臆测溢出。

算术后果和溢出本身分开：CWE-190/191 是候选类别，分配不足或越界写是候选 consequence；不能把每个 `+`/`*` 都当漏洞。

## EvidenceObligations

每个候选保留：

- `capacity_and_alias_identity` / `integer_range_and_signedness`
- `guard_dominance` / `overflow_guard_dominance`
- `cross_function_and_macro_context`
- `entry_or_privilege_boundary`
- `attacker_control`
- `trigger_conditions` / `allocation_or_memory_consequence`
- `cia_impact`

这些义务当前为 `unknown` 或 `missing`。只有真实入口/权限边界、可达敏感操作、触发条件、具体 CIA 影响和可审计证据闭合后才允许 `confirmed/reportable`。

## Controls and regression

`tests/detectors/fixtures/cpp_memory_safety/manifest.json` 绑定 9 个自编 synthetic fixtures 的 SHA-256，覆盖 `positive`、`fixed`、`safe`、`unrelated`、`unknown` 五类。`tests/detectors/test_cpp_memory_safety_detectors.py` 固定：

- 正例产生候选；
- 修复/精确容量/checked arithmetic 为 quiet；
- 动态目的地和宏-only 分配为 unknown/quiet；
- partial、failed、1MiB/unit、32MiB/run fail-closed；
- 输出和 source binding 稳定；
- 已审阅误报形状（placement new、`strnlen` guard、窄整数提升）不再告警。

## Production Catalog

`src/ohscanner/detectors/catalog.py` 注册两个 Detector，普通扫描默认选择它们；Catalog 的 `kind` 为 `research_candidate`。版本和规则身份以实现文件及本次生产 CLI 输出为准。示例 Detector 永不作为漏洞能力启用。


## Historical replay

CVE-2025-0587 / `arkcompiler_ets_runtime-atomic-index-overflow-2025-03` 在 vulnerable `cae11f121c030a90ba41d8e4d866f91292f25892` 上得到 1 个 narrow-index candidate，在 fixed `5aa9c035e98911ec7ed28065a2138c2709792a42` 上为 0。`n`nCVE-2025-23420 / `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` 在 vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` 上得到 5 个 direct `ElementAccessor` candidates，在 fixed `1b23531531e768398682582969c2a9f17e72cafe` 上为 0。这个结果是 known historical capability hit，不是新漏洞或全局 Recall。`kernel_liteos_a` 的 concurrency/user-kernel cases 对当前 lexical bounds/integer rules 明确 `not_applicable`。
