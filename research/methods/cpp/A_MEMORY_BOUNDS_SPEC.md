# A-BOF-01 / A-INT-01 memory-safety detector specification

更新：2026-10-17。本文是队友 A 的研究规格和注册建议，不是公共 Catalog 变更。结果默认 `candidate/unassessed`，`validated_vulnerability=0`。

## Identity

| Detector | Version | Languages | Rules | Candidate CWE |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `0.2.8` | `c`, `cpp` | `ohcpp-memory-bounds-copy-candidate-001`, `ohcpp-memory-bounds-index-candidate-002`, `ohcpp-memory-bounds-element-access-candidate-003` | CWE-119/125/787 |
| `ohscanner.cpp.integer_bounds` | `0.2.1` | `c`, `cpp` | `ohcpp-integer-bounds-arithmetic-candidate-001`, `ohcpp-integer-bounds-truncation-candidate-002`, `ohcpp-integer-bounds-narrow-index-candidate-003` | CWE-190/191/681/680 |

实现入口：

- `src/ohscanner/detectors/cpp/memory_safety.py`
- `src/ohscanner/detectors/cpp/bounds_detector.py`
- `src/ohscanner/detectors/cpp/integer_bounds_detector.py`

源码绑定字段包括 `source_sha256`、`rule_version`、`rule_lineage_id` 和 `identity_quality=partial`。公共契约没有改变；Catalog 注册由公共负责人审查后另行提交。

## A-BOF-01 触发和排除

支持的局部形状：

1. 固定 C 数组或 `std::array<T,N>` 的 `memcpy`、`memmove`、`strncpy`、`snprintf`、`strcpy`、`strcat`。
2. 固定数组索引，包含常量越界和未证明上界的符号索引。
3. 识别 `if (n >= cap) return`、`if (n > cap) return`、`if (n < 0) return` 等单函数分支收窄。`SortElements*` 中未被 stable-array/index guard 保护的直接 `ElementAccessor::Get/Set` 作为历史 OOB 候选。
4. 识别简单的 `malloc/calloc/new[]` 指针目的地容量；复制长度与分配表达式相同时 quiet，确定超界或不同符号长度时产生候选；`new[]` 的已知元素容量也用于索引上界，动态/包装分配保持 unknown。
5. 识别一阶直接 copy wrapper：函数体内只有一个 `memcpy/memmove/strncpy/strcpy/strcat/sprintf`，目的地为函数参数；调用点代入调用者数组/分配容量。更深 wrapper、函数指针和重载保持 unknown。
6. `snprintf` 使用第 1 个实参作为字节上限；`snprintf(dst, sizeof(dst), ...)` quiet，`snprintf(dst, 8, ...)` 对 4 字节数组产生候选。
7. `<= 0`、`< 0`、`>= MAX`、`> MAX` 和 `nullptr` 早退 guard 收窄区间；例如 `if (n <= 0) return; if (n > 4) return; dst[n-1]` 保持 quiet。`if (x != 0) return;` 只生产 `GuardFact.kind=zero_check`（区间 `[0,0]`），不注入 bounds 区间推断：`dst[n - 1]` 在 `n==0` 时仍是越界/回绕，必须保留候选。
8. 简单计数循环 `for (init; i < N; ++i)` / `i <= N` 为循环体内的索引和复制长度提供 `[init, N-1]` / `[init, N]` 区间；只接受编译期常量或具名常量上界，`break`/`continue`、非常量步长和循环内改写仍是 unknown。`for (size_t i = 0; ...)` 不再被误记为常量 `i=0`。
9. `memcpy_s/memmove_s(dst, dstsz, src, count)`：分别检查 `dstsz` 与 `count` 对目的地容量的上界；WiFi Parcel 的 `new char[cfgLen] + memcpy_s(..., cfgLen, ..., cfgLen)` 保持 quiet。
10. `strcpy_s/strcat_s/strncpy_s/sprintf_s/snprintf_s` 检查 destination size；`strncpy_s/snprintf_s` 额外检查 count。

候选只在目的地容量可归属、常量越界或复制/索引上界未证明时产生。`sizeof(destination)` 精确容量、完整上界守卫、动态目的地、宏/别名未知和 `partial/failed/not_run` 不产生强结论。字节/元素单位、指针别名、包装函数、跨函数参数、模板和完整 CFG dominance 仍是 unknown。

## A-INT-01 触发和排除

支持的局部形状：

1. `size * count`、`offset + len`、`len - header` 等算术进入 `malloc/calloc/new[]`、copy length 或后续敏感 size 变量。
2. `uint8_t x = 255 + 1` 等常量结果超出目标类型范围的截断候选；`int32_t index = DoubleInRangeInt32(...)` 后再做 bounds check/offset multiply 的 narrowing-index 候选。
3. `__builtin_*overflow`、`SIZE_MAX /`、明确 checked arithmetic guard 作为安全对照。
4. `strnlen` + `if (len >= MAX) return` 的窄安全形状和 `uint8_t/uint16_t + 1` 整数提升安全形状不告警。
5. `MAX_KEY_PATH + 1` 这类宏值未知保持 unknown，不按宏值臆测溢出。
6. `calloc(count, size)` 与 `new T[count]` 的隐式 `count * element_size` 乘法；元素大小为 1、常量乘法或 checked arithmetic guard 为 quiet。

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

`tests/detectors/fixtures/cpp_memory_safety/manifest.json` 绑定 32 个自编 synthetic fixtures 的 SHA-256，覆盖 `positive`、`fixed`、`safe`、`unrelated`、`unknown` 五类；另有 `bounds_malloc_symbolic.cpp` 覆盖符号容量 unknown。`tests/detectors/test_cpp_memory_safety_detectors.py` 固定：

- 正例产生候选；
- 修复/精确容量/checked arithmetic 为 quiet；
- `malloc` 已知容量、`malloc(n)` 与 `memcpy(..., n)` 的精确匹配为 quiet；不同符号长度产生 unknown candidate；
- `new char[4]` 的越界索引产生候选，`new char[8]` 的最后一个合法索引 quiet；
- 一阶 `CopyInto(dst, src, n)` wrapper 的 4→8 越界调用产生候选，8→8 和 `sizeof(dst)` 调用 quiet；
- `snprintf` 的 8→4 长度产生候选，`sizeof(dst)` 安全控制 quiet；
- 动态目的地和宏-only 分配为 unknown/quiet；
- partial、failed、1MiB/unit、32MiB/run fail-closed；
- 输出和 source binding 稳定；
- 已审阅误报形状（placement new、`strnlen` guard、窄整数提升）不再告警。

## Catalog registration suggestion

建议公共负责人在独立兼容性提交中注册：

```python
"ohscanner.cpp.bounds": {
    "factory": M2BoundsDetector,
    "kind": "research_candidate",
    "summary": "A: bounded local array/copy length candidates; no exploitability proof",
},
"ohscanner.cpp.integer_bounds": {
    "factory": M2IntegerBoundsDetector,
    "kind": "research_candidate",
    "summary": "A: bounded size arithmetic and truncation candidates; no product impact proof",
},
```

未注册前不改变当前生产 Catalog；研究脚本直接调用 Detector。示例 Detector 永不作为漏洞能力启用。


## Historical replay

CVE-2025-0587 / `arkcompiler_ets_runtime-atomic-index-overflow-2025-03` 在 vulnerable `cae11f121c030a90ba41d8e4d866f91292f25892` 上得到 1 个 narrow-index candidate，在 fixed `5aa9c035e98911ec7ed28065a2138c2709792a42` 上为 0。`n`nCVE-2025-23420 / `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` 在 vulnerable `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` 上得到 5 个 direct `ElementAccessor` candidates，在 fixed `1b23531531e768398682582969c2a9f17e72cafe` 上为 0。这个结果是 known historical capability hit，不是新漏洞或全局 Recall。`kernel_liteos_a` 的 concurrency/user-kernel cases 对当前 lexical bounds/integer rules 明确 `not_applicable`。

## Real-source scan (2026-10-18)

`ohscanner.cpp.bounds` 0.2.1 was scanned over the same five pinned components as
the 2026-10-17 baseline. The result remains 33 candidates / 22 lexical groups;
no new real-source candidate was emitted by the added heap-capacity fact on
this corpus. This is a coverage regression check, not an accuracy claim.

- Scope: 4,983 files / 51,551,827 bytes.
- Environment: WSL, Python 3.10.12, light-ast, no build profile.
- Wall: 170.94s; peak RSS: 371,736 KiB. The runner was executed from the
  existing mainline script with `PYTHONPATH` pointing at this branch; no shared
  script was modified.
- Evidence: `research/evidence/cpp/a_line_scan_20261018/summary.json`.

The follow-up `new[]` index-capacity rerun is compared in
`research/evidence/cpp/a_line_scan_20261018_v2_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

The `integer_bounds` 0.2.1 rerun is compared in
`research/evidence/cpp/a_line_scan_20261018_v3_comparison.json`: candidates and
groups also remain 33/22, with no new real-source hit in this corpus.

The one-hop wrapper rerun with `bounds` 0.2.2 is compared in
`research/evidence/cpp/a_line_scan_20261018_v5_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

The `snprintf` 0.2.3 rerun is compared in
`research/evidence/cpp/a_line_scan_20261018_v7_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

The `<=0`/offset guard normalization with `bounds` 0.2.4 is compared in
`research/evidence/cpp/a_line_scan_20261018_v8_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

The `memcpy_s/memmove_s` 0.2.5 rerun is compared in
`research/evidence/cpp/a_line_scan_20261018_v9_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

The secure string-copy extension with `bounds` 0.2.6 (`strcpy_s`, `strcat_s`,
`strncpy_s`, `sprintf_s`, `snprintf_s`, in addition to `memcpy_s/memmove_s`) is
compared in `research/evidence/cpp/a_line_scan_20261018_v11_comparison.json`:
candidates and groups remain 33/22 and every component keeps its baseline count
(7/4, 11/8, 4/2, 7/6, 4/2). Wall time was 163.19s with 372,036 KiB peak RSS.
The absence of new hits is a coverage result for this corpus, not evidence that
the new rules are accurate or complete.

The inclusive `>=` guard and the non-injected `zero_check` fact with `bounds`
0.2.7 are compared in
`research/evidence/cpp/a_line_scan_20261018_v13_comparison.json`: candidates and
groups remain 33/22 with every component unchanged. Wall time was 166.90s with
371,860 KiB peak RSS. The added guard facts change no candidate on this corpus;
they add explicit controls for `>= MAX`, zero-exit and null-check shapes, not
new conclusions.

The simple counting-loop bounds with `bounds` 0.2.8 are compared in
`research/evidence/cpp/a_line_scan_20261018_v14_comparison.json`: candidates and
groups remain 33/22 with every component unchanged. Wall time was 166.28s with
372,332 KiB peak RSS. The sandbox copy-range replay
(`research/evidence/cpp/sandbox_controls_20261018/summary.json`) is the targeted
check: the Parcel-derived model and safe control stay quiet, the deliberately
unsafe control reports one index candidate.
