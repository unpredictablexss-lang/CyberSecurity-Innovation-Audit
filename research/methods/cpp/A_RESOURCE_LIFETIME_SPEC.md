# A-RES-01 C/C++ resource lifetime specification

更新：2026-10-18。`ohscanner.cpp.resource_lifetime` 0.1.3 是队友 A 的局部 Alloc/Acquire、Release、Alias、Null/Realloc 状态机研究 Detector。默认 `candidate/unassessed`。

## 触发

- `malloc/calloc/realloc/new` 后同一 lexical flow segment 内再次 `free/delete`：CWE-415 double-free candidate。
- 释放后直接 `*p`、`p->`、`p[i]` 或 `memcpy/memmove/memset(p, ...)`：CWE-416 use-after-free candidate。
- `p2=p` 的局部 alias 跟随同一资源状态。
- `p=nullptr` 或重新分配使旧状态失效。
- `delete[] p->member` / `delete p->member` 只释放成员，不把 owner `p` 标成已释放；这是 0.1.1 修复的已知误报形状，0.1.2 保留。
- 有界 `if` 分支内释放 `p` 且该分支继续落入主路径时，后续 `free/delete` 或 `*p`/`p->`/`p[...]` 产生 conditional double-free/UAF candidate；分支内提前 `return/break/continue/goto` 或释放后置空/重绑定时不产生。
- 一阶 release wrapper：函数体只有一个无条件 `free/delete` 且目标是按值参数时，把调用点当作 release；`Release(p); Release(p);` 和 `Release(p); p[...]` 产生候选。带 `if`/循环/提前返回或引用参数的 wrapper 保持 unknown。

## 排除和 unknown

- `if/else/loop/goto/label/return/break/continue` 之间的状态不拼接；跨分支/标签路径保持 unknown，避免把互斥释放误报为 double-free。
- 跨函数 ownership、容器、字段、回调、异常、析构时序、自定义 allocator、move/escape 均未建模。
- partial/failed source 和资源预算超限 fail-closed；无 finding 不是 safe。

## Controls

`tests/detectors/fixtures/cpp_resource_lifetime/manifest.json` 绑定 positive double-free、alias UAF、conditional double-free/UAF、fixed null/realloc、safe member-release/early-return/conditional-null、unrelated 和 unknown controls。`tests/detectors/test_cpp_resource_lifetime_detector.py` 固定 source hash、identity、determinism、budget 和五类控制。

The same five-component fixed corpus was replayed with 0.1.2: candidate and
group totals remain 33/22, with no additional real-source hit. The comparison
is `research/evidence/cpp/a_line_scan_20261018_v4_comparison.json`.

The one-hop release-wrapper 0.1.3 rerun is compared in
`research/evidence/cpp/a_line_scan_20261018_v10_comparison.json`: candidates and
groups remain 33/22, with no new real-source hit in this corpus.

## PoC

`validation/cpp_memory_safety_poc/resource_double_free_vulnerable.cpp` 在 ASan 下触发 double-free，固定版本通过 `p=nullptr` guard 后 exit 0。该 PoC 验证状态机机制，不是 OpenHarmony 产品漏洞证明。

## EvidenceObligations

候选保留 allocation/release/alias state、control-flow dominance、cross-function/container transfer、entry/privilege boundary、attacker control、trigger 和 CIA impact 义务；未闭合前不得升级 confirmed/reportable。
