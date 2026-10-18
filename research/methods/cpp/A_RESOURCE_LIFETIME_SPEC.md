# A-RES-01 C/C++ resource lifetime specification

更新：2026-10-18。`ohscanner.cpp.resource_lifetime` 0.1.1 是队友 A 的局部 Alloc/Acquire、Release、Alias、Null/Realloc 状态机研究 Detector。默认 `candidate/unassessed`。

## 触发

- `malloc/calloc/realloc/new` 后同一 lexical flow segment 内再次 `free/delete`：CWE-415 double-free candidate。
- 释放后直接 `*p`、`p->`、`p[i]` 或 `memcpy/memmove/memset(p, ...)`：CWE-416 use-after-free candidate。
- `p2=p` 的局部 alias 跟随同一资源状态。
- `p=nullptr` 或重新分配使旧状态失效。
- `delete[] p->member` / `delete p->member` 只释放成员，不把 owner `p` 标成已释放；这是 0.1.1 修复的已知误报形状。

## 排除和 unknown

- `if/else/loop/goto/label/return/break/continue` 之间的状态不拼接；跨分支/标签路径保持 unknown，避免把互斥释放误报为 double-free。
- 跨函数 ownership、容器、字段、回调、异常、析构时序、自定义 allocator、move/escape 均未建模。
- partial/failed source 和资源预算超限 fail-closed；无 finding 不是 safe。

## Controls

`tests/detectors/fixtures/cpp_resource_lifetime/manifest.json` 绑定 positive double-free、alias UAF、fixed null/realloc、safe member-release/early-return、unrelated 和 unknown controls。`tests/detectors/test_cpp_resource_lifetime_detector.py` 固定 source hash、identity、determinism、budget 和五类控制。

## PoC

`validation/cpp_memory_safety_poc/resource_double_free_vulnerable.cpp` 在 ASan 下触发 double-free，固定版本通过 `p=nullptr` guard 后 exit 0。该 PoC 验证状态机机制，不是 OpenHarmony 产品漏洞证明。

## EvidenceObligations

候选保留 allocation/release/alias state、control-flow dominance、cross-function/container transfer、entry/privilege boundary、attacker control、trigger 和 CIA impact 义务；未闭合前不得升级 confirmed/reportable。
