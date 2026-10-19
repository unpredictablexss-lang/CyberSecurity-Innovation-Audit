# A-RES-01 C/C++ resource lifetime specification

更新：2026-10-19。`ohscanner.cpp.resource_lifetime` 0.2.0 是队友 A 的局部 Alloc/Acquire、Release、Alias、Null/Realloc 状态机研究 Detector，并增加 0.2.0 的 CWE-674 registered-callback recursive-cleanup 候选规则。默认 `candidate/unassessed`。

## 触发

- `malloc/calloc/realloc/new` 后同一 lexical flow segment 内再次 `free/delete`：CWE-415 double-free candidate。
- 释放后直接 `*p`、`p->`、`p[i]` 或 `memcpy/memmove/memset(p, ...)`：CWE-416 use-after-free candidate。
- `p2=p` 的局部 alias 跟随同一资源状态。
- `p=nullptr` 或重新分配使旧状态失效。
- A-RES-01 规则 `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`：同一 translation unit 内，函数指针成员已绑定到本地实现、调用点回到资源释放器，且迭代子对象清理链可再次触发该回调时，提出 CWE-674 候选。能看到回调解绑或简单显式深度上限时抑制候选。

## 排除和 unknown

- `if/else/loop/goto/label/return/break/continue` 之间的状态不拼接；跨分支/标签路径保持 unknown，避免把互斥释放误报为 double-free。
- 通用跨函数 ownership、容器/字段别名、异常、析构时序、自定义 allocator、move/escape 均未建模。
- callback-cycle 只做同文件 may-call 扩展；同名字段可能属于不同结构体，回调实参、字段别名、条件可行性、真正深度上限与调用入口均未解析。候选不证明递归可达或攻击者控制；复杂的边界保护也可能令静态过滤不准确。
- partial/failed source 和资源预算超限 fail-closed；无 finding 不是 safe。

## Controls

`tests/detectors/fixtures/cpp_resource_lifetime/manifest.json` 绑定 positive double-free、alias UAF、fixed null/realloc、unrelated 和 unknown controls。`tests/detectors/test_cpp_resource_lifetime_detector.py` 固定 source hash、identity、determinism、budget 和四类控制。

## PoC

`validation/cpp_memory_safety_poc/resource_double_free_vulnerable.cpp` 在 ASan 下触发 double-free，固定版本通过 `p=nullptr` guard 后 exit 0。该 PoC 验证状态机机制，不是 OpenHarmony 产品漏洞证明。

## EvidenceObligations

候选保留 allocation/release/alias state、control-flow dominance、cross-function/container transfer、entry/privilege boundary、attacker control、trigger 和 CIA impact 义务；未闭合前不得升级 confirmed/reportable。
