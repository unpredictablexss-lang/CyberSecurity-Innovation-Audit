# A-RES-01 C/C++ resource lifetime specification

更新：2026-10-19。`ohscanner.cpp.resource_lifetime` 0.3.0 是局部 Alloc/Acquire、Release、Alias、Null/Realloc 状态机研究 Detector，并包含三类 CWE-674 resource exhaustion 候选：registered-callback recursive cleanup、patch-driven tree amplification 和 recursive compare cost。默认 `candidate/unassessed`。默认 `candidate/unassessed`。

## 触发

- `malloc/calloc/realloc/new` 后同一 lexical flow segment 内再次 `free/delete`：CWE-415 double-free candidate。
- 释放后直接 `*p`、`p->`、`p[i]` 或 `memcpy/memmove/memset(p, ...)`：CWE-416 use-after-free candidate。
- `p2=p` 的局部 alias 跟随同一资源状态。
- `p=nullptr` 或重新分配使旧状态失效。
- A-RES-01 规则 `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`：同一 translation unit 内，函数指针成员已绑定到本地实现、调用点回到资源释放器，且迭代子对象清理链可再次触发该回调时，提出 CWE-674 候选。能看到回调解绑或简单显式深度上限时抑制候选。

- 规则 `ohcpp-resource-exhaustion-tree-amplification-candidate-004` 要求跨选定源码绑定递归子树释放、完整源码中深拷贝后附加到树、以及迭代输入循环调用对应 mutator；候选保留 partial identity，不证明实际树增长或调用输入可控。
- 规则 `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` 要求同一函数递归比较、两个方向的兄弟遍历及每项查找；只保留 bounded local shape，partial TU 命中会保留但整个运行仍 blocked。

## 排除和 unknown

- `if/else/loop/goto/label/return/break/continue` 之间的状态不拼接；跨分支/标签路径保持 unknown，避免把互斥释放误报为 double-free。
- 通用跨函数 ownership、容器/字段别名、异常、析构时序、自定义 allocator、move/escape 均未建模。
- callback-cycle 只做同文件 may-call 扩展；同名字段可能属于不同结构体，回调实参、字段别名、条件可行性、真正深度上限与调用入口均未解析。候选不证明递归可达或攻击者控制；复杂的边界保护也可能令静态过滤不准确。
- partial/failed source 和资源预算超限 fail-closed；无 finding 不是 safe。

## Controls

`tests/detectors/fixtures/cpp_resource_lifetime/manifest.json` 绑定 positive double-free、alias UAF、fixed null/realloc、unrelated 和 unknown controls。`tests/detectors/test_cpp_resource_lifetime_detector.py` 固定 source hash、identity、determinism、budget 和四类控制及 D3 的 compare/tree amplification positive 与 safe/unrelated controls。

## PoC

`validation/cpp_memory_safety_poc/resource_double_free_vulnerable.cpp` 在 ASan 下触发 double-free，固定版本通过 `p=nullptr` guard 后 exit 0。该 PoC 验证状态机机制，不是 OpenHarmony 产品漏洞证明。

## EvidenceObligations

候选保留 allocation/release/alias state、control-flow dominance、cross-function/container transfer、entry/privilege boundary、attacker control、trigger 和 CIA impact 义务；未闭合前不得升级 confirmed/reportable。

## D34 interprocedural lifecycle assessment (2026-10-24)

Current `resource_lifetime` 0.4.2 was replayed on the exact libpng CVE-2026-46675 vulnerable/fixed source pair. Both production CLI runs are blocked/partial with zero findings; each seven-function replay has six complete fragments, the partial `png_handle_iCCP` fragment, and zero findings. This is inconclusive, not a fixed/safe pass. Pinned-source review sees the shared `png_struct` zstream fields, chunk release, conditional IDAT refill and `png_read_end` drain sequence, but the current parser does not provide resolved parameter/type identity, call-site enclosing function, field SSA/alias state, or cross-function path/order facts. Do not add a name-based special case or claim this relation as statically proven. Keep the case PARTIAL/BLOCK and require a bounded, reviewed interprocedural resource-state model with parse/context unknowns and independent positive/fixed/safe/unrelated/renamed/partial controls before extending this mechanism. Full source identities, commands, parser assessment and replay verifier: [D34 assessment](../../evidence/cpp/d34_libpng46675_model_assessment_20261024.md).
