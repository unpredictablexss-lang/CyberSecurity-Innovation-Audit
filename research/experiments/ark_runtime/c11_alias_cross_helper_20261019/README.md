# C11 Alias / Cast / Cross-Helper / Loop Backedge Slice

日期：2026-10-19（Asia/Shanghai）。
基线：`ab30df6a01797af455d2abbbc9533ab15964ee68`；工作树 HEAD 与基线相同，未执行 fetch/checkout/commit/push/merge/reset。
Detector：`ohscanner.ark.runtime.type_safety` v0.6.2。语义规则版本提升到 v1.1.0，公共 contracts/Runner/Catalog 未修改。

## 最小语义切片

1. `cross_helper.py` 只摘要“完整函数体仅 `return same_typed_parameter;`”的 identity helper；返回 cast、副作用、多语句、重载歧义和类型变化均不展开。
2. `type_origin.py` 将局部 alias、C/C++ cast、精确 identity helper 保持为同一 source identity；循环内重绑定标记 `may_differ/loop_backedge_rebinding`，不得据此证明类型相等。
3. `runtime_exception.py` 仅穿透精确 identity wrapper 找回 callback effect；effectful/未知 wrapper 和 loop backedge 继续 partial/unknown，绝不转 safe。
4. `exception_guard.py` / `receiver_guard.py` 通过 alias/cast/identity helper 解析同一 binding；只过滤已证明无副作用的 identity helper 调用，未知调用仍使路径 fail-closed。
5. `size_overflow.py` 显式解析局部 alias root、cast width 和 loop alias；I7W51D/IB8BCA 的长度/索引规则保留 alias root，未知转换仍产生 limitation/unknown。

## 机制控制

`control-matrix.json` 含 alias/cast/helper/loop 各 positive/fixed/safe/unrelated/unknown，共 20 项，`all_assertions_pass=true`。
positive 只产生 `candidate/unassessed`；fixed/safe 只证明局部规则边界；unrelated 不产生同根因 candidate；unknown 显式保留。

## 九个已知案例

`known-case-matrix.json` 覆盖 CVE-2025-24304、IBS5YG、I7KZJ7、IC7B8Q、I7E0FM、IAO7GO、I7W51D、IB8BCA、IAO7E8。
父侧均为 source-bound candidate；fixed 侧均无同根因 candidate。IB8BCA fixed 仍显式 unknown（`index_width_bounds_arithmetic_not_fully_proven`），未写 safe。
这些是本地 source-bound 控制/最小语义切片响应，不是产品漏洞确认、完整 TU 安全或 Precision/Recall 证据。

## 实际验证

- focused C11：3 tests，OK。
- focused known cases：24 tests，OK。
- Ark full：173 tests，OK，3 historical skip。
- `compileall`：exit 0。
- Windows `git diff --check`：exit 0。
精确命令、stdout/stderr、exit code 在 `logs-final/`，机器可读汇总在 `test-results.json`。

## 证据身份

`source-hashes.json` 记录 baseline commit/tree、工作 HEAD/tree、每个源文件的 SHA-256 与 Git blob OID、Detector/rule version、scope 和 profile。
分析输出仍默认 candidate/unassessed；没有使用外部扫描器、历史 verdict、名称相似性或模型自评。
