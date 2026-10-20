# 残余限制

1. 17 个公开 CVE 只是已披露案例回归集，不是独立盲标注 holdout，不能据此计算或宣称 Precision/Recall、零 FP/FN。
2. 当前规则是有限源码形状签名。命中不证明 ownership、调用可达、攻击者控制、并发竞争或 CIA 影响；全部保持 `candidate/unassessed`。
3. CVE-2026-58313 的 LRU mutex 只是保护迹象，审查原文没有把公告根因精确绑定到该 LRU 实现。
4. CVE-2026-33636 主 libpng 补丁清单有迹象，但 Flutter/libpng 最终 pin 与产品构建仍未建立。
5. CVE-2026-92392 对审查到的 curl 8.8.0 按版本为 not-affected；该结论不能套用到其他构建。冲突或缺失版本保持 unknown。
6. CVE-2026-9079 只有局部清理逻辑对应，当前状态仍是 unknown/疑似 fixed，不能按版本号直接报漏洞。
7. fixed/safe/unrelated 控制的 0 findings 只证明局部规则行为，不是组件或产品安全结论。
8. 测试执行使用固定 `db77164fdc2af0da02e4d3efc056d84694fd68e8` Git blob 字节。工作树 CRLF 仅记录 worktree SHA-256 与 normalized SHA-256；由于 `.gitattributes` 未明确把这些 C/C++ fixture 声明为规范化文本，测试没有用工作树规范化字节替代 Git blob。
9. 未执行产品构建、动态 PoC、入口/权限链、攻击者控制、影响或修复重验。
