# 限制与证据边界

1. 三个规则均为 bounded local syntax/dataflow shape，不证明完整 C++ 类型、宏展开、CFG、别名、跨函数 summary、并发、ownership、真实入口或攻击者控制。
2. 所有命中保持 `candidate/unassessed`。没有产品构建绑定、权限边界、触发条件、具体 CIA 影响、隔离动态 PoC 或修复产品重验，不升级 confirmed/reportable。
3. I7W51D 的 `uint32_t`/RangeError 修复控制只证明同根因静态候选消失，不证明内存安全或产品安全。
4. IB8BCA 的 fixed 输入仍产生显式 `index_width_bounds_arithmetic_not_fully_proven` / unknown；0 findings 不写 safe。
5. safe 控制只是局部规则边界，不是安全 verdict；unrelated 是 not_analyzed；unknown/partial/blocked 不计通过。
6. Ark discover 的 3 个 skip 需要 pinned historical Ark Git stores，未计通过。没有独立可靠标注集，不计算 Precision/Recall，不声称零 FP/FN。
7. Windows Git 子进程 stdout 存在流哈希与 resolved Git blob OID 分离现象；生产适配器以共享事实中的 verified Git OID 加源 SHA-256 绑定，不把流哈希当 blob identity。
