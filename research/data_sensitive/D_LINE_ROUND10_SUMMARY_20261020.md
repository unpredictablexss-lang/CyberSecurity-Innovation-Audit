# D94/T93 完成报告（2026-10-20）

D94/T93 已在负责人分支集成。D94 将敏感材料的 raw pointer value 与实际 pointee/member 写槽分开：可证明的本地及成员目标把材料传播到真实 consumer；目标未知时保留 `destination_binding` unresolved write candidate；literal-only 标量metadata不产生材料来源。C++ pointer cast 只传播 operand，类型名本身不产生来源。caller 输入指针或 callee 局部指针重绑定不再冒充调用方输出写入。

开发实现序列为 `5d33abf99857584a7194cb466590592e397e9339`、`d421c27a1a3da9254905ed6d8f4b8e2696978418`、`fe8080e4cd48a53422f4647981b3871575a31f01`，最终版本0.21.9；开发证据 `1cdbe45445930f27437e5e90e8b08cd60d212cdb`。T93独立测试提交 `7fe1c0bf8760277707b5a111a7284bbcf3f2733c`。负责人集成提交分别为 `32e41afa3`、`df58126df`、`abefb4cff`、`1b2d4d7a9`、`5b80f6e55`。

固定T85证书三文件direct/Runner从26变为24。最终24条共同诊断身份、消息和证据不变；638个调用位置不变；第890行长度查询与第915行字节提取继续保留；coverage仍是3个detector partial。移除的1880/1882两条trace源自第1878行按值传入的 `options.privateKey`：旧summary错误地把未变化的输入指针当作callee writeback，回灌aggregate并污染其他字段或对象地址。T93逐行核对了1880的 `encryptedContentData` 是不同成员、1882是 `options` 地址；可见清理体没有把输入写入这些位置。实际私钥清理候选仍在，第317/328/364/381/384/386/388等剩余项未被当作安全清理豁免。初版D94把 `static_cast<PrivateKeyInfo *>(nullptr)` 误当来源，第358行因此先从26变27；T93反馈后修为cast只传播operand，最终测试不再产生该假来源。

验证通过：负责人data252/252、AST/parser/linkage/known/corpus 66/66；开发控制10/10、data239/239、compatibility62/62；T93独立控制13/13、data252/252。额外具名输入输出对照：只读与局部重绑定不污染caller；实际 `memcpy` 输出仍到达caller buffer log。上述都是固定源码和控制结果，不是准确率、运行时安全或产品影响结论；复杂别名与其余partial边界继续unknown。

权威任务树与后续队列见 [D_LINE_TASK_TREE](D_LINE_TASK_TREE_20261020.json) 和 [并行计划](D_LINE_PARALLEL_PLAN_20261020.md)。
