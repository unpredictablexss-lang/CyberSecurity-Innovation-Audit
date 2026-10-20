# D线第5轮：D89/T88 闭环与 D90/T89 启动（2026-10-20）

D89/T88 已完成并集成。D89 仅在常量身份、同函数的 NAPI property-key 角色、可见且未被调用方改写的完整日志宏链以及确切格式参数角色均成立时，排除日志中的 schema 属性名候选。T88 曾发现 `__FUNCTION__` 覆盖可把隐式公开前缀转成密码值，D89 已修复为拒绝该安全证明；实际 `__FILE__`、`__FUNCTION__`、`__LINE__` 覆盖控制均保留候选。

固定 T85 的三个源码文件和原始身份不变。独立证据与负责人复放一致：direct 和 Runner 均由20个诊断变为19个，只移除 `napi_cert_utils.cpp:349`；其余19个 diagnostic ID/message逐项相同，638个调用位置、三文件partial覆盖状态不变。负责人验证T88独立测试13/13、data suite 157/157通过，并以独立replayer再次复现20→19。该变化只说明这组来源/控制中的候选行为，不代表正式准确率、产品漏洞或日志实际可达性。

T88 从剩余19条里选出的下一组问题是释放/擦除调用导致的 unresolved-escape：`CfFree`、`CF_FREE_PTR`、`CfBlobDataFree`、`memset_s`，集中在 `FreePrivateKeyInfo` 与 CMS cleanup 路径。D90/T89 已并行启动。D90 首次核实这些精确实现位于原 T85 三文件以外，当前头文件解析也有 partial 边界；因此需要分别报告原范围的 unknown 保留结果，以及附加精确源定义时的控制结果。不得仅凭函数名排除，必须挑战同名泄漏包装、宏覆盖、未知声明和混合数据参数。

任务树与结构化 D90/T89 提示词见 `D_LINE_TASK_TREE_20261020.json` 和 `D_LINE_PARALLEL_PLAN_20261020.md`。本轮提交含 D89 实现/证据、T88独立验证/报告及负责人任务树更新；尚未推送。
