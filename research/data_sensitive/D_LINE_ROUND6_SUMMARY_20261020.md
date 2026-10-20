# D线第6轮：D90/T89 闭环与 D91/T90 启动（2026-10-20）

D90/T89 的研究没有把释放函数名当成安全证明。T85 原三文件里看不到 `CfFree`/blob 实现；加入 memory/blob 源码后，两个关键头文件仍因真实 split extern C 声明而 partial。即便精确同文件看到 `CfFree` 最终调用 `free`，NULL/free 宏和 using 名称导入仍可能改写语义，故本轮不排除 cleanup 候选。

T89 在 D89 0.21.6 基线上独立找到既有漏报：敏感参数被同名函数指针或局部 callable alias 调用时，detector 遇到 shadow 后直接返回。D90 现在对敏感实参发出 unresolved escape，而不借用同名 API 规则；普通字面量/null不造候选，后续实际日志输出继续保留。两个 shadow 控制在 direct 和 Runner 从0恢复到1。实现 0.21.7；开发六项、完整数据163项、兼容61项通过。T89独立14项与其数据177项通过。

固定 T85 源码重放前后：原三文件 direct/Runner 均19且不变；添加四个memory/blob定义形成七文件时 direct20、Runner18且不变，其中两个头文件partial。差异来自扫描覆盖/Runner eligibility，不可合并成原范围改进。源字节和AST调用位置不变；diagnostic IDs/messages不变，但嵌套 observation detector_version 随版本0.21.6→0.21.7变化，稳定finding/occurrence identity仍unknown。完整重放已由负责人重新执行。

下一轮 D91/T90 根据 T88/T89 剩余 trace 中 `napi_cert_utils.cpp:185 napi_typeof` unresolved sink启动。目标是核对固定版本 API 的类型元数据与状态角色；相邻第192/208行 `napi_get_value_string_utf8` 是实际材料提取，必须继续候选。同名/宏/未知/partial输入不得仅凭API拼写获豁免。结构化提示词、任务状态与持续目标见并行计划、任务树及 sustained-goals 文件。

本轮集成提交包括 D90 实现和开发证据、T89独立测试/报告/重放、D90/T89闭环记录。提交只在本地owner分支；未推送。
