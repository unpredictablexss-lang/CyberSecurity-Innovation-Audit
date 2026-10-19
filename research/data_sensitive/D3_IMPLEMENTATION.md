# D3 实现与不支持范围

默认检测器/模型继续为 0.2.0 / 0.1.0；独立 HistoricalSensitiveExposureDetector 为 0.3.0，历史模型 0.2.0-historical.1。显式 historical_model(full_commit) 选择两个受审提交，其他提交拒绝；不注册 Catalog。

历史 profile 固定每端 10 个文件的 commit/tree/blob/SHA 与原始定义行号。执行前检查 ScanContext 中全部依赖文件的字节 SHA，缺失或不匹配即 blocked。公共 Git 加载器负责固定 Git 对象身份，直接研究探针则由实验脚本先核对同一清单。

新增 HistoricalLocalFlow 在原局部引擎之上，只支持一个已核验的一跳摘要：唯一、无直接语法错误的 DecryptMessage 第 2 个参数指向 MsgCryptInfo.out。依据是同版本函数把 outbuf.buf 指向该字段，调用 AuthDecrypt 并在成功后返回；不是自动构建调用图。

先观察 SoftBusCalloc 分配、局部非空检查，再在 DecryptMessage 与 SOFTBUS_OK 比较的成功边上引入条件材料流。失败边不引入材料，未检查状态、未确认分配、复杂别名或缺少摘要时不给这条来源。分支合并时分配/非空属于 must 信息，不能把某一分支成立当作所有分支成立。直接成员覆盖清除材料；内层同名声明与成员状态离开作用域后恢复。

旧 SoftBusLog 的格式下标是 2（从 0 开始），普通 %s 先经 secure-C 格式化，再被适配器以 public HiLog / printf 输出。它与默认 HiLog 的私有格式不同。未经核验的 %{public/private} 旧接口格式不套用隐私模型；历史模式下复制/格式化输出状态尚未建模，保留缺口而不无条件认定写成功。

默认引擎只新增 make_flow 扩展点及可选格式默认隐私参数；原模型语义、旧 71 控制不变。历史流限制在受审目标文件和 ProcessReceivedData。输出仍为 syntax 候选，附历史模型、请求内容、日志适配器和运行可见性义务，不记录秘密原值。

限制：may-flow 不证明请求种类、路径可行性、字符终止/日志长度成功、未知调用副作用、别名生命周期或编译器符号身份。所有依赖校验也不等于构建系统实际选择了这些实现。普通 Runner 仍拒绝目标 partial 文件；独立探针只作研究，不覆写覆盖等级。

代码/模型/测试按三次独立提交组织，实际哈希见 D3_FREEZE.json。24 个新增设计控制验证成功/失败、初始化、遮蔽、格式及版本边界；它们不是 holdout。
