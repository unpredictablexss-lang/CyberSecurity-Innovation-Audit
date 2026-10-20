# D 线第 17 轮：D101/T100 内建 comma 结果与 effects

D101/T100 已在 owner 分支集成，版本0.21.16。窄范围类型证明可识别已证明的单TU内建逗号表达式：所有operand effects保留，表达式值只取最后operand；重载或类型身份不清时保留may-flow。T100发现的 Status 状态码caller过传播由2条降为1条（保留内部真实日志），未知Audit effects仍保留；重载、class同名、shadow/alias、macro和partial反控通过。

开发7项/data394，T100独立19项/data413/compat62，owner集成data413/413与compat62/62通过。T85仍24条诊断、638 calls、890/915不变，3个文件partial。T85不含comma语法，因此只算兼容回归。合法 `(out=key,0)` 未加额外语法括号时当前parser root ERROR/Runner blocked，这项记为D102任务，未宣称通过。

实现 `ecaa9b0c32df2fb1688027a1b0e2af67c79bf540`，证据 `b977bd56bae0c5fd4e375800e0dae7c68e9feffd`，独立T100 `29d8c84f243b55963e6d7431fa466ac52cb2d8f8`。用户设定进入收尾后再跑3至4轮；计划固定为D102/T101、D103/T102、D104/T103三轮，随后最终有界验证和closeout。
