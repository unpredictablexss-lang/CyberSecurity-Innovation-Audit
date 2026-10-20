# D 线第 14 轮：D98/T97 all-return switch 可达性

D98/T97 在 owner 分支集成。规则0.21.13 仅在完整无预处理输入、case 标签唯一且为规范数字、存在一个 default、每个 arm 都直接裸 `return` 时，证明 switch 后续语句不可达，避免该路径上的敏感写入/日志误候选。

开发侧7个方法的5个基线子断言失败归零；独立T97 16项的3个基线失败归零。最终负责人重跑 data335/335 与兼容性62/62通过。T85 direct/Runner均24条，24条共同ID/message/evidence、638个调用事实和890/915不变，3文件仍analysis-partial。T97确认 goto/label 绕过、混合退出、partial输入等可达流仍保留。分组fallthrough标签和 return-expression arms 尚未支持，继续标为 known gap。

实现 `b3dfd70894290c344017c33198b905c70eb51985`，D98证据 `5b1a4ca513d662a02eb2987888b22d8445adf85a`，独立T97 `dc963d80a2e8858586769aa284e763f062a146b7`。接续D99/T98评估分组case标签和return表达式能否安全纳入同一有限证明。
