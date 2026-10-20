# D 线第 15 轮：D99/T98 分组标签与返回值流

D99/T98 在 owner 分支集成。规则0.21.14有限识别连续分组 case 标签和受支持的 return 表达式终止形态；return expression 中原有数据流 effects 仍执行，helper 返回的材料继续流向 caller sink。测试反馈中的 Select helper 材料返回漏报由 direct/Runner 0→1 候选闭环；未知Consume逃逸和return表达式内部真实日志候选保持。

开发侧8项、基线5个子断言失败归零，data343/343；独立T98 20项、基线7项失败归零，data363/363、兼容性62/62。负责人集成后 data363/363、兼容性62/62。固定 T85 direct/Runner仍24条，24共同finding ID/message/evidence、638 call facts、890/915不变，三文件partial状态不变。T85这三文件不含switch代码，故只作为兼容回归，不宣称新语法已有真实源码覆盖。

实现 `f9296a695907845e6bd32598892ff036d4ac62d1`，D99证据 `71a054eb031999751291c023c6f300141acbcacc`，独立T98 `687b0540610e56100a5d630089ef6d8e63208e84`。D100/T99已启动，聚焦switch arm中单层if/else两支均return的终止证明；缺else或存在live path继续保守。
