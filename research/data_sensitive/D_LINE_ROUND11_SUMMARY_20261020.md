# D 线第 11 轮：D95/T94 指针循环作用域

本轮在 owner 分支集成 D95/T94。D95 修复了 `for (unsigned *p = &inner; flag;) { break; }` 离开循环后没有恢复外层 `p = &outer` 的作用域状态问题；循环后的 `*p = secret` 因而重新绑定外层目标。改动保持有界，不引入通用别名分析。

T94 独立覆盖 11 个路径/作用域控制，发现上述循环头 shadow 缺陷并在修订版确认关闭。owner 集成验证 data 269/269、AST/parser/linkage/known/corpus 66/66。固定 T85 direct/Runner 仍为 24 条，24 条共同证据和 638 个调用事实不变，890/915 保留，3 个 detector 仍为 partial。覆盖比较中的变化仅是嵌套 source-binding obligation 记录了 0.21.9→0.21.10 版本更新，不代表分析覆盖状态变化。

实现版本 0.21.10。D95 实现 `c4605710ac517ca5b61f48fef03b31860fb88966`，T94 独立测试 `15532397ce53bdec57cbb66accc2976110d25cf9`；owner 集成 HEAD `9c298fefe`。远端此前最后确认 HEAD 为 `9b0e67c1d9610a31077682c37db6e55bf148f567`，本轮推送待复验。后续 D96/T95 聚焦 if/while/switch 控制语句声明和初始化器的指针作用域恢复。

本轮不报告正式准确率或产品影响；结论限于上述控制、固定源码差异和测试范围。
