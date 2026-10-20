# D 线第 16 轮：D100/T99 嵌套 return 分支

D100/T99 在 owner 分支集成。规则0.21.15对 flat switch arm 内单层 if/else 仅在两支均直接return时判定arm终止；支持的return expression与材料返回流继续参与现有effects分析。缺else、活出口、复杂嵌套、partial/macro/goto仍保守。

开发侧8项、5个基线失败归零，data371；独立T99 16项、8个基线失败归零，data387/387，兼容性62/62。owner集成后data387/387、兼容性62/62通过。固定T85 direct/Runner仍24条，638个call facts及890/915不变，3文件仍partial。T99对comma-return发现状态码被左侧sink错误污染；该问题明确为 `known_gap_not_passed`，本轮不处理。

实现 `835f02dc72ac0c1926634e0cc4a10f82a4994052`，D100证据 `4f1486fe73178adf11b19428a5c0cf57f85c7bef`，独立T99 `4405bfa90f4a0ee495ecb99c47ff035889363a68`。D101/T100已启动，聚焦内建comma operator左侧effects与最终返回值分离，同时对重载/unknown type保持保守。
