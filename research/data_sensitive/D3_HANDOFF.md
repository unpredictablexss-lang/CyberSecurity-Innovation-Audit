# D3 交付与停止核对

本轮按任务书在原 D 分支执行。起始与远端状态见 D3_BASELINE.json；源码来源见 D3_SOURCE_MANIFEST.json。模型、算法、测试分别提交，冻结实现见 D3_FREEZE.json；证据/文档提交在其后，不改变冻结算法。

| 交付 | 入口 |
| --- | --- |
| 实现及边界 | D3_IMPLEMENTATION.md |
| 模型来源 | D3_MODEL_EVIDENCE.md、historical_profiles.json |
| 两组历史判断 | D3_HISTORICAL_CASES.md |
| 真实实验与覆盖 | D3_REAL_SCAN.md / .json、D3_REAL_CONTROLS.json |
| 本轮验证 | D3_VALIDATION.json |
| 剩余限制 | D3_LIMITATIONS.md |
| 三份独立用户文档 | D3_acceptance_zh.md、D3_interface_requirements_zh.md、D3_research_plan_zh.md |
| 冻结后未标注数据 | D3_HOLDOUT_COLLECTION.json |

实际结果：537 测试中 526 通过、11 跳过；D 专项 25 个方法。原九文件覆盖无变化。真实 TCP 历史前后研究候选 1→0，公共均 0，目标 partial 文件未获公共准入。服务发现案例因开源 stub 返回不支持而排除为有效正例。已确认漏洞 0，没有 PoC/独立评估准确率。

四类统计与真实控制缺口不可混算。三个新组件源码仅收集待独立盲审，无标签、未测评。未调用其他 agent 或把本次自审冒充独立真值。

开发范围保持 D 的四个获准目录。任务书禁止修改其他路径，故 D3 当前状态在本研究交付中记录，不修改公共状态表；此明确任务约束优先于根 AGENTS 的通用状态更新规则。

本地可执行目标已到达任务书允许的停止边界：真实实验、模型、必要代码、回归与缺口/RFC已形成。按授权更新原 Draft PR #17 后停止，不继续扩规则，不擅改公共准入，不执行未经批准的动态 PoC。远端发布是否成功以单独核验回执为准，不把本地文档当推送证明。
