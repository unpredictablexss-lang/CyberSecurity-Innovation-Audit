## D2：修复提前退出传播，补齐固定范围审计（保持 Draft）

D1工程原型保留。本轮只升级D模块到Detector0.2.0，Source/Sink语义模型仍0.1.0；唯一规则
`data.log.sensitive-value`，拟议ID `ohscanner.data.sensitive_exposure`，未注册Catalog/UI。

### 问题与变化

D1把已return分支的敏感赋值合并到后继日志，同时漏掉部分活跃else/短路效果。
先加入33控制，在D1实测12个失败子用例；修复后仅合并存活后继，显式返回退出状态，恢复块作用域绑定。
补充格式/实参/状态与同名函数指针对照，最终新增39控制；旧32控制及预期哈希不变。

### 实际验证

- 实现与测试HEAD：`3b646c881716eb6b0c86195cdeeb1012ac9c921b`；D1 HEAD `f11d5fd`，merge-base `e510c99`。
- D专项16方法通过（含32旧+39新控制）；全项目528项，517通过、11历史来源/Docker等条件跳过，0失败/错误；compileall和diff检查通过。
- 固定dsoftbus `0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132`、相同9文件、相同源模型：D1/D2均0候选，覆盖均complete0/partial3/not_analyzed6/failed0；D2双跑观察和覆盖一致。
- 逐文件错误/函数/模型审计及私有探针已区分；15个不与错误直接交叠函数不等于已批准准入。

### 审核入口

- [D2交付总览](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_HANDOFF.md)
- [基线](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_BASELINE.md) / [实现与回归](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_IMPLEMENTATION.md)
- [9文件覆盖](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_COVERAGE.md) / [机器证据](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_COVERAGE.json)
- [历史调查](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_HISTORICAL.md) / [来源manifest](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_HISTORY_MANIFEST.json)
- [独立评估计划](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_EVALUATION.md) / [隔离验证计划](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_POC_PLAN.md)
- [最小前端RFC](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/frontend_request.md) / [实际测试记录](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/feat/teammate-d-sensitive-exposure-20261017/research/data_sensitive/D2_VALIDATION.json)
- D1的独立验收、接口需求、研究方案仍保留；D1 validation push=false是当时快照，不是当前PR状态。

### 限制

没有确认真实漏洞、CVE或产品影响；两组可核实日志删除硬化对尚不具备当前规则的真实正例标签/模型。
GitCode具体API请求404，使用明确标注的GitHub镜像/API证据，未声称双源核验成功。
独立holdout和Docker PoC仅完成方案，未执行。零候选不是安全结论，不提供Precision/Recall。
公共Runner/Catalog/contracts/frontend/indexing/DB/UI与A/B/C均未改动；D2增量只限D目录。
负责人请审查局部partial资格/共享事实RFC。保持Draft，不自动Ready/Merge。
