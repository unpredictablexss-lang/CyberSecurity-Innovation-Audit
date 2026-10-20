# 可选 Ark Runtime 正式评测工具

组长于 2026-10-20 授权取消项目自设的逐次审批、真人评测、产品确认和全部案例准入前置条件。授权持续有效直到用户撤销，见根 `AGENTS.md` 与 `config/collaboration/standing_authorization.json`。缺项记 unknown/not_run，继续可执行工作；豁免不代表测试通过。

`holdout_pipeline.py` 是历史双盲流程的可选实现，不是开发入口。缺真人、custodian 或 source set 时跳过此工具，直接继续规则/回归/真实源码重放。不要为满足它的 schema 伪造人员、签署和标签。

当前保存的 selftest 是合成机制测试，真实独立 holdout 未运行，Precision/Recall 未计算。管线的 strict score 要求只影响主动选择运行该研究工具的结果解释，不影响开发完成、扫描、模型候选审查或本地组件 PoC。

日常评估可报告真实控制矩阵、覆盖、候选差异、耗时与失败。若以后需要正式准确率，再选择与结论相适合的标签和采样方法并说明局限；不强制两名真人加裁决人、保管员和独立签署。
