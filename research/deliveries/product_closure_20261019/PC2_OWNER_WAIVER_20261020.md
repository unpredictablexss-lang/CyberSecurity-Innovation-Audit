# PC-2 长期豁免与开发授权

组长于 2026-10-20 授权取消项目自设的逐次审批、真人评测、产品确认和全部案例准入前置条件。授权持续有效直到用户撤销，见根 `AGENTS.md` 与 `config/collaboration/standing_authorization.json`。缺项记 unknown/not_run，继续可执行工作；豁免不代表测试通过。

早先的 PC-2 人工配置豁免现扩展为整个项目的非阻塞开发规则：不要求独立 source set、两位真人 reviewer、一位 adjudicator、custodian、签署或 sealed custody 才能开始开发、扫描、组件测试和成果报告。无需反复向用户索取这些配置。

真实 holdout 仍未执行，可靠独立标签和 Precision/Recall 仍不可用；豁免不构成 review PASS。以后需要相应指标时按适合的证据与方法开展可选评测，披露来源和独立性，不强制恢复旧的多方签署流程。

任务树改为 ACTIVE_DEVELOPMENT，PC-2 为 OPTIONAL_NOT_RUN、blocks_development=false。该授权持续有效直到用户撤销。
