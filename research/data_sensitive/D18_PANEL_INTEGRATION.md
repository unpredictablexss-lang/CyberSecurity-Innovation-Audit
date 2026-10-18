# D18：面板显式扫描接入记录

日期：2026-10-18（Asia/Shanghai）。目标是验证 D 检测器能否通过现有仓库扫描 API/Worker/报告链执行；这是接入验收，不是漏洞确认。

## 固定输入与运行

- 面板：本地工作台 http://localhost:8765；任务：http://localhost:8765/#/tasks/568dc8b265df41108f03ce2aed14dfce。
- 仓库：openharmony/communication_dsoftbus，commit 0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132，tree bd915661eedd139df17f249191e2a691e76f7565。
- 快照 SHA-256：cd873f97cfbfa8740efbf31545cb4ddd7c4dd9755ea60f3bc96e8b15b408174f；扫描范围为 9 个固定目标文件，范围清单及逐文件 source SHA-256 见 [D18 固定范围重放](D18_G_REPO_DSOFTBUS_REPLAY/summary.json)。
- Detector：ohscanner.data.sensitive_exposure 0.13.0；本次通过仓库扫描页实验选项显式选择。默认计划跳过该 Detector。
- 计划 SHA-256：0e246afef733813a8de9283d1b78cb5fd99ca4032df7310f74b91f458e517548；引擎 SHA-256：1369fba53521f4e7b2bd3e754b347cb3dc7103010c8aceb37d3e5b0bba331be。
- 报告 SHA-256：6c7947edba67d844a2a5d09e108afbf4e2599cfdce4289aa44c43b4ad8eb0d85；Worker 约 2.05 秒。

## 观察结果

报告保留 1 条 data.sensitive.unresolved-escape 候选，位于 core/authentication/src/auth_hichain.c:136：OnSessionKeyReturned 的参数进入未解析调用 AuthSessionSaveSessionKey。该文件 source SHA-256 为 4132e6577e6d736a7f922b0344fbcb2002d533f079ee332494ffdf007ec47e7b。

D 的文件覆盖为 partial，DetectorRun 为 blocked，任务状态为 completed_with_limitations；报告 validated_vulnerability=0。候选保留证明公共面板链没有因聚合 blocked 而丢弃局部候选，不能证明它在产品中可达、最终进入日志、可被未授权主体读取或造成影响。

首次将仓库登记为临时实验名时，精确版本模型未匹配，D 返回 blocked 且 0 findings。更正为模型所审查的规范身份后才得到上述候选。一次全仓预览也因当前 M1 2,000 文件预算被拒绝，未入队；本次改用 9 个固定目标文件。上述失败均是范围/身份限制，不是负例。

## 代码接线与验收边界

D 以 research_candidate 注册，default_enabled=false；只可由仓库扫描页显式勾选，API 仍校验可用 detector ID，默认扫描不请求 D。精确仓库/commit 模型与模型文件摘要进入引擎指纹；未知版本继续 blocked。D4 审核材料的 main 准入清单建议继续适用：本接线只证明显式实验扫描功能；不代表默认启用、商业级召回率、独立 holdout 通过或真实漏洞确认。

可复核代码测试：tests/test_owner_cd_admission.py、tests/test_owner_integration.py、tests/test_workbench.py、web/tests/auditRequests.test.js，以及根目录完整 Python/前端命令。动态产品 PoC、受控修复前后验证与独立真实 holdout 仍未完成。
