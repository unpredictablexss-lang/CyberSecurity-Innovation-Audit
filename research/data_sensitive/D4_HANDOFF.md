# D4 交付入口

- 真实请求到日志的逐跳事实与版本边界：`D4_SOURCE_TRACE.md`、`D4_SOURCE_MANIFEST.json`
- 源对象 API 复核和真实版本重放：`D4_SOURCE_API_VERIFICATION.json`、`d4_replay_real_source.py`、`D4_REAL_SOURCE_REPLAY.json`
- HiLog 读取 ACL 的固定 commit/tree API 快照、4 个源 blob 与离线校验：`D4_HILOG_ACCESS_EVIDENCE.json`、`d4_verify_hilog_access.py`
- 检测器扩展和结论边界：`D4_IMPLEMENTATION.md`、`D4_LIMITATIONS.md`
- 验收清单：`D4_ACCEPTANCE_ZH.md`
- 平台接口需求：`D4_INTERFACE_REQUIREMENTS_ZH.md`
- 后续研究方案：`D4_RESEARCH_PLAN_ZH.md`
- 机器可读验证记录：`D4_VALIDATION.json`

本地复核期间发现研究 Detector 可被直接调用而不经过 Runner 的快照前置检查，已在 Detector 内增加请求快照、文件路径唯一性、源字节 SHA-256、输入单元与 context 一致性和必须纳入目标文件检查；4 个新增回归测试覆盖输入漂移、摘要漂移、重复路径和目标 scope 缺失。当前 D4 专项 17 项及数据检测器套件 33 项通过；HiLog ACL 独立校验器验证 4 个固定 blob/tree path 与配置、客户端、服务端读取链通过。真实固定源码重放旧版 1 候选、后版 0 候选，但两版均 blocked/partial。

D4 本地改动限定于 detector、测试、项目状态和 `research/data_sensitive/` 路径。D4 镜像没有 `.git`；本地补丁基于 4 个已核实的现有 PR head 文件 blob 和新增文件重建，在隔离树中 19 个路径均可应用且逐文件 SHA-256 与镜像一致。这不是完整 PR head checkout；所有新增路径是否已存在当前远端尚未重核。只做本地复核，没有提交、推送或更新 PR；不合并，不把未完成证据标成漏洞确认。

远端只读核查确认 Draft PR #17 仍为 open/draft，head 为 `feat/teammate-d-sensitive-exposure-20261017` @ `c250bd57fa6670c21afa82a2e4684c0bc4c21298`，base 为 `main` @ `e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。已将 PR 正文更新稿保存在 `DRAFT_PR_BODY.md`，没有写入 GitHub。当前本机 Git checkout 只有 `feat/historical-vuln-benchmark` @ `348945f7fc9d1519c7084e40131893ef177014e8`；D4 工作镜像无 `.git`，故不能把这份本地副本误称为该 PR 分支的本地 Git diff。
