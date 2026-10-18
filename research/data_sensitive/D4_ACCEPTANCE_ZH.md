# 队友 D D4 阶段验收文档

## 阶段结论

**D4 的静态证据追踪和可审查摘要泛化原型已交付；运行态验证与公共 Runner 准入尚未完成，因此整个 D4 只能部分验收。**没有确认真实漏洞或产品影响。

## 已完成

| 要求 | 结果 | 证据 |
| --- | --- | --- |
| 追踪真实请求是否包含 `SESSION_KEY` | 已由固定版本源码证明：生成会话密钥、`PackRequest` 加入 JSON、`FLAG_REQUEST` 发送 | `D4_SOURCE_TRACE.md` 第 1-2 步 |
| 追踪接收解密和日志位置 | 已证明成功解密并解析后，整段 JSON 在 `ProcessMessage` 分流前进入 `SoftBusLog` | `D4_SOURCE_TRACE.md` 第 3-4 步 |
| 分清请求和回复 | 已证明请求消息有密钥字段，`PackReply` 不写密钥；共享日志语句先于回复判别 | `D4_SOURCE_TRACE.md` 第 4-5 步 |
| 追踪源码进入 SoftBus 标准服务构建目标 | 已核对根组件 -> core feature -> frame common sources -> `trans_session_src` -> `trans_channel_src` -> TCP Direct 源文件；标准 `softbus_server` 与 `softbus_adapter` target 均含相应源集合 | `D4_SOURCE_TRACE.md` 第 6 步、两份固定版本的 BUILD/GNI manifest |
| 扩充真实源码安全/同名无关对照 | 同一固定源码的 parse-failure 分支只记录常量错误文本并释放/返回；同名 `SoftBusLog` 的 `GetAuthSideFlag` 只记录 flags/side/seq 元数据。离线 verifier 对精确 blob 断言；不代表动态执行 | `D4_SOURCE_TRACE.md` 第 7 步、`d4_verify_sources.js` |
| 读取权限的同期间源码线索 | HiLog 命令经 `hilogControl` 控制 socket 读取；同期间 init 配置为 `0600 logd:logd`，SoftBus 服务配置为 `system` 或 `dsoftbus` 身份。配置含 `disabled: 1` 与 `start-mode: boot`，未证明服务已启动/socket 已创建；仅在服务运行且该配置适用、未被覆写时，按 DAC 可推断普通应用无法直接打开此控制 socket | `D4_HILOG_ACCESS_EVIDENCE.json` 与 `d4_verify_hilog_access.py` 固定 commit/tree、完整 commit/tree API 快照、4 个 blob/路径与离线校验；补充背景见 `D4_SOURCE_TRACE.md` |
| 固定版本真实源码对照 | 研究 Detector 对 10 个精确源码文件重放：旧版 1 个候选、后版 0 个；两版均 blocked，且各有 6 个文件 partial，因此只是候选差异，不是漏洞/修复结论 | `D4_REAL_SOURCE_REPLAY.json`、`d4_replay_real_source.py` |
| 日志长度和超长行为 | 固定实现使用 256 字节缓冲，`[TRAN]` 前缀占 6 字节；标准 adapter target 声明链接 `libsec_static`，同期可见 Secure-C 源码说明 destMax 含 NUL、溢出返回 -1，`SoftBusLog` 随后直接返回而不输出原始记录。目标产品最终链接的 revision 仍待锁定 | `D4_SOURCE_TRACE.md` 日志格式化第 8 步；`D4_SOURCE_MANIFEST.json` |
| 日志等级与查看路径 | 固定默认日志阈值为 0；HiLog 开发者可用 hilog/hdc 读环形缓冲，默认不持久化。这不证明普通应用/未授权主体可读 | `D4_SOURCE_TRACE.md` 第 9-11 步 |
| 机制扩展与安全边界 | 摘要可绑定其他函数/参数/类型/字段/分配器/sink/格式位置与默认隐私；检测器也拒绝快照摘要漂移、context 外/字节不匹配输入、重复路径和遗漏目标文件 | `historical.py`、`test_d3_historical.py` 的 profile 与来源绑定控制 |
| 安全与无关反例 | 默认私有 sink 不产生公开候选；同样名字的流位于无关处理函数时无候选 | 同上 |
| Runner 边界 | 保留现有 parse-partial 不准入控制，没有扩大公共扫描覆盖 | D 专项测试 |

## 验证

- D 专项定向单元测试：17 个方法通过；其中包括不同机制 profile、私有默认、同名无关函数，以及 4 个新增的快照/字节/重复路径/目标 scope 绑定回归。
- 新增离线源码证据校验器：DSoftBus 本地缓存模式复核 23 个唯一源 blob、对应 44 行来源映射及 35 个代码/构建图/安全对照事实，全部通过；HiLog 固定 commit/tree API 快照（151 项、未截断）、4 个源码 blob 与路径映射由独立校验器离线复核通过；并确认后续版本仍保留 SESSION_KEY 请求字段及其解码路径，仅日志语句被删除；解码侧会把请求字段恢复到会话密钥缓冲并清零临时编码串。缓存覆盖两个版本 profile 各自要求的 10 个文件、组件构建链和两种 SoftBus 服务身份配置。API 缓存模式可以离线重跑，但 API 记录不是独立 Git 对象库。另有同期 Secure-C immutable source；HiLog 的 `hilogd.cfg`、客户端、共享头、服务端源码已有固定 commit/tree/blob 和本地离线校验。HiLog 配置含 `disabled: 1`，无法证明服务启动/socket 存在；仍没有目标产品/设备 ACL、最终链接依赖、运行输出或日志读取实测。
- `py_compile` 和 D4 Markdown 尾随空白检查通过。当前本地 `d4-dev` 镜像没有 `.git`，因此无法对该镜像运行 `git diff --check`；项目实际 Git checkout 未修改。
- WSL 中缺少 `tree_sitter_c` 依赖，故定向测试在工作区已安装匹配 Tree-sitter C/C++ 依赖的 Python 3.10 环境中对 WSL 工作副本镜像执行。
- WSL 没有 `docker` 命令；未执行设备测试或动态 PoC。

## 尚未通过验收的部分

- 已确认上游仓库定义的标准 SoftBus target 构建图包含目标源码；但产品仓库配置、具体构建参数/最终 target graph 和设备镜像未提供，不能证明任何特定产品实际选择并打包这些 target。
- 已知固定源码格式化上限与 Secure-C 契约的错误分支；仍无目标产品 Secure-C 链接版本、运行时格式化返回/最终日志内容证据。超长时按该接口契约是拒绝输出，不应描述成“截断后输出”。
- 同时期 HiLog 源码配置显示 `hilogControl` socket 为 `0600 logd:logd`，SoftBus 服务配置为 `system`/`dsoftbus`；HiLog 配置还含 `disabled: 1`，因此不证明服务启动/socket 存在。仅在该 socket 按配置创建且产品未覆写时，普通应用直接打开会受 DAC 拒绝；目标产品配置、启动状态、shell/hdc 实际身份、普通应用 UID 拒绝测试和未授权主体实测仍缺失，不能下目标产品可读/不可读结论。
- 目标文件仍未由公共 Runner 正式准入；局部 AST/宏/类型接口需平台负责人处理。
- 泛化控制和同名无关函数仍是合成设计测试，没有第二个真实上游 API 的核验样本或独立 holdout；真实源码重放虽能复现版本候选差异，但整体解析 partial/blocked，不能用作独立准确率样本。

## 2026-10-18 本地复测补充

- Windows 本地虚拟环境复跑 D4 定向测试：17/17 通过；`tests/detectors/data` 数据检测器测试：33/33 通过。
- 在最后 4 项快照/scope 绑定回归加入前，全仓测试共 493 项，16 项失败、40 项错误、13 项跳过。失败项涉及 Windows 沙箱临时目录创建 Git 仓库权限、符号链接/平台假设和 POSIX Clang 可执行程序测试；因此全仓 Windows 结果不作为最终 D4 专项回归结论。加入回归后的 D4/数据检测器套件已单独通过 17/17、33/33。
- `d4_verify_sources.js --source-cache outputs/d4-source-cache` 本地复核通过；验证步骤见 `D4_SOURCE_API_VERIFICATION.json`。当前 Windows checkout 没有独立的 `communication_dsoftbus` Git 对象库，故 cache 模式证据依赖已记录的 GitHub API commit/tree/path 响应；若需独立 Git 数据库复核，仍要取得上游对象库。
- 本地补充核对了两个固定 commit 的完整递归 tree 中 11 个构建/服务身份文件（两版本共用相同 blob），并新增 12 项构建图、依赖和身份断言；共验证 44 条来源映射、23 个唯一 blob、35 项静态断言。版本对比也确认后续版本仍构造 SESSION_KEY 请求字段并保留接收解码路径，但不再记录明文；请求解析侧恢复密钥并清理临时编码字符串；发送侧用 Auth 加密 API 封装 JSON 后再交给 TCP，因此候选指向接收端解密后日志而非网络明文。另引用并缓存同期 Secure-C 和 HiLog socket DAC 源码作为长度与权限线索；HiLog 4 个 blob、recursive tree 的 4 个路径映射和客户端/服务端日志查询链有独立离线校验器。上述均不等同于某个产品镜像中的实际启用、最终链接依赖或设备拒绝证明。
- D4 仍未接入公共 Runner/Catalog 或面板，本地验证的是研究原型和测试，不表示面板已有 D4 功能。
- 本地复测没有上传或推送到 GitHub。

详细依据与剩余工作见 `D4_SOURCE_TRACE.md`、`D4_LIMITATIONS.md`、`D4_INTERFACE_REQUIREMENTS_ZH.md` 和 `D4_RESEARCH_PLAN_ZH.md`。
