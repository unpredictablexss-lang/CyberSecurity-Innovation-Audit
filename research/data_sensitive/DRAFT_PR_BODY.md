## 队友 D：历史敏感信息日志候选与受限检测研究

本 PR 累计包含 D1-D3 的敏感材料到日志研究原型，以及 D4 对 TCP Direct 历史候选的源码追踪、版本对比和证据加固。固定旧版源码显示：请求 JSON 含 Base64 `SESSION_KEY`；发送包经 Auth 加密后传输；接收端成功解密、解析后，在请求/回复分流前把完整 JSON 传给旧版 `SoftBusLog`。后续固定版本删除了这条接收侧日志，但仍保留请求字段及接收解码路径。

**这只是受限的静态候选与历史语句差异，不是已确认漏洞或修复证明。**D4 真实源码重放两版均为 `blocked`（各 10 个 required files 中有 6 个 partial）；旧版 1 个候选、后版 0 个候选。未确认产品影响，未执行动态 PoC，公共 Runner/Catalog/面板未改。

### D4 证据与实现

- 真实请求/密钥链：发送端生成会话密钥，`PackRequest` 写入 `SESSION_KEY`，并以 `FLAG_REQUEST` 发送；接收侧 `UnpackRequest` 把该字段解码回 `appInfo->sessionKey`，清理临时编码串。
- 网络边界：`TransTdcPostBytes` 经 `PackBytes` 调用 `AuthEncrypt`/`AuthEncryptBySeq` 后发送包缓冲；候选是接收端解密后的日志风险，不是网络明文传输结论。
- 日志路径与版本：旧版 `DecryptMessage` 将 Auth 解密输出写到 `crypInfo.out`；成功解析后、`ProcessMessage` 根据请求/回复标志分流前记录该缓冲。后版移除了这条日志，仍保留密钥请求与接收解码协议路径。
- 构建/长度/访问线索：已逐层核验上游标准 SoftBus target 图、256 字节日志缓冲、Secure-C 格式化错误返回行为、默认日志等级及相邻日期 HiLog `0600 logd:logd` 控制 socket 配置。HiLog 配置含 `disabled: 1`，不证明服务启动/socket 存在；只有在服务运行并按该配置创建 socket 时，0600 才支持普通应用无法直接打开此控制 socket 的条件性 DAC 推论。产品选用构建、最终 Secure-C 依赖、目标设备 ACL 和实际读取权限仍未知。
- DSoftBus 精确源码离线校验器覆盖 44 条来源映射、23 个唯一 blob 和 35 项代码/构建/安全对照断言；另将相邻日期 HiLog 固定 commit/tree 下的配置、客户端、共享头、服务端 4 个 blob 与完整 recursive commit/tree API 响应均纳入本地证据和独立离线校验。校验区分 0600 `hilogControl` 与 0666 `hilogInput`，并验证 hilogd `disabled: 1`、客户端使用控制 socket、服务端查询日志缓冲；所有结论仍不证明产品服务启动或目标设备 ACL。
- 研究 Detector 对固定版本输入使用精确 commit/profile/source SHA，并拒绝快照漂移、重复路径、外部输入字节不匹配和缺少目标文件。保留 `partial`/`blocked`，不扩大公共 Runner 覆盖。

### 本地验证

- D4 定向测试：17/17 通过；数据检测器测试：33/33 通过。
- 源码 verifier：44 条映射、35 项断言通过；验证材料包含 manifest、API tree 记录、缓存 source blob、重放 JSON 和校验脚本 SHA-256。
- Python 编译检查、JSON 解析和 D4 文档空白检查通过。

### 尚待审核/验证

- 具体产品构建配置、镜像清单、最终 Secure-C 依赖和运行时日志输出未提供。
- HiLog ACL 证据来自相邻日期上游源码配置，且配置含 `disabled: 1`；没有目标产品服务启动状态、socket 权限、普通应用或未授权主体读取实测。
- 两版研究重放均因解析不完整而 blocked；候选差异不能推导漏洞引入、修复或检测准确率。
- 公共 Runner 的局部 AST/宏/类型准入由平台负责人处理；此 PR 不改共享 Parser/Runner。
- 没有确认漏洞、产品影响或修复结论。

从 `research/data_sensitive/D4_HANDOFF.md` 开始查看；完整证据、验收、接口需求和研究方案分别见 `D4_SOURCE_TRACE.md`、`D4_ACCEPTANCE_ZH.md`、`D4_INTERFACE_REQUIREMENTS_ZH.md`、`D4_RESEARCH_PLAN_ZH.md` 与 `D4_VALIDATION.json`。
