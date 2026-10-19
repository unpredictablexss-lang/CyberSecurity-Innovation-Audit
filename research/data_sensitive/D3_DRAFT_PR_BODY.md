## 队友 D：D3 真实历史版本实验与受限检测原型

本 PR 累计包含 D1/D2 局部敏感材料到日志原型，以及 D3 的显式历史模型和真实 Git 源码实验。D3 在成功解密后的请求 JSON 缓冲区到旧版公开日志之间识别出一条条件研究候选，并在真实日志删除后的版本观察到候选消失。

**真实候选来自独立研究探针；公共 Runner 因目标文件 partial 解析未准入该文件，两端正式候选均为 0。没有确认漏洞、产品影响结论或动态 PoC。**

### D3 代码及验证

- 模型提交 `dc9ed46`：TCP 前后两个精确 commit，模型 `0.2.0-historical.1`；每端 10 个依赖文件、定义行号、blob/SHA 与日志语义。
- 算法提交 `7a75d9c`：历史检测器 `0.3.0`；分配/非空/成功分支、受审一跳 DecryptMessage 输出摘要、旧 SoftBusLog 格式语义；未修改公共准入。
- 测试提交 `88528b7`：24 个新增设计控制；旧 71 控制哈希不变。专项 25 个 unittest 方法通过。
- 全量实际执行：537 项，526 passed、11 skipped、0 failures/errors；compileall 和 diff 检查通过。跳过理由与日志 SHA 见 `D3_VALIDATION.json`。

### 真实实验

| 范围 | 公共候选 | 研究探针候选 | 公共覆盖 complete/partial/not_analyzed/failed |
| --- | ---: | ---: | --- |
| 原固定 9 文件 | 0 | 0 | 0/3/6/0 |
| TCP 修改前 10 文件 | 0 | 1 | 0/4/6/0 |
| TCP 修改后 10 文件 | 0 | 0 | 0/4/6/0 |

每个输入公共及私有分析双跑稳定。TCP 消息构造将 Base64 会话密钥加入 JSON，旧日志经过 secure-C 格式化后由 public HiLog / printf 输出；请求种类、格式化长度成功、生产配置和非授权读取仍是义务。

服务发现日志删除对不作为正例：开源 DiscCoapAssembleCapData 是返回“不支持”的 stub，调用方退出，不能证明被删日志可达。GitCode 具体 API 404，使用明确标识的官方 GitHub 镜像，未宣称跨镜像已核验。

### 审核入口与剩余限制

从 `research/data_sensitive/D3_HANDOFF.md` 开始；模型证据、历史判断、真实实验、覆盖、机器可读验证及限制分别位于 `D3_MODEL_EVIDENCE.md`、`D3_HISTORICAL_CASES.md`、`D3_REAL_SCAN.md/.json`、`D3_VALIDATION.json`、`D3_LIMITATIONS.md`。

三份独立中文文档：`D3_acceptance_zh.md`、`D3_interface_requirements_zh.md`、`D3_research_plan_zh.md`。

冻结后收集 3 个其他组件的未标注源码供盲审；未执行独立 holdout，不报告 Precision/Recall。真实同名无关函数对照尚缺，脱敏形状不等于已通过安全评估。

D3 增量只在 D 获准的四个目录；不改 Runner/Catalog/contracts/frontend/DB/UI/A/B/C，不注册面板、不自动 Ready 或合并。原 D1 的公共状态文档改动是历史累计差异，D3 没有新增该路径修改。
