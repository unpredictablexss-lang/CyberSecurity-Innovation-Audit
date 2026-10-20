# D 线接续切片：D86 / T85

负责人集成分支 `codex/d-owner-20261020-01a1571f` 当前验证 HEAD：`7d8a25a67f76d962a0196518c394a27c0f03f841`。远端在本轮复核时仍为 `origin/main=db77164fdc2af0da02e4d3efc056d84694fd68e8`、`origin/feat/d-commercial-next-20261019=0f4560c4712dbf914d762948e2220942f16324ad`；两者包含于负责人基线。该负责人分支为本地提交，未推送。

## 开发与测试反馈

D86（实现提交 `c484e722138600198b20f94e05e0cec56ec03f71`）将 C++ `alignof` AST 子树从敏感字节值流与执行效果中排除，检测器版本升至0.21.3。具名控制覆盖直接/内含非求值调用的 `alignof`、`sizeof`、真实日志、硬编码秘密、歧义属性键/脱敏拼写、空字符串、未知返回、实际调用及混合运行时值。仅对可证明为类型对齐元数据的两类输入消除候选；硬编码秘密、未知值和真实调用保持候选。

T85（测试提交 `7e729318a0a3377558769f057a4335480c1bd802`）独立固定了 Wi-Fi 与证书框架两组件的5个完整源文件，共109,330字节。commit/tree/path/blob/字节数/SHA-256均由本地Git对象复核。Wi-Fi 的实际代码包含 `config.preSharedKey`、复合追加、`std::string.c_str()`、`AssetValue` 和 `AssetAdd`；证书框架提供固定属性键 `CERT_PASSWORD="password"` 的对照。三版本回放（0.21.0/0.21.1/0.21.2）中 Wi-Fi 保持3个候选、证书框架保持21个候选；Wi-Fi候选依据从名字启发式变为真实 `preSharedKey→+=→c_str→AssetAdd` 依赖证据。证书候选保持未解析调用义务，不能据此声称密码内容泄漏。

D86 固定实现的扩展证据提交为 `4042510fef05d342968794a9c3d6f6f244982db4`；T85 实源输入上，直接与 `decltype` 内部 `alignof` 均为1→0，硬编码秘密/属性键歧义/脱敏拼写/空串/未知返回/真实调用/混合值均为1→1。Wi-Fi与证书框架分别仍为3与21个候选，候选签名、消息哈希、义务和覆盖状态完全相同。报告和可复放脚本见 [D86 handoff](D86_HANDOFF_20261020.md)、[T85 handoff](T85_REAL_CPP_HANDOFF_20261020.md)；第二层模型未实现。

## 集成验证与当前队列

负责人集成后实际复跑：

- `python -m unittest discover -s tests/detectors/data -t . -q`：108项通过。
- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus tests.detectors.test_d83_adversarial -q`：39项通过。
- `python research/data_sensitive/D86_verify.py --revision c484e722138600198b20f94e05e0cec56ec03f71 ...`：9个具名前后控制与两组固定真实源码复放通过；真实候选数分别3与21且身份/覆盖不变。
- `git diff --check`、任务树JSON解析通过。

关联集成提交：T85 `5d6d0ff0323fb41ab93f366191513a0132fbb9dc`，D86实现 `48404441ce270ddaba7389a3802bbc13c47df1e1`，D86固定SHA复验 `7d8a25a67f76d962a0196518c394a27c0f03f841`。可重放集成测试日志保存在负责人工作区的 `records/d-line-parallel-20261020-01a1571f/`。

样本解析/检测仍有 partial/blocked 覆盖；结果限于固定文件和当前静态模型，不证明完整组件覆盖、运行时可达性、产品影响或正式准确率。

下一轮 D87/T86 已启动：开发线审查证书全局属性键常量及其已知参数角色；测试线独立区分属性键、真实密码值、同名无关文本和未知 helper 包装，并对D87提交反馈复验。权威状态和逐线提示词见 [任务树](D_LINE_TASK_TREE_20261020.json) 与 [并行计划](D_LINE_PARALLEL_PLAN_20261020.md)。
