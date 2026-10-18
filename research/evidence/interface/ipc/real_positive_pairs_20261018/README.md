# IPC 高召回评估集状态

本目录当前保存一条独立公开来源的 OpenHarmony AUTH-01 真实修复对，以及同一漏洞版本中的一条安全入口对照和一条无关客户端对照，用于固定提交扫描的回归校验。数据集仍为建设中且未冻结；对照标签由本项目人员按固定源码复核，不是独立盲测，不能据此计算 family precision/recall。

- 案例：cases/useriam_query_callback.json
- 来源：Gitee OpenHarmony 安全问题 I4WQO1
- 复跑：run_useriam_pair.sh [本地仓库目录] [输出目录]
- 标签依据：公开完成状态、修复提交说明、漏洞父提交与直接源码差异绑定。
- 安全对照：`ExecutorCallbackStub::OnRemoteRequest` 在分发前读取并比较 interface token，完整解析且没有 AUTH-01 诊断。
- 无关对照：`ExecutorMessengerProxy` 是出站客户端代理，写入 token 后调用 `SendRequest`，不是入站 IPC dispatcher；完整解析且没有 AUTH-01 诊断。
- 两条对照均固定在 vulnerable commit，包含 Git blob、SHA-256、解析/分析状态和源码复核理由；标签是团队源码复核结果，不是外部裁定。

新案例必须绑定固定完整 commit、tree、受影响 blob、源码 SHA-256、规则/模型版本和独立标签依据。synthetic fixture、Harness 自测和未经独立复核的 scanner 候选不计入真实正例。
