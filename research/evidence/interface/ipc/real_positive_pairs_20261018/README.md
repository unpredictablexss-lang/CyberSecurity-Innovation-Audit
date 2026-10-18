# IPC 高召回评估集状态

本目录当前保存一条独立公开来源的 OpenHarmony AUTH-01 真实修复对，用于固定提交扫描的回归校验。数据集仍为建设中且未冻结；该样本不是盲测，不能据此计算 family precision/recall。

- 案例：cases/useriam_query_callback.json
- 来源：Gitee OpenHarmony 安全问题 I4WQO1
- 复跑：run_useriam_pair.sh [本地仓库目录] [输出目录]
- 标签依据：公开完成状态、修复提交说明、漏洞父提交与直接源码差异绑定。

新案例必须绑定固定完整 commit、tree、受影响 blob、源码 SHA-256、规则/模型版本和独立标签依据。synthetic fixture、Harness 自测和未经独立复核的 scanner 候选不计入真实正例。
