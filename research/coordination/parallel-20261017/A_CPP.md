# A 线：C/C++ 算法与证据

组长于 2026-10-20 授权取消项目自设的逐次审批、真人评测和产品确认前置条件；授权持续有效直到用户撤销。缺项记 unknown/not_run，继续可执行工作；无需再申请目录、构建、隔离组件 PoC 或日常提交许可。

任务位置、基线和环境以本机 manifest 为准。原 A 分支保持原样。
参考来源：`codex/full-runtime-performance-audit-20261014@95ed5a71f9ada37cb0b3f3eb4d95340287d38027`（本轮只核对远端 head，未把全部改动验收）。
先读 `research/reviews/owner-platform-review-20261016/README.md`（若当前共同基线不含此远端材料，可从固定 GitHub 提交 8e97f152ef747c1e1d21ae179a048910f147e07a 只读查看）。

第一交付：选一个算法/来源绑定阻塞，按最小文件集迁入本线，说明父提交和文件来源；不要整体 cherry-pick 平台/公共契约。
保留 shared_ptr/lifetime 的 positive/fixed/safe/unrelated 控制与 partial/not_analyzed；
同范围复扫必须绑定 repo/full SHA/tree/blob/source hash/scope/Detector 版本，不用告警减少证明准确率。

ownership.json 的 cpp 记录主要职责；必要公共 runner/catalog/contracts 和验证编排改动已授权，直接实现最小兼容改动，不复制另一套契约或改写历史复核。

验收：
- `.venv-web/bin/python -m unittest discover -s tests/detectors -v`。
- `.venv-web/bin/python -m unittest tests.test_shared_ptr_race_poc tests.test_lifetime_uaf_poc -v`；依赖缺失可自行准备合适隔离环境；确实不可执行时如实写明 skip。
- 针对算法移动提供固定来源逐项 diff，区分候选身份数、根因数、confirmed；没有真值集不报 Precision/Recall。
- scope check 仅提示，不作为交付门；按实际改动和验证交付。不得改写历史 229/208 记录或升级组件 Harness 为产品漏洞。
