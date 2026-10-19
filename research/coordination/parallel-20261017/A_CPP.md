# A 线：C/C++ 算法与证据

任务位置、基线和环境以本机 manifest 为准。原 A 分支保持原样。
参考来源：`codex/full-runtime-performance-audit-20261014@95ed5a71f9ada37cb0b3f3eb4d95340287d38027`（本轮只核对远端 head，未把全部改动验收）。
先读 `research/reviews/owner-platform-review-20261016/README.md`（若当前共同基线不含此远端材料，可从固定 GitHub 提交 8e97f152ef747c1e1d21ae179a048910f147e07a 只读查看）。

第一交付：选一个算法/来源绑定阻塞，按最小文件集迁入本线，说明父提交和文件来源；不要整体 cherry-pick 平台/公共契约。
保留 shared_ptr/lifetime 的 positive/fixed/safe/unrelated 控制与 partial/not_analyzed；
同范围复扫必须绑定 repo/full SHA/tree/blob/source hash/scope/Detector 版本，不用告警减少证明准确率。

可写范围看 ownership.json 的 cpp。公共 runner/catalog/contracts、验证编排和历史复核记录不归本线。
如果算法需要公共契约，提交接口申请，不复制一套契约。

验收：
- `.venv-web/bin/python -m unittest discover -s tests/detectors -v`。
- `.venv-web/bin/python -m unittest tests.test_shared_ptr_race_poc tests.test_lifetime_uaf_poc -v`；依赖缺失写明 skip，不能宿主机回退绕过 Docker 策略。
- 针对算法移动提供固定来源逐项 diff，区分候选身份数、根因数、confirmed；没有真值集不报 Precision/Recall。
- 本线 scope check 为零越界；按模板交付。不得改写历史 229/208 记录或升级组件 Harness 为产品漏洞。
