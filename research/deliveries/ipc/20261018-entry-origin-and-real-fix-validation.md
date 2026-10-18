# B 线入口来源修正与真实修复对实验

日期：2026-10-18
代码分支：work/ipc-20261017
实验代码基线：5254e1b28e804a344394b897d3456ff0801d50e5，随后只修改 B 线 IPC 分析器和对应测试。
目标：让仓库级扫描的候选入口更接近真实 IPC 服务边界，并用公开 OpenHarmony 修复对验证候选变化。

## 结论

- 已修正入口准入：仅凭 OnRemoteRequest 名字和 Parcel 参数不再足以建立 IPC 根；必须是索引器按 code/request Parcel/reply Parcel 签名发现的类方法分发入口。明确列入策略的 service/transport 入口与 Stub 的 *Inner 辅助入口保留。
- test/fuzz/mock 路径下被识别出的入口不再混入产品候选；结果中记录跳过的入口数。源文件仍在固定提交的扫描范围内，测试入口的行为不被表述为产品可达性。
- 全量回归：651 tests 通过，36 项按现有测试标记跳过。
- 大组件全仓重扫：communication_netmanager_ext@8c35917b7e2f152813b13a20530a8452cf73d938。选入 654 个源文件，其中分析器执行覆盖 632 个；434 个完整解析、198 个 partial。入口修正前，11 条候选全部由 test/fuzz 入口路径带出；修正后产品候选 0，明确跳过 1 个 test/fuzz/mock 入口。partial 比例约 31.3%，所以 0 候选不是安全结论，运行覆盖为 completed_with_limitations。
- 真实修复对：useriam_auth_executor_mgr 的官方历史修复明确在 QueryCallbackStub::OnRemoteRequest 中增加接口 token 检查。漏洞父提交固定为 48f3ba7c220f18244f908f0452527304349e850c，修复为其直接子提交 9f35fade871d3cf15acb6191e965a8582bea201e。相同检测器分别全仓扫描后，受影响文件 AUTH-01 候选从 2 条变为 0 条；全仓总数从 8 变 6，剩余 6 条没有由本实验判定。
- 这是一条公开、独立于算法实现的真实正例修复对回归，不是盲测，也没有运行设备 PoC。它支持“这条 AUTH-01 规则命中过已公开修复的代码区域并在修复后消失”，不支持全家族召回率、准确率或漏洞确认结论。

## 改动说明

旧逻辑可能把 fuzz 包装代码里的同名方法当作服务端 IPC 入口，再沿着 fuzz 初始化/模拟路径分析生产服务函数。netmanager 的旧报告 11 条候选全部带有 test/fuzz/mock 入口路径提示，无法代表产品入口。

现在 IPC 根需要满足源码索引发现的分发函数签名：code + request Parcel + reply Parcel，并要求有类 owner。自由函数即使叫 OnRemoteRequest 也不进入产品候选分析。测试路径入口在 allowlist、显式入口和索引绑定入口三类准入后统一排除，并计入限制信息。

这项改动只调整入口来源，不调整 AUTH-01 规则和授权语义。新增负例覆盖“自由 fuzz wrapper 只有请求 Parcel”的情况；既有正例继续验证完整类方法能形成根。测试/模糊测试目录作为验证素材保留，但不作为产品候选来源。

## 固定实验清单

| 实验 | 固定目标 | 结果 |
|---|---|---|
| 全量单元测试 | 当前 B 线工作树 | 651 OK，36 skipped |
| 大组件全仓 | communication_netmanager_ext @ 8c35917b7e2f152813b13a20530a8452cf73d938，tree e26372f6cd65be928b9c1cf4a96d3c7dd5ece804 | 654 selected source files，632 analyzed; 434 complete / 198 partial; 0 product candidates |
| 真实正例 | useriam_auth_executor_mgr @ 48f3ba7c220f18244f908f0452527304349e850c | 8 全仓候选；目标文件 2 条 AUTH-01 |
| 修复反例 | 同仓 @ 9f35fade871d3cf15acb6191e965a8582bea201e | 6 全仓候选；目标文件 0 条 |

复跑脚本：research/evidence/interface/ipc/real_positive_pairs_20261018/run_useriam_pair.sh。固定标签与 blob/hash：同目录 cases/useriam_query_callback.json。目标仓库在本地 WSL 临时目录 /home/audit/oh-audit-targets/useriam_auth_executor_mgr；netmanager 在只读 G 盘镜像副本和 WSL 本地副本都绑定相同 full SHA/tree，扫描在本地副本上完成。

## 下一步：只围绕仓库扫描质量推进

1. 保持入口误归类与测试来源隔离进入固定回归。扩大到另一个 fuzz 密集组件确认旧入口是否也污染候选。
2. 为 AUTH-01 建立更多独立公开修复对。先从 OpenHarmony 安全公告/已完成安全 issue 收集固定 vulnerable/fixed SHA 和受影响文件；每条用相同 detector commit 扫两端。暂不声称该家族总体准确或召回。
3. 每条候选展示 IPC dispatcher → transaction handler → guard → effect 证据；固定绑定不足、partial、仓外依赖明确打 unknown，不删候选。
4. 完整仓库扫描继续按固定提交批次执行。每次保存 Git SHA/tree、源文件总量、支持文件数、complete/partial/unknown、跳过原因、候选数量和报告摘要哈希。候选数量不能替代覆盖率或准确率。

## 未验证

- 没有设备级运行时 PoC 或跨进程攻击验证。
- 没有证明 netmanager 的 198 个 partial 文件安全；这些路径保持 unknown。
- 没有复核 useriam 固定版本余下 6 条候选。
- 一个 AUTH-01 修复对不足以估计任何总体 Precision/Recall。


## Report hashes

- netmanager full scan JSON: e38732d967e11e3b3a4bbf2077859d97e626b37509f52e542884f0fda8f95085
- useriam vulnerable scan JSON: eaf174f913931cd27d12f8bfe6bed57dcc64619db51d0b31434789f18f6622a2
- useriam fixed scan JSON: 476d5e4ab139ba9570b37cf1a805837b0fdebcbfeccb62dc3083d90061e58a8d

Exact detector and regression-test source blobs are recorded in the case JSON; the source model is oh-ipc-2026.10-v11.
