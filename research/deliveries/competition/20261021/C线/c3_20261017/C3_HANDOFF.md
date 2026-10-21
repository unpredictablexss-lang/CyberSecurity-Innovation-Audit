# C3 交付与负责人验收入口

算法冻结提交：`4ea5f4020884aed5860a88d50f5a926610e7b98a`；C2 基线：`33242fbd2b58e2f510fa74f1521e247fea08db27`；公共 main 基线：`e510c99c67f31ec6c73365f9ab749c79ca6ff0a1`。
分支：`codex/teammate-c-ark-runtime-type-safety`；交付到 [Draft PR #16](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/pull/16)，使用 shriory，保持 Draft、不合并。
Detector/model `0.2.0`；模型 SHA-256：`1421ec97eb81e0f08910a83d7b72cfdd9d5bcd22aa752105739faf36341c72fe`。

## 本轮结论

1. 不再只用原历史案例作为开发验证：先在 C2 上运行 24 个新机制，12 失败；改进后同一矩阵 24/24。独立准确率仍未知。
2. 新增表达式副作用统一处理、token 采样寿命、别名/重赋值失效、守卫过期控制、宿主写入预检、循环身份保护、真实符号区间及跨函数预算证据保留。公共协议不变。
3. 修复版真实文件索引 53 个函数，4 个精确配置适用；Filter/Set 匹配，CopyWithin/With 未知，无新增候选。不是 53 个函数安全证明。
4. 固定历史版本仍为独立研究 1 candidate / 0 candidate；修复后 Filter 明确产生 matched，不是未运行。C01–C12 为 12/12。
5. 分支、标签和循环使用有界生成图；保存的路径是符号 witness。完整数值约束可满足性、species 实际行为及产品可达性尚未知。
6. 真实文件仍 partial；正式 Runner 两版本均 blocked/not_analyzed，未注册 Catalog，未删除 AST 要求。
7. 无上游构建或动态 PoC。已核验 Ubuntu 存在，能运行本项目回归；上游工具链和可信动态隔离环境未就绪。
8. 冻结后 16 项待审样本已生成预测，未据此调参；尚缺独立人工标签，不能声称完成独立 holdout 评分，Precision/Recall 不计算。
9. 假候选风险来自符号路径/实际类型差异义务；假安全风险通过未知副作用和宿主写入降 unknown，但尚无完整 C++/跨过程证明；假覆盖通过真实 partial、精确配置和区域元数据限制。详见限制报告。
10. 请求负责人独立评审 partial 局部证据准入、摘要/构建事实绑定和跨过程事实需求；不请求本 PR 自动生产启用或合入。

## 实际验证

- Windows 冻结前最终专项 66/66，0 skip，含固定历史对象；compileall 与 diff check 通过。
- Ubuntu 22.04 / Python 3.10.12，冻结 Git 提交的独立 LF clone：专项 66/66，完整 Python 578 项中 567 pass、11 skip、0 fail/error，compileall 与 diff check 通过。
- 11 skip 为 perf IPC 语料 1、Docker-only AUTH-01 2、缺固定可达性源码 6、缺 shared_ptr 历史源码 2；不是 C 的两项历史测试被跳过。
- 研究 replay 总墙钟实测见 C3_RUN_MANIFEST.json；RSS 未测量。范围为单个固定文件与逐版本摘要依赖。
- 本证据包在推送前冻结，远端 CI 当时尚未执行；最终发布提交及对应 CI、评审和 Draft 状态以 PR #16 的发布记录/Checks 为准，并保存本地 C3_REMOTE_VALIDATION.json。不得用 C2 CI #180 代替新提交验收。

首轮 Linux 历史库存取超时、第二轮因外层环境禁止本地 file fetch 导致两项既有夹具失败，均保留在 C3_VALIDATION.json earlier_runs；最终通过使用新的 Linux 源码对象副本，禁用其全部 promisor，并仅允许测试夹具显式本地 file fetch，未修改公共服务。中间 Windows 失败日志另存且不当当前成功证据。

## 文件与复现

[实现](C3_IMPLEMENTATION.md)、[泛化与 holdout 盲审说明](C3_GENERALIZATION.md)、[真实源码调查](C3_REAL_SOURCE_SCAN.md)、[partial RFC](C3_PARTIAL_RFC_UPDATE.md)、[验证清单](C3_VALIDATION.json)、[限制](C3_LIMITATIONS.md)。JSON 原始证据与源码 fixture 均有 C3_ARTIFACT_HASHES.json；第三方原始源码、Git 对象库、依赖、数据库和大运行目录不提交。

```text
python -m unittest discover -s tests/detectors/ark_runtime -t . -v
python -m unittest discover -s tests -v
python -m compileall -q src tests
git diff --check
python research/experiments/ark_runtime/c3_20261017/replay.py --repo-dir <local-pinned-store> --output <new-output>
```

设置 OHSCANNER_ARK_REPO 指向已有固定对象库；依赖安装使用项目 requirements-web.txt，运行版本见验证 JSON。扫描不联网补对象。复现 holdout 使用 prepare_holdout.py，拒绝覆盖旧包，且必须满足冻结 Git 字节。

保留 C1/C2 历史报告、ID 和复核；保留原 UI dirty 工作区。当前代码变更仅 C 专属目录，另按 AGENTS 要求更新现行状态文档。负责人可独立 worktree 选择性验收，勿整体覆盖团队仓库。
