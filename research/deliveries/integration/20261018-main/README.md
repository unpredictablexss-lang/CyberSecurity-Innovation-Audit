# 负责人主线集成交付（2026-10-18）

B、UI、平台、负责人修复及受限 Agent 流程在独立分支 integration/main-reviewed-20261018 收口。来源清单见 sources.json；正式漏洞确认数仍为 0。先推 Draft PR，远端精确提交 CI 通过后，按用户本轮明确授权 Ready/合入 main；C/D 保持 Draft，不合并、不执行。

## 交付内容与审查修复

- 在 main@e510c99c67f31ec6c73365f9ab749c79ca6ff0a1 之上复用已验收联合基线 cdbb1e5aaecf35ed71a72e3cc57181ec96e62248，A 七项 C++、B IPC 0.9.3 / JS 0.3.1、UI V4.1/V8 比例、统一语言/事实规则规划，CLI/API/Worker 复用同一核心。NULL 仍仅显式选择。
- 固定源/规则/规划摘要，Worker 重算拒绝漂移；批量读取 Git blob 保持 OID/type/size/framing 校验与离线限制。报告保留 64MiB 上限。
- 完成扫描后全部候选进入幂等批次，不做 TopK 截断。该批次目前仅排队，普通/验证 Worker 均不领取；单候选模型调查须另行预览并同意外发。两者不能混称自动模型复核完成。
- 受限 Agent：R1 单轮、R2 固定版本只读工具；Provider 仅来自环境，HTTPS、不跟随重定向、无任意命令；输出引用须匹配原文/证据 ID，结果只作分诊建议。
- 修复 Agent 读取实际报告 git_tree 时错误使用 tree 字段；外发预览/结果现绑定真实 Git tree。
- 修复 Agent Git 历史/符号工具缺少离线环境；禁止 lazy fetch/replacement，查询固定 commit，脏工作树内容不参与工具结果。
- 预览授权加入实现文件摘要与核心指纹，源码/模型/预算/工具策略或实现变化均使旧授权失效；Worker 再验证，不因版本字符串没变而放行。
- Agent 评测表迁移 v4 纳入现有迁移锁和备份。模型已配置状态与自动批处理开关分开；配置模型不自动外发全量候选。
- 修复 UI reviewBacklog 未定义、候选上下文切换残留授权、普通单候选被强制要求 R0、排队批次取消入口与后端策略不一致。带实验 ID 的 R1/R2 仍须先保存同源 R0。自报反馈不是漏洞真值或 Precision/Recall。

## 实测

Python：834 项，829 passed / 5 skipped / 0 failures，53.865 秒。五项分别为缺失同范围历史重扫产物 1、禁止宿主机运行 Docker Harness 2、缺失可选历史源码 2；详见 validation.json。前端 16/16；TypeScript、生产构建、compileall、diff check 通过。fake Provider 成功路径与失败/预算/引用/授权漂移回归不代表真实 LLM 可用或有效。

真实面板任务 658a901bcb3843798e1a83b90aa21e2a，服务 http://localhost:18778，独立数据目录 /home/audit/ohscanner/parallel-20261018/main-review/data。浏览器实际完成规则预览→提交→结果→候选证据→调查表单。未配置 Provider 的提示、禁用按钮与 API 503 一致；无模型请求。截图本地保存于 Windows 工作区 验收记录/20261018-main-integration，不以旧图替代。

- 目标：openharmony/communication_dsoftbus，commit 9f922677e147b939d6db899bde181d609d64711b，tree 4b114179868d96c69eedc4520037552ddc3d65dd，scope core。
- 870 文件 / 8,969,000 字节；446 complete / 424 partial。7 个规则计划尝试、C/D 两项 blocked。
- 4 candidate / 0 confirmed；Worker 52.61s。全部候选源码 hash 已复核；CLI/Worker 的 scope、parse、coverage、snapshot、逐条 diagnostics 一致。
- 报告 SHA-256：187d8673badd82082afdd7edc9ae5ea493b68167d69ae128c63056ba15f0b003。
- 计划 SHA-256：2bcb19eac3bf7c1cf2adaebdd6c511eb029551b84c576858bf91771c3a319df9。
- 四类报告下载成功；复核队列 1 批次、4 候选、自动处理关闭。C/D 显式选择 HTTP 409，未创建扫描。
- 验收驱动首次把准入拒绝期望写成 HTTP 400，实际契约为 409；只修正验收驱动，未放宽产品门槛。

完整原始报告、日志、冻结快照与保护检查保存在 /home/audit/ohscanner/records/main-integration-20261018，不提交第三方源码、数据库、环境或密钥。这里的小型 JSON 是摘要，不是完整离线复现包。复现需准备对应本地 Git 对象、安装依赖并按 acceptance.json 固定 scope/规则/计划；不要用旧脚本显式选择所有元数据条目，因为包含未准入项。

## C/D 保持限制

本次 Git 树不含 detectors/ark_runtime、detectors/data 实现与 D 模型 JSON。只接准入说明和拒绝逻辑；不修改公共 partial 政策。C 元数据 upstream_head 指向已审 C2 固定版本 33242fbd，不代表 C3 已审；2026-10-18 已观察 GitHub #16 的 C3 HEAD 76f20af9e372189627f5117ed9a30815d1f49747，必须重新复审，不能沿用旧结论。D #17 HEAD c250bd57fa6670c21afa82a2e4684c0bc4c21298。

C 需生产适配器绑定目标/creator 依赖、精确版本与构建，并补 AST 完整或获单独审查的局部准入及依赖无污染证据；D 需精确模型选择/依赖及模型数据冻结、partial 准入证据、真实同名替身/受保护日志反例。两线还缺独立 holdout；产品入口、攻击者控制和 CIA 影响不能由研究探针或 Harness 代替。研究 1→0 与组件测试不升级为 confirmed。

## 旧 Draft 处理依据

| PR | 精确 HEAD | 本轮处置依据 |
|---|---|---|
| #8 | 86fbf9951967aaab879d24748a8231744d6977aa | 已是 main 基线祖先；旧 Draft 无需重复合代码 |
| #9 | d443f11bff917d475e4b1e3e92a0c1cbc2637a58 | 已是 main 基线祖先；平台后续通过 #13 接收 |
| #12 | 7e6ff537f23c1adde6cb82859e714d4025e0d375 | 已是 main 基线祖先；新联合交付包含其后续修复 |
| #11 | 54a4d980766ca9b8f2e3aaeccf3420bd98700399 | 旧 IPC 0.5.0 relay_guard 已由当前 0.9.3 更严格实现及回归覆盖；不向旧堆叠 base 合并 |
| #10 | aa79d57a3612c0bc5a04dac7af03c2a086dcddd8 | 旧 A 混合分支落后且冲突；当前 A 0.5.1 与 PoC 已选择性接收，但 87 个旧路径未在当前 HEAD 同名出现，含旧研究/benchmark/自动报告模块，未整包验收，不能声称全部已合入 |
| #16 / #17 | 上述 C/D HEAD | 继续 Draft，未合并、未 Ready |

#10 的剩余材料需要另拆研究交付、核验来源/报告门槛再审；不能为了减少 Draft 数量把旧审查器/自动报告及不一致 API 重新带回生产树。原分支和 Git 历史保留。PR 关闭/Ready/合并的最终实际状态以 GitHub 为准，本表是审查决策依据。

## 局限

这是静态工程集成验收，未执行真实 Provider、独立准确率评价、完整上游构建或 Docker/产品漏洞验证；零候选范围也不是安全证明。原负责人 / A/B / UI / 平台 / C/D / Agent 工作树未被 reset、clean、stash、覆盖、切分支或重启；18775 原服务与数据保留。其他会话在本轮自行产生的新改动未盲目追入此冻结交付。

## #10 直接合入的具体阻塞复核

审计精确 HEAD aa79d57a3612c0bc5a04dac7af03c2a086dcddd8 的 src/report/vulnerability_report.py，在内存直接调用其 renderer：只提供六项 true 布尔值、poc_state=stable_reproduced、patch_revalidation=passed，缺少仓库、commit、源码 binding、static_evidence，仍返回 report_status=reportable。输入和实际输出及原源码 SHA 见 pr10-evidence-gate-review.json。

该模块自称 renderer、信任上游提供的 gate；不能把它当作独立证据验证器接入当前系统。需要明确可信人工审批/不可变证据记录的来源并交叉核验 target/PoC/patch/report 身份，缺失或混用时拒绝升级。当前主线使用自己的证据门，此旧模块未迁入；不宣称 OH 产品漏洞或已利用缺陷。#10 保持 Draft，待拆分研究材料与验证适配后再审；不为了清空 Draft 而强合。
