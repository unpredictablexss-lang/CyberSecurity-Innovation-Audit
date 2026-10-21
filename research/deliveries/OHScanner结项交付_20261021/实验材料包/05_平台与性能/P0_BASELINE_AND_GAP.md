# 智能安全审计落地与差距复核

Date: 2026-10-20

## 审查基线

- Worktree: `/home/audit/ohscanner/worktrees/ohscanner-8765-integrated-20261019`
- Branch: `integration/ohscanner-8765-20261019`
- HEAD: `631901a90513748d7d72e8c15fa9f9f131132259`（本轮代码和文档仍是未提交改动）
- 本轮保留了此前负责人的集成改动；没有修改 A/B 或其他队友 worktree，没有 push、合并或改变 PR 状态。
- 本文记录代码和本机接口验收，不代表真实 Provider 调用、准确率评估或产品漏洞确认。

## 需求实现状态

| 阶段 | 当前结果 | 尚存限制 |
|---|---|---|
| P0 基线与追踪 | 已核对固定 checkout、API/Store/Worker/Agent 调用链、当前服务和原有数据目录。 | HEAD 是本地验收基线，不是本轮改动的提交。 |
| P1 源码根目录 | 复用多根目录注册、发现、仓库登记和固定 Git 版本验证；普通仓库列表不返回服务器路径；本轮隔离浏览器走通同名仓库发现、登记和审计选择。 | 原方案 P1 验收项已覆盖；官方清单/镜像身份认证属于额外可信来源能力，若需要需另行定义权威 catalog 与信任根。 |
| P2 双阶段调度 | 静态扫描与 Agent 研判进度分别返回；R1/R2 条件调度、授权、撤销和 Worker 幂等恢复已接入。新增停止单项研判与整项审计取消，持久标记阻止取消后自动重排。 | 没有真实 Provider 调用；并发与重启边界由合成集成测试验证。 |
| P3 外发授权 | 用户可在新任务中明确同意最多 5 个 R1 候选；任务授权绑定固定源码、计划/流程、Provider/model、策略版本、候选预算、USD 工作台费用上限与 nonce，实际发出前重新校验。只接受有已复核费率卡且最坏预算估算不超上限的自动批次。未授权时只做静态扫描。 | OHScanner 无法控制 Provider 的真实账单，`hard_spend_cap=false` 仍表示外部账单不是硬上限；未知费率的模型不能使用任务级自动批量研判。没有执行真实 Provider 请求。 |
| P4 风险分层 | `smart_audit.py` 按静态证据、固定源码绑定与完整人工 R0 obligation review 计算风险层级。模型置信度不参与提级；人工 refuted 只降低优先级，不表示安全。 | `high_confidence_candidate` 仍是 candidate；层级不表示漏洞确认。 |
| P5 报告与覆盖 | /scans/{id}/risks、/coverage、/reports/snapshots 及 /overview/risks 提供风险、覆盖、双阶段进度与首页队列；overview 支持有界筛选/分页；SQLite schema v9 持久保存快照及研判取消状态。 | 原始静态报告仍独立；扫描不完整时只能报告对应覆盖限制。 |
| P6 控制实验 | 仍未完成。 | 需要预先冻结的独立标注集、独立评价人和单独批准；不可由 Agent 自评推导 precision/recall。 |

## 执行边界

1. `api.py` 固定仓库 commit/tree、范围、检测器和静态预算，并分别校验 plan 与 workflow 摘要。
2. `Store` 保存不可变扫描任务和 task-level 外发授权；现有报告/案例库继续作为唯一静态证据源。
3. `Worker` 执行静态扫描并验证报告绑定，随后最多为已授权候选创建有界 R1 队列。
4. `OperationWorker` 只向 Agent 调查任务提供 Provider 配置；模型结果单独存储，不能改变静态发现或 `validated_vulnerability`。
5. 风险层级由服务端确定规则计算；报告快照写入风险、覆盖、研判状态、证据摘要和已有运行时验证门，不复制 Provider 密钥。

## 验收记录

- Python 全量回归：1335 项运行，1327 通过、8 跳过、0 失败；Owner 集成与并发迁移专项 21/21。 `compileall` 与 `git diff --check` 通过。
- Workbench Web：Node 测试 43/43；TypeScript 检查和 Linux Node 22 生产构建通过。
- 8765 运行态：健康接口返回 `ok`、Worker 正在运行、配置 6 个扫描根；OpenAPI 已含 `GET /api/v1/overview/risks`、`POST /api/v1/scans/{key}/triage/cancel`、`POST /api/v1/scans/{key}/cancel` 和候选详情接口。SQLite schema v9 已生效，迁移前备份存在。3 个历史扫描均终态；旧 `candidate_review_batch` 队列指针仍 queued 且不会被 Worker claim，没有运行中的扫描或操作。
- 浏览器已验收首页和任务详情：3 份报告对应 1 条待进一步验证候选、1 条未完成模型研判、0 条人工确认。候选源码不属于授权根目录时，详情接口返回 `source_status=unavailable`，仍保留 4 项 unknown 证据义务；页面说明访问限制并禁止无固定源码引用的复核/模型研判。当前规则说明、核查项标签、unknown 状态有人类可读的中文提示，原始文本与 JSON 仍可查看。
- 本轮没有创建审计任务、真实 Provider 调用、源码外发、动态 PoC、Docker 验证或全量仓库扫描。P6 独立标注真值集与盲评仍未完成；`validated_vulnerability=0`。

## 合并判断与后续工作

2026-10-20 后续本地改动将风险中心改成跨审计、可筛选和分页的候选队列，并为扫描、报告、研判增加独立顶层状态。全量 Python 回归与隔离 SQLite 快照服务验证通过；18776 In-App Browser 的可访问树确认总览摘要、带筛选深链、候选行和详情三阶段状态/unknown 义务。桌面窗口截图工具超时，因此未做像素级截图审查。8765 主服务没有重载，不能把隔离验收称为 8765 运行态验收。代码仍未提交，当前应保留为待负责人代码审阅状态，不据此标 Ready 或合并。

后续限制包括 Provider 账单硬上限和需要独立冻结真值及评价人的 P6 盲评。官方仓库身份认证是额外可信来源能力，不属于总方案 P1 的验收范围。漏洞结论统一按 candidate/unknown；扫描器候选、模型输出和组件 Harness 都不能替代产品级确认。

## 2026-10-20 隔离浏览器端到端补充

修复版本在 18776 临时服务完成同名仓库登记、固定源计划、静态扫描、覆盖/候选/证据查看与报告快照完整流程。此前 Hash 对 null 调用 .slice() 导致详情白屏；当前缺失值显示“未知”且不可复制，新增 Web 单测 2 项。任务 b2348bcc135747c4ab4048d8c4b900a8 使用合成夹具，结果 4 条原始 candidate、3 组、3 个文件 complete/1 个 partial、0 confirmed。未配置模型，4 条都未研判。

快照 e5ff6ea6ccbd64fde424835ba071e864 JSON/Markdown 下载字节 SHA-256 同时匹配数据库摘要和响应头；重复生成返回相同 ID、记录数仍为 1。回归为 Python 1342 通过/8 跳过、Web 46/46、TypeScript --noEmit、compileall、git diff --check 通过。隔离构建和页面重载成功。没有调用 Provider、动态验证或重载 8765；所有结果继续是 candidate/unknown，validated_vulnerability=0。

## 2026-10-20 浏览器端验收与状态文案收尾

在 18776 隔离服务和真实固定组件任务 `e8c3bf72808a4313bf6a76c94d52ad01` 上复验前后端联动。详情页显示固定 commit/tree、123 个源码文件、185 条原始候选、52 个浏览分组、0 条人工确认；智能研判等待本次外发授权，Provider 未配置。`GET /scans/{id}`、`/risks`、`/coverage`、`/triage`、`/findings` 均返回 200。没有重新扫描、授权模型调用或向外发送源码。

根据页面复核补齐状态文案：风险建议句不再出现中英文标点拼接；风险/解析缺失值用“未知”；Agent 源码证据门通过与产品级漏洞确认分开表达；解析覆盖数字与候选数量分栏；聚类明确只按固定身份字段减少重复浏览，不代表根因；用户可见的覆盖说明、Token 字段和 Agent 统计缺失值统一使用中文。浏览器在刷新后的第二次数据读取完成后显示完整候选，首次加载时出现的“状态未知”是尚未加载完的过渡状态，接口返回数据正常。

验证：Python 全量回归 1342 项通过、8 项跳过；Web 测试 50/50；TypeScript `--noEmit`、`compileall`、`git diff --check` 通过；Linux esbuild 生产资源构建成功。前端改动后的 Web、TypeScript 和 diff 检查再次通过。18776 的隔离进程使用临时应用副本和 `/tmp/ohscanner-product-audit-20261020-real` 数据目录；8765 主服务未重启。

漏洞证据边界未变：185 条都是待复核候选，`validated_vulnerability=0`；没有动态验证或独立真值评估，P6 未完成。全部改动仍是本地未提交内容；未 push、未合并、未更改 PR 状态，也未修改 A/B 队友目录。

## 2026-10-20 风险队列可用性补充

风险中心按检测器展示计数并支持精确筛选；仓库/风险层级/研判状态/搜索条件也与 hash URL 同步，刷新、分享链接和返回操作可以保留队列视图。浏览器在隔离副本中从真实固定报告读取 185 条候选观测，按 ohscanner.cpp.integer_bounds 筛选后得到 1 条，刷新后匹配条件仍在。该筛选只重排候选观察范围，不改变风险判断或人工确认状态。

另修正两处容易造成误解/暴露的行为：扫描成功后不再生成 Worker 永不执行的旧候选批次占位项；显式授权的任务级 Agent 研判路径保留。普通仓库列表 API 不返回服务端绝对路径，路径只由设置页的管理接口读取。Python 1342 passed/8 skipped，Web 51/51，TypeScript、compileall、diff check 均通过。18776 隔离副本已用新 bundle 和后端模块验收；未触碰 8765、A/B 队友目录或真实 Provider。漏洞状态继续是 candidate/unknown，validated_vulnerability=0。


## 2026-10-20 任务级 USD 费用上限与加载状态验收

- 前端预览与创建任务共用授权字段；上限、候选/R1/R2 名额、Provider/model、固定费率卡摘要绑定进 workflow 和授权 manifest。扫描提交及 Agent 发出前重验，费率未知、费用估值超限或授权字段漂移时阻止自动批次，静态扫描保持可用。
- 18777 临时服务用户流程：固定合成仓库/Commit，预算 USD 0.10 时预览估算 USD 0.03758400 和官方 CNY 参考价 0.25920000；降至 USD 0.01 后预览明确拒绝授权。关闭自动研判后成功创建静态任务 60e7a5c3dd754eeab5d06a2b89847c9b，Worker 在隔离数据库中完成扫描：4 个完整解析文件、2 条 candidate、报告 SHA-256 0a7a9b379de2f0f8d74b0ba6aa9d05cf691580e9ffe2277e86f705fa23423105、人工确认 0。页面显示候选未研判并等待任务授权，不表示安全。
- 浏览器首轮读取尚未返回三阶段接口时曾暂显“等待报告/状态未知”。增加读取中状态文案后复验首屏显示“正在读取报告状态/正在读取研判状态”，数据返回后显示“已生成/等待本次任务授权”；这是加载延迟状态，不是服务端结果。
- Python 全量 1,345 项通过、8 项跳过；授权定向 138 项通过；Web 56/56；TypeScript、隔离生产 bundle、compileall、git diff --check 通过。真实 Provider 未调用、动态验证未执行、漏洞确认数为 0。所有漏洞结论保持 candidate/unknown。


## 2026-10-20 8765 部署后状态

8765 由原有集成 worktree 进程组正常重启，API、扫描 Worker、操作 Worker 与验证 Worker 均启动。SQLite 在线备份 /tmp/ohscanner-8765-pre-p3-costcap-20261020.sqlite3 的完整性检查为 ok。新 health 返回 status=ok、target_root_count=6、agent-egress-preview-0.6.0、worker_running=true；浏览器确认预算控件已出现在真实 8765 新审计页，复位为默认不授权且未提交。历史 3 个扫描均仍 completed_with_limitations；旧版 candidate_review_batch 5a8a0bcc0bc14372924b7e9f8cc9338c 仍 queued，当前 Worker 明确排除该占位批次。没有在 8765 创建扫描、进行 Provider 请求或更改漏洞状态。

## 2026-10-20 预算输入精度复验

将新建审计费用输入改为保留用户输入精度，默认显示 USD 0.10，并以同一个前端 helper 校验服务端接受的正数、最多 6 位整数与 8 位小数。节点回归 56/56，TypeScript 和生产构建通过；8765 浏览器复载确认新格式，恢复为默认未授权且没有提交任务。

## 2026-10-20 全量回归与固定 OpenHarmony 源码 E2E

重新运行当前集成工作树的完整验收：Python `unittest discover -s tests -q` 为 1,345 项、0 失败、8 跳过；Web Node 测试 56/56；`npm run build` 的 TypeScript 检查与生产构建通过；`compileall` 和 `git diff --check` 通过。

另用隔离数据目录运行 `scripts.verify_workbench`，目标为只读本地固定源码 `openharmony/commonlibrary_c_utils@b807d3dadb7dbb7639fe85b3a5f72da18d318da2`，提交树 SHA-1 `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`。API→Worker→保存报告→逐条固定源码核验→CLI 对照成功，结果任务 `d77ffb1a7b0c4f7e9dd36db555de4817`、数据目录 `/tmp/ohscanner-verify-p1-p5-20261020-a7`、123 文件、94 complete/29 partial、185 条原始 candidate、185 条候选来源核验、0 条 confirmed、`validated_vulnerability=0`。扫描为 `completed_with_limitations`；报告 SHA-256 为 `a6c752ab68d364d0f7c87d12a2319148dd39a545814e169558542162cca7b651`。本次没有真实 Provider、源码外发、动态 PoC 或准确率评估；不能据此把候选写成产品漏洞确认。

测试在独立目录运行，8765 的任务和数据库未参与。P6 仍需独立冻结真值与盲评人员，当前状态保持未完成。

## 2026-10-20 新建审计默认版本与仓库检索

新建审计选中已核验仓库后，页面等待该仓库的版本列表加载完成，再自动填入服务端根据 `origin/HEAD`（本地镜像缺少该引用时回退到 `HEAD`）识别的默认分支；版本列表同时标出默认分支。手动填写或选择的版本不会被覆盖，切换仓库会清空旧版本并等待新列表。

设置 → 仓库与源码管理新增仓库搜索，可按名称、来源根目录别名、管理员可见路径、可用状态和不可用原因筛选，并显示“命中数 / 登记总数”；无匹配时给出修改或清空关键词提示。

用户流程在隔离服务 `127.0.0.1:18779`、临时数据库 `/tmp/ohscanner-smart-audit-ux-20261020/data` 和只读本机样本 `openharmony/commonlibrary_c_utils` 上复核：仓库选择后显示 `refs/remotes/origin/master`，计划预览固定到 commit `3bdc11e00e7bf6e577cee300ad51045ca9958efd`、tree `3ae2784218ab9cb06982d4660e37bababa06055e`，识别 122 个 C++ 文件、27 个解析不完整文件，规则计划为 7 项尝试、1 项未准入；设置页搜索 `commonlibrary` 显示 1/1，搜索不存在的仓库名显示 0/1 和空结果文案。只预览计划，没有开始扫描、创建审计任务或调用 Provider；8765 服务和正式数据库未参与。

回归：Python 全量 1,346 项、0 失败、8 跳过；Web Node 64/64；TypeScript `--noEmit`、生产构建、`compileall`、`git diff --check` 通过。测试仅验证工作流和候选展示，不能推导漏洞准确率；候选与确认状态未改变，`validated_vulnerability=0`。P6 独立冻结真值、独立评价人及真实对照实验仍未完成。

## 2026-10-20 调用预算失败边界与确认弹窗验收

隔离固定源码 E2E 中，单个 Agent 请求的保守 UTF-8 字节上界为 12,497，而任务剩余输入预算为 24,000；如果继续保留一次完整重试预算，预算预检会在首个 Provider 调用前误拒绝。现在只有在一次请求可容纳、但可选重试不可容纳时才将本次重试数降为 0，并持久化 `agent_retry_budget_reduced` 事件；如果首请求本身超限仍 fail closed。本次本地假 Provider 实际收到一次候选复核，HTTP attempts=1，未放宽总 Token/字节、输出、时长、候选数或费用上限。

复核结果 `needs_more_evidence`、7 项义务未决、0 条支持性主张；`vulnerability_state=candidate`、`validated_vulnerability=0`。候选源码仅发送到隔离链路中的 loopback 假 Provider，未调用真实 Provider，不能把假 Harness 成功解释为模型正确或产品漏洞确认。设置页和任务表单的无源码连接检查确认框在修复后均可见，点取消后未发送探测请求。

前端 64/64，TypeScript 检查与生产构建通过；Python 全量 1,348 项通过、8 项跳过，`compileall` 与 `git diff --check` 通过。测试 API/Worker 在端口 18780；生产 8765 仅做健康检查，未重载或写入任务。