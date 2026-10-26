# Agent 调查原型交付记录（2026-10-17）

> 此文件记录队友各时点自报实验。负责人本次冻结集成的独立结果为 Python 834 项（829 pass / 5 skip），前端 16/16，真实静态浏览器验收通过；没有真实模型调用。旧 887/890/891 等数字属于含 C/D 的其他工作树，不能作为 main 集成验收。以 ../../integration/20261018-main/README.md 及 validation.json 为准。

- 分支：work/agent-llm-20261017
- 基线：1f8c7d31478f64cfd8586a46931b628844f96f64
- 范围：服务端 Agent adapter、operation API/worker 集成、调查面板表单、mocked tests、设计与状态文档。
- 未做：真实模型调用、密钥配置、PR/push/merge、运行服务重启、产品漏洞确认。

## 接口与安全边界

GET /api/v1/agent/status 返回配置是否完整、model/hostname 与缺失环境变量名，不包含密钥值。POST /api/v1/operations/agent-investigations 要求 source_submission_approved=true，且只接受已有完整报告中的一个 finding；mode 支持 single_shot（R1）与 tool_agent（R2）。入队计划绑定 report/commit/candidate/source hash、provider fingerprint 和外发预览 SHA-256。凭据只从 Worker 环境读取，不能放进 API body、SQLite plan、前端或 Git。

Agent 调用固定读取工具，范围是入队报告所绑定 commit/file。函数名与参数在服务端再次校验；不提供命令执行、联网搜索、任意路径、PoC 或写操作。R1 单次无工具调用，R2 最大工具步数 6；输入预算以完整 UTF-8 JSON 请求字节做调用前保守预检，Provider usage 到达后按实测输入 Token 结算；缺 usage 时保留预留；输出 usage 可用时按实耗释放预算、缺失时保守保留；输入/输出与 wall-time 有界；模型分诊建议为 likely_true_positive/likely_false_positive/needs_more_evidence/unknown；漏洞状态仍固定 candidate，validated_vulnerability=0。当前只实现 OpenAI Responses API 形状，费用记为 unknown。

Provider usage 不完整时总用量在 UI/导出中显示 unknown/null，保留已观测小计；输入预算使用 UTF-8 请求字节保守预检，输出预算基于已知 usage 结算，缺失 usage 时保留上限预留。

源码 excerpt 与证据被发到用户同意的 endpoint，也会作为操作结果/审计 trace 本地持久保存；部署方需先确认模型端数据保留政策，并配置本机存储访问控制/清理策略。

可选案例关联仅允许绑定已包含同一 job/candidate 的案例；案例 JSON/Markdown 导出纳入 Agent 分诊建议、证据引用、未知项、预算与来源绑定，并标注为非漏洞确认。未关联案例的调查仍可独立运行。

外发前提供固定候选上下文、目的地、工具可能追加读取的数据范围与预算预览；授权哈希绑定 provider/model、候选上下文、模式、工具策略和预算。预览变化后旧哈希会被服务端拒绝，Worker 再次验证哈希和预览版本。

## 验收

- python -m unittest tests.test_agent_workflow -q: 20 tests OK（fake provider；未产生网络请求）。
- python -m unittest discover -s tests -v: 2026-10-18 isolated-worktree full Python run: 887 tests, 880 passed, 7 skipped, 0 failed in 39.2 seconds; Agent-focused suite: 20 passed, including case binding, consent preview invalidation, and export assertions。This run supersedes the earlier snapshot count.
- Web 单测 16/16 通过；将最新前端源文件同步到临时 Windows 构建目录后 npm run build（含 tsc --noEmit）通过；临时构建产物没有复制回工作树。隔离服务 18777 的 health、agent/status、根页面 smoke 均返回 200，随后已关闭；模型配置为空。Work 浏览器自动化被设置禁用，未绕过，故未做真实浏览器 smoke。独立 OS Worker/child 子进程已验证 Provider 未配置时失败关闭，且以临时 fake Provider 完成成功路径并持久化结果/调用事件；真实 Provider 调用仍未验收。另有 fake-provider 纵向测试覆盖 API 入队、队列 claim、operation dispatcher、结果持久化与 API 取回。模型请求/响应哈希、token 用量和单次请求耗时已即时写入操作事件；畸形 usage/超预算响应和工具异常也会留下不含源码/密钥的失败事件，避免失败任务丢失已完成调用轨迹。模型请求期间取消会在后续工具执行前二次检查，取消后不再运行工具。
- 无手动浏览器验证；此代码没有部署到 localhost:18775。

## 2026-10-18 追加复核

- 当前工作树：work/agent-llm-20261017，HEAD 1f8c7d31478f64cfd8586a46931b628844f96f64，基于 origin/main e510c99c67f31ec6c73365f9ab749c79ca6ff0a1；实现仍为未提交的本地差异。最新 fetch 后 origin/main 未变。
- 更新后的 Agent 专项测试为 23 项；全仓 Python 回归重新执行为 890 项，883 passed、7 skipped、0 failed，耗时 69.203 秒。Web 单测 16/16、TypeScript/生产构建通过；git diff --check 通过。跳过项按现有仓库测试约束保留，不能当作通过。
- 在独立临时目录 /tmp/ohscanner-agent-run-20261018/data、回环端口 127.0.0.1:18777 实际启动当前工作树版本并完成 HTTP smoke：health、agent/status、agent/evaluation-summary、根页面均 HTTP 200。模型状态明确 configured=false；无密钥时创建调查返回 503，随后 operations 仍为空。测试服务已停止，未接触 localhost:18775 的正式/现有服务，也没有真实模型请求。
- 当前监听的 localhost:18775 仍报告 capabilities.agent=false，Agent 状态/评估汇总路由为 404；因此那一实例没有运行本交付版本。
- 协作范围尚未验收：config/collaboration/ownership.json 没有 Agent lane；改动含集成人所有的 API/operations 与 docs 路径。现有 scope checker lane 仅列 cpp/ipc/ui/platform，必须由集成人确定 Agent 文件所有权和基线后复跑；本记录不声称 scope pass。
- 本次没有生成产品漏洞结论、真实 Provider 效果数据或 R0/R1/R2 结果。历史段落中旧的全量测试计数和 20 项专项计数仅为当时快照，由本节记录覆盖；权威 docs/** 文档仍需集成负责人更新。
### 静态候选到 Agent 的受控纵向实验

- 可复现驱动：experiment_static_to_fake_llm.py。它复制仓库内 self-authored 的 positive_unsafe.cpp 到临时 Git 仓库，固定新生成的 commit，调用真实已注册 Detector ohscanner.cpp.unsafe_memory_call，验证得到 5 个静态 diagnostics；随后将第一条候选、源 blob/hash 和报告 hash 绑定到 Agent 外发预览，通过 fake Provider 执行 R1 单轮路径。脚本不访问网络，结束时删除临时仓库。
- 本次运行：临时 commit a7c138eb1a1cf1d430c7409dc4c1a7be54746c8e；candidate 955e28ba3d012c284be8d017474d055c948b5b5301a36388f2cc545172ad130e；分诊 needs_more_evidence；最终仍是 candidate，validated_vulnerability=0；单次模型调用，写入 3 条 operation events。
- 复跑命令：`cd /home/audit/ohscanner/worktrees/agent-llm-20261017 && PYTHONPATH=/home/audit/ohscanner/worktrees/agent-llm-20261017 /tmp/ohscanner-agent-venv/bin/python research/deliveries/agent/agent-investigation-20261017/experiment_static_to_fake_llm.py`。
- 这证明受控合成控制样例可从实际扫描器输出走到 Agent 调查函数；fake Provider 不代表 LLM 推理质量。该 fixture 不是 OpenHarmony 产品漏洞，5 条 diagnostics 也不能解释为 5 个独立漏洞。R0/R1/R2 产品效果、人工真值和真实模型调用仍未验证。
### 2026-10-18 R1/R2 配对评测流程

- Agent 调查请求现在可选填写格式受限的 experiment_id；空值不会被自动分组。评测 API 仅当同一实验 ID、模型、提示/工具版本、repository、固定 commit、candidate ID 都匹配且两侧都有人工评价时，生成 single_shot（R1）与 tool_agent（R2）配对汇总。
- Agent 面板新增实验批次字段和配对反馈表，显示每侧评价量、引文质量反馈和人工复核中位耗时。结果与 case 导出保留实验 ID，便于审计。
- 新测试覆盖 API 保存实验 ID、同候选 R1/R2 配对、不同实验批次隔离；全仓 Python 回归 891 项，884 passed、7 skipped、0 failed（46.417 秒）。Web 测试 16/16、TypeScript/生产构建通过；git diff --check 通过。
- 此表仍只汇总操作者自报意见，不能视为 R0 基线、盲审、随机对照、漏洞真值、Precision/Recall 或 R1/R2 因果收益。R0 静态人工基线仍未接入；真实模型尚未配置/调用，localhost:18775 也未部署此分支。