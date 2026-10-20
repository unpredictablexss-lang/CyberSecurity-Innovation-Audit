# B 线八仓候选逐条复核阶段收口

日期：2026-10-19
工作树：`/home/audit/ohscanner/worktrees/parallel-ipc-20261017`
分支：`work/ipc-20261017`
HEAD：`2fee193dd2d8a1849ac31e0683baef8c9a59d9c3`（本地代码仍有未提交改动）
对照来源：G 盘 `ABCD线实测分析与改进建议_20261018.md` 与 `B线IPC八仓复测_20261018/`。

## 当前结论

G 盘建议优先把保留候选固定 commit/blob/hash 后逐条分类，并优先解决 partial 解析缺口。本轮按当前 v0.12.12 八仓固定复测包完成了这轮候选清点和源码复核索引：

- G 盘旧报告有 **31 条**观察；当前固定八仓包有 **30 条**。以 `(repository, file, line, rule_id, source_sha256)` 比较，**30 条完全一致、当前没有新增，旧快照多出的 1 条为 `ConnectCallbackStub` AUTH-01**。
- 该旧候选绑定 `openharmony/aafwk_standard@834a566b1372268c7bbb0c40362322f812ca6efc`，tree `c3744c8c230573a4bcdb76bf49493a1ea61c72d1`。固定源码 `connect_callback_stub.cpp:59-63` 在派发前比较 `IConnectCallback::GetDescriptor()` 并在不匹配时返回；接口声明和 Proxy 都使用同一 descriptor。它不满足“缺少 descriptor 边界”的原候选主张，当前规则不再报出是合理收敛。未把它当作一个漏洞，也没有删除旧报告。
- 当前 30 条观察都已关联到逐条源码复核 Markdown；其中有 2 条规则观察共享一个根因的情况，所以 **30 条 finding 不是 30 个独立根因**。
- 成员函数指针语法归一化后，八仓总解析从 `complete/partial/not_run = 4302/1733/372` 变为 `4341/1694/372`，候选身份差分为 `0`。30 条观察中，17 条所在文件由 partial 转 complete；另有 2 条 Contacts Poster 观察仍为 partial，保持 unknown。
- 当前 candidate key 的根因字段给出 **28 个 root cluster**：两个重复组分别是 RSRenderServiceConnection 的同入口 AUTH-01/CAP-01，以及 VSync fall-through 的同一入口 AUTH-01/CAP-01。产品界面仍应保留各规则观察，再以 cluster 作为人工复核视图，不能把 occurrence 与根因数混报。
- 本地全量测试在新增真实 `token.compare(Interface::GetDescriptor()) != 0` 回归后为 **728 tests OK，36 skipped**。所有 B 静态扫描报告的 `validated_vulnerability` 仍为 **0**。

## 逐条复核材料

规范身份与候选原始输出仍以 `20261019-eight-component-candidate-triage-v0.12.12/candidate_triage.csv` 和扫描 JSON/manifest 为准；解析状态前后以 `20261019-eight-component-member-pointer-normalization-v0.12.12/candidate_parse_status.csv` 为准。以下报告提供人工源码判断与证据边界：

- AAFWK AUTH-02 跨 TU：`20261019-aafwk-auth02-cross-tu-policy-review.md`
- AAFWK AppMgr CAP-01：`20261019-aafwk-appmgr-cap01-cross-tu-review.md`
- AAFWK 其他能力/策略：`20261019-aafwk-capability-policy-review.md`
- AAFWK 最后四条完整解析观察：`20261019-aafwk-final-four-complete-review.md`
- Contacts Poster callback 与跨组件信任边界：`20261019-contacts-poster-callback-trust-boundary.md`
- Contacts include 尾随空格解析缺口：`20261019-contacts-preprocessor-whitespace-parser-gap.md`
- Pasteboard AUTH-02：`20261019-pasteboard-auth02-complete-review.md`
- Graphic VSync fall-through 根因组：`20261019-graphic-standard-vsync-fallthrough-review.md`
- Graphic 与 DeviceAuth 剩余观察：`20261019-graphic-deviceauth-final-candidate-review.md`

## CVE 回归口径

[ B 线已披露 CVE 集成清单](20261019-B线已披露CVE集成清单.md)按固定 Git 漏洞端/修复端记录了 **14 个去重 CVE、16 组范围回放**。这些是开发/回归样本，不是独立 holdout；当前检测器 `validated_vulnerability=0`。CVE 的外部披露确认与 OHScanner 是否确认一个 finding 是两套状态，不能互相替代。

## 相对 G 盘改进建议的进度

| 建议项 | 当前进度 | 仍未完成 |
|---|---|---|
| 固定来源并逐条分类候选 | **本批已完成源码绑定与复核索引**；旧 31/current 30 的单条差异已有源码原因 | 复核报告仍是分散 Markdown；后续可把索引整合进面板/机器可读审查记录 |
| 按 parser error 形状改善覆盖 | **已修一类**：`this->*` 等长归一化；同一八仓候选集合不变 | Contacts 两条 `#include` 行尾空格问题属于共享 Parser；B lane 不应自行改共享 Parser。需 owner 修复后按相同 SHA/scope 重跑 |
| 根因关联 | **人工层面 28 clusters / 30 observations**，重复规则观察已指出 | 还未在产品里提供可点击的 cluster 与每条 occurrence 证据 |
| 零命中规则覆盖 | 已有规则级设计控制审计 `20261019-eight-component-rule-coverage-audit/` | 19 条规则中 16 条在八仓为零候选；逐规则适用文件、语法支持率和评估文件数尚未由生产 sidecar 实测 |
| 独立 holdout | **尚未完成** | 需要未参与规则开发的组件、按根因切分的冻结样本和独立盲审；本批人工审查及 14 个 CVE 均不能充当 holdout |
| 产品/运行时证据 | 本轮未执行 | 暂无设备构建、受控 PoC/Harness 或产品可达性证明；confirmed 保持 0 |

## 下一步优先级

1. 让共享 Parser owner 处理 Contacts 的精确 `#include` 尾随空格形状，加入正反例，再用同一八仓 commit/tree/scope 重跑；候选变化逐条核对，不能只看 complete 数上升。
2. 指派未参与 B 规则开发的队友/评审人冻结独立组件 holdout，先按 root cause 做训练与评估隔离，复核阶段不向评审人暴露 scanner 结论；公布 precision/recall 前先报告样本数、标签一致性和 unknown。
3. 由公共平台 owner 决定 per-rule coverage sidecar 契约；在其落地前，面板应将零候选标为“覆盖未知”，不能展示成已扫描安全。
4. 对 `unresolved external dependency` 与 `plausible` 的少量高价值候选逐个补 SA/权限策略和设备验证；不得仅因候选来自披露 CVE 或源码有 suspicious pattern 就自动 confirmed。

本文件仅记录本地验证状态和复核索引。检测器工作树已有未提交变更；本轮没有 commit、没有 push，没有改 A 线、队友 B 源仓或 OpenHarmony 目标源码。

## 2026-10-20 收口补记

本补记依据当前集成工作树直接复跑的测试与已归档固定对象报告。定向家族 fixture matrix 为 13 tests OK；全量 unittest discover 为 736 tests，36 skipped，0 failed；git diff --check 通过。新增六条精确 safe controls 后，19/19 条规则至少各有一条 fixed 和 safe 设计对照。控制矩阵只证明这些固定样例的预期行为，不是独立 holdout。

八仓固定快照回归仍为 30 条候选观察，候选键集合未变；complete/partial/not_run 为 4,341/1,694/372。逐条源码复核为 30 observations、28 root-cause clusters；两条 Contacts Poster AUTH-01 保持 partial/unknown。已记录的 14 个 CVE 固定回归样本及所有限制见 20261019-B线已披露CVE集成清单.md。候选 validated_vulnerability 仍为 0。

本次准备提交时，B 工作树里另有四个共享所有权路径的未提交改动：项目状态文档、src/parser/ast.py、新增共享 parser normalizer 与 tests/test_ast.py。它们不进入 B detector commit；共享 parser 改动与 B detector 改动分别提交。仍未完成的工作是：真实组件的 rule-specific applicability/evaluated sidecar、独立盲审 holdout、两条 Contacts partial 的共享 Parser 修复与八仓重跑，以及任何产品构建/动态影响验证。零命中继续是 coverage unknown，不能表述为安全。