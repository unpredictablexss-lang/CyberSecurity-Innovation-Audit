# B 线八仓成员函数指针语法归一化回归

日期：2026-10-19。实验绑定本地工作树 `work/ipc-20261017` 的当前工作内容；代码 HEAD 为 `2fee193dd2d8a1849ac31e0683baef8c9a59d9c3`，本次修正尚未提交或推送。

## 目的和改动

前一轮对 30 条候选做 pinned-source 复核时发现，AAFWK 的四个 stub 与 Pasteboard 的一个 stub 都因合法的成员函数指针派发 `(this->*handler)(...)` 被共享 Tree-sitter 索引标成 `partial`。B 的 IPC 内部分析已有按字节偏移保持不变的同类归一化，所以这些文件在内部语义分析可解析，但共享前端把它们继续作为 partial 传播。

本次将窄归一化提到 `src/parser/syntax_normalize.py`，并由共享 AST parser 和 B 的 IPC 分析共同调用。它只将 `this->*` 的不支持语法改写为等长空格；不解析函数指针目标、不推断调用者或控制流。源 Git blob、原始源码文本、行列偏移和 source SHA 均保持原样，检测器结果仍从 pinned original source 绑定。

## 同一八仓固定对象前后结果

| 组件 | 固定 commit | complete / partial / not_run（前） | complete / partial / not_run（后） | 候选前→后 | 候选身份变化 |
|---|---|---:|---:|---:|---:|
| aafwk_standard | `834a566b1372268c7bbb0c40362322f812ca6efc` | 1222 / 531 / 18 | 1246 / 507 / 18 | 15→15 | 0 |
| applications_contacts_data | `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` | 199 / 19 / 142 | 199 / 19 / 142 | 4→4 | 0 |
| communication_netmanager_ext | `8c35917b7e2f152813b13a20530a8452cf73d938` | 434 / 198 / 22 | 441 / 191 / 22 | 0→0 | 0 |
| distributeddatamgr_relational_store | `42f13ea84e2f90ed511a2bd4aa5be14c5996eba8` | 789 / 376 / 185 | 790 / 375 / 185 | 0→0 | 0 |
| graphic_standard | `a73af6bd3bac599b9359cba10ca7b5f82a02d5d9` | 965 / 223 / 4 | 969 / 219 / 4 | 8→8 | 0 |
| miscservices_pasteboard | `dd22c7cb5e5f207a6c38c50f45b7369ee8575840` | 57 / 10 / 1 | 59 / 8 / 1 | 2→2 | 0 |
| multimedia_histreamer | `847aafa3dc32bcf92eb8a2d2277b8d34bff98362` | 345 / 231 / 0 | 346 / 230 / 0 | 0→0 | 0 |
| security_deviceauth | `2cf21e46f43c63857c40a79b004eda14f79b04c2` | 291 / 145 / 0 | 291 / 145 / 0 | 1→1 | 0 |
| **合计** | — | **4302 / 1733 / 372** | **4341 / 1694 / 372** | **30→30** | **0** |

身份比较键为 `(file, line, rule_id, symbol, source_sha256)`。八仓固定 commit、tree 与目标 scope 没有变化；候选增加 0、移除 0。新增完整解析 39 个文件，partial 减少 39 个，not_run 未变。

## 对候选 partial 的影响

原逐条清单的 30 条观察中，17 条从 partial 变为 complete，涉及 5 个文件：AAFWK 4 个、Pasteboard 1 个。另有 2 条 Contacts 观察仍来自 `poster_call_stub.cpp` partial 文件，保持 unknown；不把它们改判为误报或安全。完整清单见 `../20261019-eight-component-candidate-triage-v0.12.12/candidate_triage.csv`，原有 triage 包保持不变以留存基线状态。

## 验证与限制

- 新增语法归一化单测通过；全量 `python -m unittest discover -s tests -q`：**727 tests OK，36 skipped**。
- 八仓生产 CLI `ohscan-run` 全部完成，状态均为 `completed_with_limitations`；候选集合逐条一致。
- 所有报告的 `validated_vulnerability` 仍为 0；没有新增漏洞确认，也没有证明 Precision/Recall。
- 该改动仅覆盖两类已观察到的 `this->*` 拼写。其它 partial 语法、宏/编译上下文、372 个 not_run 文件和跨文件语义仍未解决。Contacts partial 未被本规则改善。
- 本实验不是独立 holdout，也不代表所有 OpenHarmony 仓库的 parser coverage 都改善相同比例。

## 产物

- 每仓生产 CLI JSON/Markdown、stdout/stderr 日志：本目录 `*_standard.json/.md/.log` 等文件。
- 每仓前后统计、完整 commit/tree 和身份差异：`manifest.json`。
- 产物校验：`sha256sum -c SHA256SUMS`。
- 全量源码和原始候选复核仍见八仓当前扫描包 `../20261019-eight-component-current-v0.12.12/`。
