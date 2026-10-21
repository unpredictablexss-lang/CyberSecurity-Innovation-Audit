# C 线独立复验：receiver_guard alias 与 registered source-bound profile

日期：2026-10-20  
复验者：C 线独立测试  
生产代码修改：无

## 1. receiver_guard alias/rebinding

复验对象：`2d79560cad45db75bb1b0c6d0677200294e17d10`（完整提交）  
基线：`71950e65f46e204e6aec21210c8de73fa4f2a1a9`  
测试：`tests.detectors.ark_runtime.test_receiver_guard`

命令（两个提交均使用 `D:\openHarmonyScanner\.venv-c-line\Scripts\python.exe`，分别在临时 detached worktree 中运行）：

```powershell
python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v
```

结果：

| 快照 | 通过 | 跳过 | 失败 | 备注 |
|---|---:|---:|---:|---|
| 基线 `71950e65f46e204e6aec21210c8de73fa4f2a1a9` | 11 | 1 | 0 | 官方历史 Git 未通过 `OHSCANNER_ARK_OFFICIAL_GIT` 提供 |
| 开发 `2d79560cad45db75bb1b0c6d0677200294e17d10` | 17 | 1 | 0 | 6 个 alias/rebinding 场景新增通过 |

开发提交新增并实际通过的控制包括：

- 同源 `saved = input` alias 保护；同源 type token resampling；稳定 alias 保存后 receiver 重绑定再恢复；
- alias 重绑定到其他对象后保留 candidate；复杂条件重绑定保留 unknown；
- reference alias 写入保留 unknown；receiver 在 guard 后重绑定保留 candidate；
- 重新绑定后重新取 type token 可以重新建立 matched；否定/复合谓词仍不提供安全保护。

基线与开发提交的一个行为差异是 `other_object_guard_does_not_protect_receiver`：基线期望 `unknown`，开发提交期望并实际返回 `candidate`。该变化是针对明确的不同 receiver sink 保留候选，属于更保守的候选保留，不是将未知变成 safe；没有发现静默误报抑制或 fixed→matched 回归。

官方历史 pair 测试没有执行，原因是测试明确要求本地 pinned official Ark Git store，当前环境未提供；未使用隐式 fetch 或合成历史源替代。

## 2. registered source-bound parent/fixed profile

报告来自最终代码快照中的 `research/evidence/cpp/a_final_closeout_20261020/`。每个 JSON 均包含完整 repository、40 位 commit、Git tree、snapshot SHA-256、source blob OID、source SHA-256、profile 和 detector version。以下为逐项核对结果：

| 案例 | parent/fixed | source | detector | parse | candidates |
|---|---|---|---|---|---:|
| CVE-2025-0587 | parent `cae11f121c030a90ba41d8e4d866f91292f25892` / fixed `5aa9c035e98911ec7ed28065a2138c2709792a42` | `ecmascript/base/atomic_helper.cpp`，两侧均 complete；blob 与 SHA 已记录 | `ohscanner.cpp.integer_bounds@0.2.1` | complete / complete | 1 / 0 |
| CVE-2025-23420 | parent `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` / fixed `1b23531531e768398682582969c2a9f17e72cafe` | `ecmascript/js_array.cpp`，两侧均 complete；blob 与 SHA 已记录 | `ohscanner.cpp.bounds@0.3.0` | complete / complete | 5 / 0 |
| CVE-2025-23420 同源安全对照 | parent commit `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `ecmascript/base/array_helper.cpp`，complete；独立 blob/SHA | `ohscanner.cpp.bounds@0.3.0` | complete | 0 |

对应 JSON：

- `cve2025-0587-vulnerable.json` / `cve2025-0587-fixed.json`
- `cve2025-23420-vulnerable.json` / `cve2025-23420-fixed.json`
- `cve2025-23420-safe-control.json`

运行状态均为 `completed`；候选差分为 1→0、5→0，安全对照为 0。该结果证明 source-bound CLI 的候选差分和解析完整性；不证明产品入口、构建宏、可达性、攻击者控制或运行影响。产品级结论仍应保持 `PARTIAL-BLOCK`/`unknown`。

profile replay 没有把 partial/blocked 伪装为 safe。历史 profile 中含有 partial source 的控制仍按 `completed_with_limitations`、`partial` 或 `blocked` 解释，并保留 candidate obligations；本次没有把它们升级为 fixed 或 confirmed。

复验限制：当前环境没有独立产品 build profile，也没有官方 Ark 历史 Git store，因此官方历史 pair 运行保持 skipped；source-bound JSON 的固定 blob/tree/SHA 是可复验的静态证据，不能替代产品运行证据。
