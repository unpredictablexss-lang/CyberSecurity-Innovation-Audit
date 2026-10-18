# B 线披露修复对回归：caller-class 摘要（2026-10-19）

## 结论

本轮在 B 线实现了一项窄而可复用的语义改进：分析器能从本地 helper 的真实实现识别“调用者 full token 是系统应用”，并把该 caller-class 事实传过布尔 helper。它要求看到 `IPCSkeleton::GetCallingFullTokenID()` 的来源，并由 `TokenIdKit::IsSystemAppByFullTokenID()` 判定；caller UID、普通 TokenID、first-token 都不会混作同一身份域。

CVE-2025-26693 固定版本从 3 条候选降到 1 条：目标函数上的 AUTH-02 和 AUTH-03 消失；剩余 AUTH-01 指向同文件的接口身份未知，与该漏洞修复点不同。两侧解析均为 partial，DetectorRun 为 blocked，因此这里只能称披露修复对的静态差分。

## 代码变化

- 区分 `GetCallingFullTokenID` 的 caller 身份标签；发生 identity reset 后不会把它当成原调用者。
- 仅在 full-token 输入传给精确的 TokenIdKit API 时产生 `system_app` 类别事实。
- 本地 helper 的 caller-class 返回值可跨单结果和多结果布尔摘要传播，并始终与权限 `auth` 事实分开。
- 检测器版本更新至 `0.8.3`，解释模型为 `oh-ipc-2026.10-v9`。
- 新增合成正例、负例和传播测试：full-token 正例、`GetFirstTokenID()` 负例、布尔包装器、敏感调用端到端测试。

模型不会仅按 `IsSystemAppCalling` 函数名放行；必须从函数实现中看到调用者 full-token 的数据来源。

## 披露修复对回归

脚本 `research/experiments/interface/ipc/replay_disclosure_pairs.py` 对本地归档的 13 份 OpenHarmony 修复对做 patch-file replay。默认按路径段排除 test、mock、sample、vendor 等目录，逐个解析归档受影响源文件后调用 B detector。逐文件 SHA-256、lineage 元数据及诊断写入本地生成文件 `replay.json`；按仓库约束，生成产物不纳入 Git，脚本可重建。

| 修复对 | 漏洞前候选 | 修复后候选 | 结果与边界 |
|---|---:|---:|---|
| background-470 | 2 | 0 | 两侧 partial / blocked |
| CVE-2022-38064 | 1 | 0 | 两侧 partial / blocked |
| CVE-2022-38081 | 9 | 6 | 完整解析；3 条 AUTH-02 消失，6 条 descriptor 候选仍待扩大源码范围 |
| CVE-2022-38700 | 1 | 0 | 存在 partial，run blocked |
| CVE-2023-0036 | 1 | 0 | 两侧完整解析 |
| CVE-2024-0285 | 0 | 0 | mock 路径被排除，不作为产品命中 |
| CVE-2025-26474 | 0 | 0 | 测试路径被排除；生产范围归档样本未产候选，不能据此声称覆盖 |
| CVE-2025-26691 | 7 | 0 | 受影响文件完整解析；按归档 patch-file replay 解释 |
| CVE-2025-26693 | 3 | 1 | 两侧 partial / blocked；目标 AUTH-02、AUTH-03 消失，剩余 AUTH-01 无关 |
| CVE-2025-27563 | 6 | 3 | 两侧 partial / blocked；3 条 caller-class 候选消失；剩余 AUTH-01、AUTH-04、AUTH-02 分别待审 |
| OpenHarmony-SA-2022-0602 | 10 | 2 | 完整解析；8 条 descriptor 候选消失，固定侧留 2 条 AUTH-02 |
| OpenHarmony-SA-2022-0603 | 3 | 0 | 含 partial，run blocked |
| OpenHarmony-SA-2022-0604 | 5 | 0 | 10 个输入文件均 partial，run blocked |

过滤后原始诊断计数合计为 48 → 12；这不是 48 个漏洞，也不是 precision/recall。候选可能描述同一根因，且多数归档样本不是完整产品构建范围。没有将 scanner finding 升级为 confirmed，`validated_vulnerability` 仍为 0。

### CVE-2025-26693 绑定信息与差分

- vulnerable commit：`89953b22ba58654beda0ff3154125d6779550e2b`
- fixed commit：`31ed3b9f31b029b0ae4dec48a9f95b6356f924c0`
- 文件：`services/accesstokenmanager/main/cpp/src/service/accesstoken_manager_stub.cpp`
- 固定文件 SHA-256：`925664def71b757b612ec5bc17b43c95efd77ad3a388c87a5c792bdfad4d2f58`

修复版 `GetReqPermissionsInner` 新增 HAP 系统应用边界与权限检查。v0.8.3 不再报告该敏感调用上的 AUTH-02/AUTH-03。留下的 AUTH-01 来自 `IAccessTokenManager` 与 stub 基类关系不在当前单文件输入中的身份缺口。

## 验证和限制

- 全量单测：522 tests，通过。
- component-audit 版本影响：`affected=1, fixed=1, not_present=1, unknown=0`。
- fixture manifest checksum 及 `git diff --check` 通过。
- 13 份回归输入来自归档的受影响文件。lineage JSON 给出 commit 字段，但脚本没有逐仓验证 Git object；每个输入文件记录本地 SHA-256。因此这是可复现的归档 patch-file replay，不是 pinned-Git-object 复现。
- 未构建 OpenHarmony 产品，未跑 PoC、设备、Sanitizer 或 Agent；确认漏洞数仍为 0。

## 下一步

优先复核 CVE-2025-27563 固定侧残留 AUTH-02：源码有 `!IsAccessTokenCalling() && !VerifyPermission(PERMISSION_USED_STATS)`，说明存在 service-account 例外。不要把规则扩大到所有操作；先从固定提交与完整组件绑定 `ACCESSTOKEN_UID`，核验 UID 定义及真实调用者，再决定是否把 `RemovePermissionUsedRecords` 加入精确 accepted-operation 契约，并补错误 UID、错误身份域和无权限反例。

其次复核 CVE-2022-38081 固定侧的 6 条 AUTH-01：扩大源码范围读取 stub 的接口基类声明，区分范围不足与 descriptor mismatch，不能为压低候选而全局忽略。

## 可复现命令

```bash
cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b
PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/replay_disclosure_pairs.py \
  --pairs-root /home/audit/openharmony-audit/ipc-research/pairs \
  --output research/deliveries/ipc/20261019-disclosure-regression-v0.8.3/replay.json
.venv/bin/python -m unittest discover -s tests -q
```

Replay JSON SHA-256: `4bd34570629a5a77e3c1dc580be5879aecc0d673779e95549c037b8c98037a75`.
