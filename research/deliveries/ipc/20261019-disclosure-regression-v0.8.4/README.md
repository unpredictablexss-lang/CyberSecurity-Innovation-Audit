# B 线披露修复回归：精确服务账号范围与固定 Git 重放（2026-10-19）

## 结果

在 B 线提交 `42c4d7140b67813105d6b8a9d3bea241f25a1209` 之后，本轮把检测器升到 `0.8.4` / `oh-ipc-2026.10-v10`，并完成两组按固定 Git 对象读取的公开修复对重放：

| 样本 | 漏洞端 → 修复端 | 目标规则 | 解析/状态 | 结论边界 |
|---|---:|---|---|---|
| CVE-2025-27563 | 3 → 0 | 3 条 `ipc.auth.caller-class` 候选在修复端消失 | 两端 2 个文件均 partial，run `blocked` | 静态补丁差分匹配；不能称产品或运行时确认 |
| CVE-2025-26691 | 9 → 0 | 9 条 `ipc.auth.missing` 权限常量错配在修复端消失 | 两端 1 个文件 complete，run `completed` | 静态源码回归匹配；不是独立 holdout，也不是产品确认 |

这两个 CVE 已在更早的集成工作树结果中出现；本次交付的价值是把它们在队长维护的 B 仓库分支上用同版检测器、明确完整 commit/tree/blob 和可重放脚本重新固定下来。它们不是新增的全球披露样本，也不增加准确率/召回率样本数。

13 组旧的归档 patch-file replay 在 0.8.4 下与 0.8.3 候选计数完全一致。归档只包含受影响 patch 文件，未携带 CVE-2025-27563 的 UID 头文件，所以不能用那份旧归档复现下面的 `.h + .cpp` 证据。

## CVE-2025-27563：服务账号例外的受限建模

固定 Git 端点是 `security_access_token` 中漏洞提交 `85ead8f16d070dd66e4ea906b1246018d747ec7b` 和其直接子修复提交 `e232d8ed63b53ba883265972872695bb5aab756a`。扫描同一显式范围：

- `services/privacymanager/src/service/privacy_manager_stub.cpp`
- `services/privacymanager/include/service/privacy_manager_stub.h`

入口代码的 `RemovePermissionUsedRecordsInner` 先对 HAP 调用者实施系统应用检查，再对非 AccessToken 服务调用者要求 `PERMISSION_USED_STATS`。`IsAccessTokenCalling()` 比较真实 caller UID 与类成员 `ACCESSTOKEN_UID`。该常量在头文件中以 `static const int32_t ACCESSTOKEN_UID = 3020` 定义；同一固定提交的 `privacy.cfg` 将 `privacy_service` 配置为 `uid: access_token` 并列出 `PERMISSION_USED_STATS`。模型因此仅在仓库 `openharmony/security_access_token`、敏感操作 `RemovePermissionUsedRecords`、处理函数 `PrivacyManagerStub::RemovePermissionUsedRecordsInner` 三个条件同时符合时，才把该 UID 分支解释为本操作的服务账号例外。它不把 UID 3020 变成通用权限，也不跨仓库传播。

修复端剩余的两个权限候选之所以消失，源头是入口索引漏记 C++ 类成员中的字面量 `static const`。本次索引只补充直接字面量 initializer；未解析的表达式、冲突定义仍保持 unknown。新测试覆盖跨 `.h/.cpp` 解析、错误仓库拒绝、错误操作拒绝和 exact-handler 限制。

同一 scope 的旧版 `0.8.3` 回放为 **5 → 2**；`0.8.4` 为 **3 → 0**。两端运行状态仍是 `blocked`，两个输入文件均 partial。漏洞端三条候选在 `RemovePermissionUsedRecordsInner`、`IsAllowedUsingPermissionInner`、`SetMutePolicyInner` 三个位置；官方固定差异在 `RemovePermissionUsedRecordsInner` 和 `IsAllowedUsingPermissionInner` 增加系统应用门，并在 `SetMutePolicyInner` 增加 native/shell 调用者限制。这里观察到的 3→0 与固定补丁中的调用者类别约束一致，但源码 partial，因此仍只记为静态差分候选。

固定重放 JSON：`cve-2025-27563.json`。其中记录两端完整 commit、tree、Git blob ID、SHA-256、parse 状态、候选与义务。

## CVE-2025-26691：完整解析的权限错配回归

固定端点为 `911c6c99872e3a6a421747815bc8c1f6b201db26` → `6018446d576b84d8893f8f7ad5d46353236fb8e0`，修复提交是漏洞端的直接子提交。扫描双方同一文件 `services/call_manager_service/src/call_manager_service.cpp`。完整解析下 9 条权限常量错配 `ipc.auth.missing` 随修复消失，报告状态为 `completed`。该修复提交仅修改这一个实现文件；固定前后候选机制与补丁行相符。

此结果仍是公开修复对回归，不是独立 holdout 或 Precision/Recall 测量。原始 finding 仍是 candidate；本轮没有设备验证或 Agent/Harness 验证。

## 版本与回归

- Detector：`0.8.4`
- Interpretation model：`oh-ipc-2026.10-v10`
- 全量测试：`525 tests OK`
- `compileall`、`git diff --check`：通过
- 13 组归档 replay：修复前后总候选数与 0.8.3 完全一致
- 产品构建、运行时 PoC、Agent/Harness：未执行
- `validated_vulnerability`：仍为 `0`

## 重放命令

在 B 仓库根目录运行：

```bash
PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/replay_pinned_git_pair.py \
  --repo-dir /home/audit/openharmony-targets/security_access_token-cve-2025-26693 \
  --repository openharmony/security_access_token \
  --vulnerable 85ead8f16d070dd66e4ea906b1246018d747ec7b \
  --fixed e232d8ed63b53ba883265972872695bb5aab756a \
  --include services/privacymanager/src/service/privacy_manager_stub.cpp \
  --include services/privacymanager/include/service/privacy_manager_stub.h \
  --json-out research/deliveries/ipc/20261019-disclosure-regression-v0.8.4/cve-2025-27563.json

PYTHONPATH=. .venv/bin/python research/experiments/interface/ipc/replay_pinned_git_pair.py \
  --repo-dir /home/audit/openharmony-targets/telephony_call_manager-cve-2025-26691 \
  --repository openharmony/telephony_call_manager \
  --vulnerable 911c6c99872e3a6a421747815bc8c1f6b201db26 \
  --fixed 6018446d576b84d8893f8f7ad5d46353236fb8e0 \
  --include services/call_manager_service/src/call_manager_service.cpp \
  --json-out research/deliveries/ipc/20261019-disclosure-regression-v0.8.4/cve-2025-26691.json
```

`archived-patch-replay.json` is rebuilt by `replay_disclosure_pairs.py` with the prior 13 archived pairs. It verifies replay stability but intentionally does not claim Git-object provenance for those extracted patch files.
