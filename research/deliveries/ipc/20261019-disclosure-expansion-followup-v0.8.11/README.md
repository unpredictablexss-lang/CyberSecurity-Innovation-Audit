# B 线披露漏洞扩展复测（OHScanner 0.8.11）

日期：2026-10-19\
代码仓库：`CyberSecurity-Innovation-Audit-b`\
分支：`feat/interface-ipc-detector`\
代码 HEAD：`42c4d7140b67813105d6b8a9d3bea241f25a1209`\
检测器：`ohscanner.interface.ipc` 0.8.11；解释模型 `oh-ipc-2026.10-v17`

## 结果

本轮在当前 B 代码上对 5 组公开修复前后固定 Git 提交作只读源码重放。4 组出现与补丁变化相符的静态候选差分；CVE-2025-26691 出现反向差异，列为未解决，不计为吸收成功。

| 披露样本 | 固定源码候选（修复前→修复后） | 解析/运行状态 | 解释 |
|---|---:|---|---|
| CVE-2023-0035，communication_dsoftbus | 1→0 | 两端 partial / blocked | relay 描述符边界候选随修复消失；仅源码回归匹配 |
| CVE-2023-0036，inputmethod_imf | 1→0 | 两端 complete / completed | relay 描述符边界候选随修复消失；本轮四组中解析完整度最好 |
| CVE-2024-12082，ability_ability_runtime | 8→4 | 两端 1 complete、5 partial / blocked | 漏洞端在 `AppMgrStub::HandleGetBundleNameByPid` 产生 AUTH-03、AUTH-02 和 DATA-04 候选；修复端这组候选消失，仍有 4 条与该披露点无关的候选 |
| CVE-2025-26693，security_access_token | 4→1 | 两端 partial / blocked | 目标 `GetReqPermissions` 路径的 AUTH-03、AUTH-02 和 DATA-04 候选消失；修复端仍有一个与此修复点无关的描述符候选 |
| CVE-2025-26691，telephony_call_manager | 7→9 | 两端 complete / completed | 反向差异：修复提交新增的权限/调用者检查触发了 9 条权限契约候选。端点差异和当前权限契约语义尚未解释，不作为命中或误报结论。OpenHarmony 官方 2025-06 公告将其描述为电话服务权限绕过并导致敏感信息泄漏，但没有给出逐方法的权限映射或修复细节（[官方公告](https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2025/2025-06.md)） |

CVE-2024-12082 的逐文件契约正反例已在 `tests/test_ipc_repository_caller_contract.py`：同仓缺少 SA 检查应报候选、敏感查询之后才检查仍应报、错误调用者角色仍应报、正确的跨 TU SA 检查应抑制候选、同一规则不得跨仓套用。它们是合成契约测试；真实源码对仍单独保存在下方复测 JSON 中。

## 复核产物

- [CVE-2023-0035 固定 Git 重放](cve-2023-0035.json)
- [CVE-2023-0036 固定 Git 重放](cve-2023-0036.json)
- [CVE-2024-12082 固定 Git 重放](cve-2024-12082.json)
- [CVE-2025-26693 固定 Git 重放](cve-2025-26693.json)
- [CVE-2025-26691 固定 Git 重放（未解决反向差异）](cve-2025-26691-unresolved.json)
- [aafwk_standard 旧候选定向复核](../20261019-candidate-review-aafwk-v0.8.11/aafwk-current-review.md)：5 个 partial 文件、16 条候选；当前阻塞覆盖，不用于披露漏洞命中统计。

每份 JSON 记录固定完整 commit/tree、固定文件 scope、Git blob 与源码 SHA-256、候选及解析状态。重新核验文件完整性时，在本目录执行：

```bash
sha256sum -c SHA256SUMS
```

## 判定边界

这些是公开披露修复对上的开发/回归样本，不是独立 holdout。静态候选变化只说明当前解释器在这些固定源码输入上观察到了差异，不证明产品可达性、影响、利用条件、检测 Precision/Recall，也不等于 Agent/Harness 复核。所有静态输出仍是候选；本轮原始 replay JSON 不包含 `validated_vulnerability` 字段，也没有设备 PoC 或产品运行验证，因此没有可升级为已验证漏洞的结果。公开 CVE 的历史披露状态可以在单独的 CVE 台账记录，不能传染给扫描候选。

CVE-2025-26691 的 7→9 表明权限契约、调用者类别门与错误权限常量需要拆开复核。下一步应先逐方法对照公开公告、修复 PR、方法权限要求来源及完整补丁历史，再决定契约应验证“系统调用者限制”“具体权限”还是两者；不得通过删掉固定端候选来人为制造 7→0。

## 代码改动与验证

本轮没有新增检测规则或更改 Detector 代码；新增固定 Git 重放产物。CVE-2024-12082 的规则和正反例测试已经存在于当前工作树，本轮实际重放确认它在真实修复对上产生差异。全量单元测试结果需以本轮最终命令输出为准。
