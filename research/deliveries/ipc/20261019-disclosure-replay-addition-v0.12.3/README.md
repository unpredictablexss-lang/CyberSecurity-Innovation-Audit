# B 线已披露漏洞回归追加：CVE-2024-39775 与 CVE-2023-25176

日期：2026-10-19；检测器：`ohscanner.interface.ipc 0.12.3`；扫描器源码提交：`33bf87139071a5ce7912f478f954c6b6942ec2b0`。

本追加包归档当前版本对两组公开披露修复对的回放。两组都是固定提交上的静态源码差分，不代表产品运行时漏洞确认。

| CVE | 固定源码对 | 当前检测器结果 | 对应规则与证据 | 限制 |
|---|---|---:|---|---|
| CVE-2024-39775 | `communication_netmanager_base`：`c172839f` → `b99cb782` | **2 → 0** | AUTH-07 在共享 `CheckNetManagerAvailable` helper 中观察到权限失败分支已写错误 reply，却返回 `NETMANAGER_SUCCESS`；修复改为返回具体拒绝码。五个调用点检查 helper 返回值并在失败时提前退出，因此旧返回值会让受保护路径继续执行。 | 两侧目标文件均为 `partial`；未构建组件或验证设备/产品。 |
| CVE-2023-25176 | `distributeddatamgr_pasteboard`：`693a188b` → `9408af4f` | **1 → 0** | DATA-05 命中 TLV 声明长度只验证剩余可用字节、但固定读取 `sizeof(T)` 的源码形态；修复增加 `head.len == sizeof(T)` 要求。 | 两侧目标头文件均为 `partial`；未验证产品入口或运行时影响。 |

## 固定证据

所有扫描都通过生产入口 `ohscan-run`，只读固定 Git commit/tree 和指定文件。扫描报告保存 snapshot SHA-256、scope、解析状态、候选和限制；两组的 `validated_vulnerability` 都为 0。manifest 绑定 JSON 报告哈希，SHA256SUMS 绑定包内文件（自身除外）。

CVE-2024-39775 的正确前后版本是修复提交 `b99cb78281915a9a2587aca981fa69c969ba8f93` 的父提交 `c172839fd6354d9bff189c8b1ade2cf621f4b24f` 到该修复提交。旧回放使用的 `eb00c2b4` → `7d0c987f` 不是这条漏洞补丁的直接前后版本，应作废；这两个版本虽然也出现 2→0，但消失候选锚定在另一处 `OnResetFactory` 修复点，不能作为 CVE-2024-39775 根因匹配证据。

## 结论边界

两项可记作“公开修复与固定源码回归相匹配”。不要把 scanner finding 的 severity 或 `validated_vulnerability` 改写为 confirmed。0 个 finding 只表示该固定 scope 中相应规则未报告候选，不证明整仓或产品安全。披露修复对是开发回归样本，不是独立 holdout，不能据此计算 Precision/Recall。
