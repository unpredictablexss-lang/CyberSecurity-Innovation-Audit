# B 线公开漏洞回归增量：AUTH-03 完整调用令牌身份（2026-10-19）

## 结论

B 线现在识别一类此前漏掉的 AUTH-03 守卫：源码取得 IPCSkeleton::GetCallingFullTokenID()，并将它传给精确限定的 TokenIdKit::IsSystemAppByFullTokenID() 时，记录调用者系统应用谓词。完整调用令牌与普通 GetCallingTokenID() 保持不同身份域；名字相近或普通 token 不会被当作 full token。多分支 helper 会保留 caller-class 谓词，但不把它并入权限事实。

CVE-2025-26693 的易受影响提交仍有 4 条诊断，官方修复提交从旧版的 2 条降到 1 条；消失的是 GetReqPermissionsInner 上的 AUTH-03 身份候选，入口描述符候选保留。CVE-2025-26691 的差分仍为 7→0。此处 confirmed 仅指公开披露根因与固定源码修复对的静态回归匹配；扫描 finding 的 severity 继续为 unassessed，validated_vulnerability 仍为 0。

## 实现变化

- GetCallingFullTokenID() 使用 full_token 身份域。
- 仅精确限定的 TokenIdKit::IsSystemAppByFullTokenID(full_token) 产生 caller-class 事实。
- SetCallingIdentity(full_token) 仍正确记录调用者身份转发，避免身份域区分破坏跨服务边界追踪。
- helper 的多结果摘要单独传播 caller-class 谓词，不与权限检查混淆。
- detector/model 升至 0.9.9 / oh-ipc-2026.10-v17。Holdout manifest 同步版本，但 holdout 仍是 not_established。

## 披露修复对复测

| CVE | 固定易受影响提交 → 修复提交 | 目标文件 | 候选诊断变化 | 解析状态与差分 |
|---|---|---|---:|---|
| CVE-2025-26693 | 89953b22ba58654beda0ff3154125d6779550e2b → 31ed3b9f31b029b0ae4dec48a9f95b6356f924c0 | services/accesstokenmanager/main/cpp/src/service/accesstoken_manager_stub.cpp | 4 → 1 | 两侧 partial；AUTH-03（行 172）随系统应用身份检查消失，AUTH-01 描述符候选保留。 |
| CVE-2025-26691 | c751a0dc4c67b40430291d983df60efbb68b5caa → 911c6c99872e3a6a421747815bc8c1f6b201db26 | services/call_manager_service/src/call_manager_service.cpp | 7 → 0 | 两侧 complete；七条 AUTH-02 候选均在修复提交消失。 |

## 五组件固定快照回归

采用仓库内只读 pinned-tree 测量脚本 research/deliveries/ipc/bline_direct_measure.py，对相同完整 commit 比较 v0.9.8 基线与 v0.9.9；两个 pass 为 all-files 和 complete-ast。脚本绕过 M2 CLI 文件数上限，不是生产扫描入口，也不是 Web/Worker 整仓验收。

| 组件 | 固定 commit | complete / partial | all-files 旧→新 | complete-ast 旧→新 |
|---|---|---:|---:|---:|
| security_access_token | 17d88bfb36bea6c9370ba919ac41a22d16dd66b3 | 489 / 56 | 4→4 | 4→4 |
| multimedia_camera_framework | 085a5d0e2dc1c90a4b676bad55675a1cf12a6380 | 932 / 173 | 11→11 | 7→7 |
| multimedia_audio_framework | 3a2688e805df970739e3b0cebf9cc05d8cb24e9b | 1317 / 193 | 6→6 | 6→6 |
| bundlemanager_bundle_framework | 9e67186cfade9714c7c212f374c7ff870524a63e | 912 / 102 | 29→29 | 8→8 |
| update_updateservice | e4942a33cc5ed29040e5c720bea3b2a8e4a79221 | 187 / 31 | 2→2 | 0→0 |

10 组 pass 规则计数均与 v0.9.8 相同，完整明细见随附 pinned-tree report.json。五个树均无 failed parse。all-files 纳入 partial 文件，状态为 blocked；这不是安全结论。complete-ast 也不覆盖 partial 文件。

## 验证与边界

- 新身份域与 helper 摘要测试 4/4 通过；跨服务身份转发测试 7/7 通过。
- 全量测试 678 passed，36 skipped；git diff --check 通过。
- 没有编译 OpenHarmony 组件、运行 PoC、设备或产品环境验证；未测 Precision/Recall。
- CVE-2023-25176 的通用 TLV/vector 越界仍不在当前 Parcel IPC 规则范围；CVE-2024-39775 的权限拒绝 transport 返回码语义仍未建模。
- 其余历史披露样本未在本轮全部按 v0.9.9 重跑；不能将旧版累计台账统计整体改标为 v0.9.9。
- finding 严重性仍为 unassessed，运行器 validated_vulnerability=0。本轮增加的是固定源码修复对的静态回归能力，不是新产品漏洞确认。

## 复现

配套 JSON/Markdown 与五组件 pinned-tree 报告归档于 G 盘 B线已披露漏洞回归_20261019/v0.9.9增补。manifest.json 为各产物记录 SHA-256。修复对可用 CLI ohscan-run 复现，固定 owner/repository、完整 commit、目标文件 --include 和 ohscanner.interface.ipc；整仓对照用只读 pinned-tree 测量脚本。