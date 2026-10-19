# D30 — Samgr 当前 IPC detector 精确源码重放（CR-0219–0226）

## 结果

在集成基线 `3aa6acc13ab7f39b0ebaee092a3e3e5b9b83bfa2` 上，使用当前 production CLI 的 `ohscanner.interface.ipc`（detector 版本 `0.12.12`）扫描固定 Samgr 源文件。原先 T10/T18 绑定的 8 个 `ipc.capability.export` 位置全部命中：CR-0219–0226 为 **8/8**。未复现当前 CLI 对这些已知位置的漏检，因此本轮不修改 IPC detector，也无 B-owner rule request。

| A0 ID | 方法 | 位置 | 当前 finding ID | 原 A0 状态 |
|---|---|---:|---|---|
| CR-0219 | `CheckRemtSystemAbilityInner` | 464 | `ohscanner.interface.ipc:2af8fbf91642cbbf` | `not_reproduced / queued_not_reproduced` |
| CR-0220 | `CheckSystemAbilityImmeInner` | 551 | `ohscanner.interface.ipc:e6305216fc6e7a94` | `not_reproduced / queued_not_reproduced` |
| CR-0221 | `GetSystemAbilityInner` | 668 | `ohscanner.interface.ipc:b810e0670174d80e` | `not_reproduced / queued_not_reproduced` |
| CR-0222 | `CheckSystemAbilityInner` | 706 | `ohscanner.interface.ipc:c50c9e08852ab64f` | `not_reproduced / queued_not_reproduced` |
| CR-0223 | `GetExtensionRunningSaListInner` | 1485 | `ohscanner.interface.ipc:d21108b21819c7b8` | `not_reproduced / queued_not_reproduced` |
| CR-0224 | `GetSystemAbilityWithUserIdInner` | 1692 | `ohscanner.interface.ipc:cfca2b2cdef00a5b` | `not_reproduced / queued_not_reproduced` |
| CR-0225 | `CheckSystemAbilityWithUserIdInner` | 1735 | `ohscanner.interface.ipc:2ffa938ee632d9d4` | `not_reproduced / queued_not_reproduced` |
| CR-0226 | `CheckSystemAbilityByUserIdInner` | 1784 | `ohscanner.interface.ipc:5f76290f7adec957` | `not_reproduced / queued_not_reproduced` |

## 来源与复跑

- Repository: `openharmony/systemabilitymgr_samgr`
- Commit: `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`
- Tree: `b7a89e95be788f2f2372258e341f7be842c7826d`
- File: `services/samgr/native/source/system_ability_manager_stub.cpp`
- Blob: `ae84d998c4d90c8c08d692b9020404593b58a0cc`; 78,212 bytes; SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`
- Scope: one explicitly selected source file; `light-ast`; detector version `0.12.12`; rule `ipc.capability.export`. The CLI does not expose a separate rule version (`null`).
- Parse and analysis status: `partial` / `partial`; parse coverage is 0 complete / 1 partial. CLI completed with limitations and emitted 10 diagnostics across rules.
- Exact command and complete JSON/Markdown output: [`a_d30_samgr_ipc_replay_20261021.json`](a_d30_samgr_ipc_replay_20261021.json), [`a_d30_samgr_ipc_cli_20261021.json`](a_d30_samgr_ipc_cli_20261021.json), [`a_d30_samgr_ipc_cli_20261021.md`](a_d30_samgr_ipc_cli_20261021.md).

```powershell
python -m src.cli.main ohscan-run --repo-dir research/evidence/cpp/.d30_samgr_source_repo --repository openharmony/systemabilitymgr_samgr --commit 08e2a552b839ea7727251cb9b749a5c1dd9cfeff --include services/samgr/native/source/system_ability_manager_stub.cpp --detector ohscanner.interface.ipc --json-out research/evidence/cpp/a_d30_samgr_ipc_cli_20261021.json --md-out research/evidence/cpp/a_d30_samgr_ipc_cli_20261021.md
```

## 判读与后续

8/8 命中只表示当前规则在该精确源码快照中产生对应根因候选。它不能证明输出对象可被未授权外部调用者取得。当前记录仍缺可信修复版、产品构建配置（包括 SELinux 开关）、实际 caller SID/策略映射、服务与目标 SA 的产品可达性和目标派生 harness；且目标文件解析为 partial，因此保持原 A0 状态，不将其改记为复现通过，也不据此得出漏洞确认或安全结论。

当前没有实际漏检，故没有生产规则改动。若后续证据发现同一源码中的候选遗漏，开发者需先提交 B-owner request：绑定交易注册、parcel 输入、权限检查与 capability sink，说明解析限制，并附漏洞正例、guarded/safe controls 和精确复跑命令；未获准前不得声称 IPC rule 已补齐生产覆盖。
