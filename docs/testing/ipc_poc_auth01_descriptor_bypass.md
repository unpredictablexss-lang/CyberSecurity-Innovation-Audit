# 接口线 P0：PoC 模块与首个端到端触发（2026-10-10）

> 政策前提：`AGENTS.md` 的 **Competition deliverables — must produce**。PoC 与动态验证是**必须交付物**。
> 唯一安全边界：**不攻击线上真实服务**；本文全部执行都发生在本地、隔离的临时构建目录里。
> **本文是实测记录。**`validated_vulnerability` 恒为 0；入口可达性**没有被证明**。

## 1. 交付了什么

新模块 `src/ohscanner/poc/`（此前后端完全空白，只有文档提到过它）：

| 文件 | 作用 |
|---|---|
| `states.py` | 生命周期状态机 `not_generated → generated → build_success → run_success → trigger_success → stable_reproduced`（`docs/architecture_2026.md` §8.4）与重放标签 `no_trigger/flaky/trigger_success/stable_reproduced`，以及证据阶梯 `static_candidate < static_confirmed < dynamic_reproduced < stable_reproduced` |
| `sources.py` | 从本地 git 对象库**按固定提交物化**组件源码，逐文件校验 SHA-256，读不到或对不上就报错而不是继续 |
| `runner.py` | 隔离构建 + 运行 + 判定 + 稳定性重放 + 环境指纹 |
| `records.py` | 机器可读记录与 Markdown 渲染 |
| `harnesses/<family>/` | 家族模板：harness 源码、桩清单、`manifest.json`（提交、摘要、用例、预期） |

驱动脚本 `research/experiments/interface/poc/run_poc.py`。**没有新增 CLI、没有新增 Finding 类型、没有改动任何公共契约**——契约 `ohscanner_detector_contract_v1.md` 要求 PoC 由独立模块承载，而非在检测器的单次静态执行里完成。

回归：`python -m unittest discover -s tests` → **255 项 OK**（236 既有 + 19 新增，其中 2 项是真编译真运行的集成测试）。

## 2. 首个端到端触发：AUTH-01 SA 中继（`cve-2023-0036`）

- 仓库 `openharmony/inputmethod_imf`，PR !228；漏洞提交 `e663b470`，修复提交 `5eaddcab`（均为 S2 / `patch_root_cause_review`）。
- 缺陷：`PlatformCallbackStub::OnRemoteRequest` 在分发事务前**不校验接口描述符**；修复是在 `switch` 之前读取 token 并与 `GetDescriptor()` 比较。
- 两个修订的 `platform_callback_stub.cpp` **逐字节原样编译**（与 git 原文 diff 已验证一致），`Parcel` 用的是 **c_utils 真实实现**。

| 用例 | 角色 | 漏洞版 | 修复版 |
|---|---|---|---|
| `no_token`（不带任何接口 token） | 攻击 | **`messages_sent=1`**，`msgId=5`(`MSG_ID_USER_LOCK`)、`userId=4242`(发送方自选)、`contentCount=2` | `ret=-74`(`ERROR_STATUS_UNKNOWN_TRANSACTION`)，**未投递** |
| `correct_token` | 正对照 | `messages_sent=0`（漏洞版不消费 token，导致后续解析错位） | `messages_sent=1`，正常投递 |
| `foreign_token` | 攻击 | `messages_sent=0` | `ret=-74`，未投递 |

**状态 `stable_reproduced`（重放 3/3），证据等级 `stable_reproduced`。** 正对照证明修复版不是「一律拒绝」。

这条链的意义：发送方**完全不提供接口描述符**时，漏洞版仍会执行回调并把一条伪造的用户锁事件投进输入法服务的消息循环——正是 AUTH-01 混淆代理/SA 中继的形态。

## 3. 首个负结果：DATA-01 长度校验（`cve-2024-0285`）——为什么它**不能**当 PoC

在选型阶段先做了这个，结论是负的，而且必须留下记录，以免后人重做：

- 目标 `HitraceInvoker::TraceServerReceieve`（`communication_ipc`，PR !907；漏洞 `c2f6020d`，修复 `8fb80113`）。缺陷是攻击者可控的 `idLen` 参与无上界的无符号减法。
- 用**真实 c_utils `Parcel`** 编译漏洞版与修复版，ASan+UBSan 扫了 7×4 组输入（payload 0/1/2/3/4/8/64 × trailer 0xff/0x28/0x29/0xffff）：**零 sanitizer 故障**。
- 原因：当代 `Parcel::RewindRead` 会拒绝 `newPosition > dataSize_`，`SetDataSize` 会拒绝 `> dataCapacity_`，两处下溢都被基线库挡掉；`MessageParcel` 没有覆写这两个方法。
- 漏洞版与修复版唯一可观测的差异是**返回值翻转**（`ret` 0↔1），`dataSize` 不被破坏。

**结论：这条历史修复对在当前基线下已不可复现为内存安全缺陷。** 它仍是有效的「补丁区分」数据点，但**不能**作为 PoC 交付件。给队伍的直接含义：本仓库 13 组修复对里，凡依赖基类库做边界校验的，都要先做这一步验证再投入。

## 4. 没有证明的事（逐条）

- **可达性**：harness 直接调用 stub。远端调用者能否经真实 IPC 抵达这个 stub、需要什么 ability 注册与权限状态，**没有证明**，仍是 `EvidenceObligation`。因此记录里 `validated_vulnerability = 0`。
- **影响范围**：没有跨版本扫描，不知道哪些分支/版本受影响。
- **修复建议**：没有产出补丁与「修复后原 PoC 失败」的重验闭环（修复版能拒绝是**上游既有补丁**的结果，不是本模块生成的补丁）。
- **桩的边界**：`MessageHandler::SendMessage` 记录而非投递；`MessageParcel` 的 token 方法是桩（转发到真实 `WriteString16`/`ReadString16`）；`poc_compat.h` 补了历史头文件集缺失的 using 指示。全部逐条列在 harness 的 `README.md` 与 `manifest.json` 的 `known_limitations`。
- **数据一致性**：`ipc-research/pairs/cve-2023-0036/lineage.json` 标 `verification_level: S1`，而 `research/corpus/interface/ipc/verified_pairs.jsonl` 标 `S2 / patch_root_cause_review`。两处不一致，**需要队伍核对哪一份是准的**。

## 5. 复现

```bash
cd ~/openharmony-audit/CyberSecurity-Innovation-Audit-b
.venv/bin/python -m unittest discover -s tests -q            # 255 OK

.venv/bin/python research/experiments/interface/poc/run_poc.py \
  --json outputs/reports/poc_auth01_descriptor_bypass.json \
  --md   outputs/reports/poc_auth01_descriptor_bypass.md
```

需要：`clang++`、`~/openharmony-audit/ipc-research/repos/inputmethod_imf`（固定提交所在对象库）、`~/openharmony-targets/commonlibrary_c_utils`（真实 `Parcel`）。缺任一项时集成测试自动 skip，PoC 驱动会明确报错而不是产出空记录。

## 6. 下一步

1. 给 module 加一个「差分但无故障」的结果模式，把 §3 这类负结果也纳入机器可读记录（当前模型只表达「有没有触发故障」）。
2. 可达性证据：把 stub 放进一个最小可运行的 IPC 场景，或引用上游 fuzz 目标，把 `entry_reachability` 义务真正补齐。
3. 修复建议闭环：对至少一个候选产出补丁并重跑原 PoC，记录「修复后不再触发」。
