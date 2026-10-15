# AUTH-01 修复重验闭环打通，与 PoC 载体 spike 判定（2026-10-15）

- 输入：`AGENTS.md` 的 Competition deliverables（证据门要求 `patch_revalidation == passed`）、
  `docs/strategy/competition_deliverables_plan.md`，以及 `src/ohscanner/poc/` 现有模块。
- 本轮做两件事：**(一)** 用一个小预算 spike 判定新 PoC 载体是否可行；**(二)** 给已有端到端 PoC
  （AUTH-01 `inputmethod_imf` / `cve-2023-0036`）补上**自撰补丁 + 修复重验**闭环。
- 结果：spike **判负/半负**（结论见 §2）；修复重验 **`passed`**（§4）。
- **`validated_vulnerability` 仍为 0**。本轮没有提升任何候选，没有新增漏洞结论。

## 0. 一句话结论

第一件：新载体**不值得做**——`window_window_manager` 的 CAP-01 载体本地编不出来（缺 `graphic_2d`），
`communication_dsoftbus` 的 AUTH-01 载体编得出来但它**是 2026-10-14 已判定的「外部依赖缺口」**
（真正的派发在 `libdsoftbus_server_plugin.z.so`，本机任何源码树都没有），给它建 PoC 只能观测到
静态上早已确认的事，impact 一格填不了。
第二件：**AUTH-01 的修复闭环打通了**——本项目自撰的补丁应用到漏洞版后，攻击用例不再触发、
正对照仍然投递，证据门里 `patch_revalidation` 这一格从「靠上游恰好有修复」变成
「本项目给出的补丁经重验通过」。

## 1. 本轮改的与没改的

**改了（全部在 B 线自有面 `src/ohscanner/poc/`）：**

| 文件 | 改动 |
|---|---|
| `harnesses/auth01_descriptor_bypass/fix.diff` | **新增**：本项目自撰的修复补丁（18 行） |
| `harnesses/auth01_descriptor_bypass/manifest.json` | 新增 `patch` 块：id / applies_to / file / rationale / criterion |
| `src/ohscanner/poc/records.py` | 新增 `PatchRevalidation`；`PocResult` 增 `patch_revalidation` 与 `patch_state`；新增渲染函数 |
| `src/ohscanner/poc/runner.py` | 新增 `apply_patch` / `patch_revalidation_state` / `_revalidate_patch`；从 `build_revision` 拆出可复用的 `build_translation_unit`（旧签名保持兼容） |
| `src/ohscanner/poc/__init__.py` | 导出 `PatchRevalidation` |
| `tests/test_poc_runner.py` | +9 用例（状态机纯逻辑 5、manifest 形状 3、真编译集成 1）；集成用例改为类级共享一次运行 |

**没改**：检测规则、`models.py` 词表、公共契约、`catalog.py`、`src/case/`、`src/benchmark/`、
`src/report/`（owner 共享面）、A 线代码、Draft PR。

## 2. 载体 spike 判定（计划第 0 步）

**目的**：判定哪个既有候选的翻译单元能在**不改目标源码**的前提下编成 `.o` 并链真实 `Parcel`。
**预算**：≤20 轮编译-修错、累计 ≤1 小时。**方法**：照抄已跑通的 AUTH-01 harness 手法
（真实 TU + 真实头文件 + `~/openharmony-targets/commonlibrary_c_utils` 的真实 `Parcel` +
最小 `poc_compat.h`），对每个探针跑自动 include 闭包发现（反复编译 → 定位缺失头的真实路径 → 加 `-I`）。

| 探针 | 载体 | 结果 | 依据 |
|---|---|---|---|
| A | `window_window_manager` `window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp`（CAP-01，2,088 行） | **不可行** | 第 2 层即缺 `ui/rs_display_node.h`（`graphic_2d`/render_service），`find /home/audit` 全树无此组件 |
| B | `communication_dsoftbus` `core/bus_center/extend/src/bus_center_ex_obj_stub.cpp`（AUTH-01，67 行） | **编得过** | 8 个 `-I` + 一个补 `#include <mutex>` 与 `HILOG_IMPL` 的 compat shim 后，`clang++ -std=c++17 -c` 退出码 0，产出 20,440 字节 `.o`，`OHOS::BusCenterExObjStub::OnRemoteRequest` 为已定义符号 `T`，唯一未定义外部符号是 `SoftBusDlopen` |

**真实编译轮数**：A 2 轮、B 约 10 轮（另有两轮因 spike 脚本自身缺陷空转，不计入载体判据）。

### 2.1 为什么探针 B「编得过」不能当成载体可用

这条候选在 **2026-10-14 的 `ipc_dsoftbus_deep_review` 里已经判过**，结论是
`external gap / plausible but unproven`，理由是四条可复核的缺口：

1. IPC 框架不兜底——`ipc_object_stub.cpp` 的 `SendRequestInner` 直接调 `OnRemoteRequest`，无 token 校验，
   描述符校验是各 stub 自己的事；
2. 符号实现不在本仓库——`grep -rn OnRemoteRequestByDlsym` 全树只命中这两处 `dlsym` **查找点**；
3. 也没有构建目标——任何 `.gn/.gni` 都不构建 `libdsoftbus_server_plugin.z.so`；
4. 本仓库内的对象实现是空壳（`TransSpecObject` 16 个方法全 `SOFTBUS_NOT_IMPLEMENT`）。

所以给探针 B 建 harness，能观测到的最多是「桩不比对描述符就转交」——**这正是静态上早已确认的事**，
而真正的派发与是否逐调用鉴权在缺席的插件里。按证据门，它最多到
`dynamic_reproduced_component_issue`，且会踩「把非漏洞包装成交付件」的风险（`AGENTS.md`：
Impact over alert count；misreporting is penalized）。

**⇒ 判定：载体切换为「闭已有 AUTH-01 的环」。** 依据是「唯一已有可用 PoC + 公开 CVE + 真实漏洞/修复对」
的候选就是 AUTH-01 `inputmethod_imf`，它缺的恰好是竞赛要的四件（影响范围 / 自撰补丁闭环 / 报告渲染 / 性能）。
计划里「谁编过谁当载体」这条规则的**前提不成立**，故本次不按它执行；`fix.diff` 与 CLI 参数
已让「新载体」在需要时可低成本重试，不需要重做本轮的判定工作。

> 负结果保留：wwm CAP-01 载体**本地不可行**；dsoftbus AUTH-01 载体**可编译但不可用于闭环**。
> 两者都不删除，供后续换机/补依赖时复用。

## 3. 自撰补丁（交付件 #5 的一半）

补丁：`src/ohscanner/poc/harnesses/auth01_descriptor_bypass/fix.diff`，`patch -p1` 可应用。

```diff
     int PlatformCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
                                               MessageOption& option)
     {
+        // Interface-descriptor guard. The descriptor names the interface a transaction is
+        // addressed to. Without reading it before the payload, a caller that presents no
+        // token at all -- or a token belonging to a different interface -- is served anyway,
+        // and the payload is parsed as though it came from the peer this stub was
+        // registered with.
+        std::u16string callerDescriptor = data.ReadInterfaceToken();
+        if (callerDescriptor != GetDescriptor()) {
+            return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
+        }
         switch (code) {
```

**从 guard/effect 关系论证（不是套模板）**：效应是 `notifyEvent()` 走到
`MessageHandler::SendMessage()`，只能从 `switch` 的 `NOTIFY_EVENT` 分支到达；漏洞版在这条路径上
**唯一的前置条件**是 `code == NOTIFY_EVENT`，也就是说「事务属于本接口」根本不是前置条件的一部分，
而是**整体缺席**。补丁把它变成前置条件：在 `switch` 之前读接口 token，不等于 `GetDescriptor()`
就返回 `ERROR_STATUS_UNKNOWN_TRANSACTION`。

**位置为什么必须在最前**：`ReadInterfaceToken()` 会消费 parcel 字节，任何放在它之前/之后的载荷读取
都会与它错位并导致解析错误——所以这不是风格选择，是正确性要求。

**与上游修复的关系**：上游 `5eaddcab` 的修复在同一位置加了等价的守卫。本补丁**陈述相同、
独立推导并独立验证**，且这条事实写在 manifest 的 `rationale` 里，不装作与上游无关。

## 4. 重验结果（交付件 #5 的另一半）

链路：`vulnerable` 修订 → 复制到 `work/component/patched` → `patch -p1` 应用 → 重新编译 →
跑全部用例 → 与 `fixed` 修订的逐用例预期比对。

| 项 | 值 |
|---|---|
| 补丁 id | `auth01-descriptor-guard-v1`，作用于 `vulnerable` 修订 |
| 应用 | 成功 |
| 补丁后源码 sha256 | `7b7660ab9973e27fa5a104b76f7c713aa95a210cf504d507d7a6c2778389dba9` |
| 依赖的原始 blob sha256 | `59c980bf8923fe783ab1f02ac9d999b6eb0c6a3fbcf62a16b369000b5877e043`（pinned `e663b470`） |
| 重新编译 | 成功（`clang++`，ASan+UBSan，`returncode = 0`） |
| 状态 | **`passed`** |

| 用例 | 角色 | 打补丁后观测 | 判定 | 符合 fixed 预期 |
|---|---|---|---|---|
| `no_token` | attack | `messages_sent=0 ret=-74` | `no_trigger` | 是 |
| `foreign_token` | attack | `messages_sent=0 ret=-74` | `no_trigger` | 是 |
| `correct_token` | 正对照 | `messages_sent=1 msgId=5 userId=4242 contentCount=2` | `trigger` | 是 |

**判据（写在 `runner.py:patch_revalidation_state`，纯逻辑、有单测）**：`passed` 要求
①补丁应用成功 ②重新编译成功 ③**每个**用例都符合 `fixed` 修订的预期。第 ③ 条是关键——
正对照 `correct_token` 也在比对集里，所以**「一律拒绝」不会被误当成修复**。
其余状态各有其名：`not_applied` / `build_failed` / `run_failed` / `failed`，不会与 `passed` 混淆。

## 5. 这一步在证据门里的位置

`AGENTS.md` 的证据门要求 `reportable` 需六字段齐全 **且** `poc_state == "stable_reproduced"`
**且** `patch_revalidation == "passed"`。本轮把第三项从「无」变成「`passed`」，且是**本项目产出**的补丁。

**没有跟着变的**：`validated_vulnerability` 仍是 **0**；可达性仍是 **`partial`**；
无特权/无关进程能否拿到那个句柄、对端身份与权限、对端是否把句柄再转出去，**都仍未证明**
（`manifest.json` 的 `reachability.relations` 逐条写明「证明了什么 / 没有证明什么」）。
本轮**不因为有了补丁闭环就上调任何判定**。

## 6. 没有证明的事

- **可达性未补齐**：harness 仍直接调用 stub。修复闭环证明的是「守卫是有效的」，
  **不是**「攻击者到得了这里」。
- **影响范围未做**：本轮没有跨 tag/分支扫描，不知道哪些版本受影响。
  （数据源已确认可用：`ipc-research/repos/inputmethod_imf` 6,231 提交 / 57 tag / 19 条发布分支，
  漏洞提交 `e663b470` 与修复提交 `5eaddcab` 的可达 ref 边界可算。）
- **报告渲染未做**：`src/report/vulnerability_report.py` 在 B 仓库**不存在**，属 owner 共享面，
  移植需 owner 批准。
- **性能数据未做**：B 的 audit manifest 只记文件数与字节数，无墙钟/峰值 RSS。
- **数据一致性未核**：`ipc-research/pairs/cve-2023-0036/lineage.json` 标 `verification_level: S1`，
  而 `research/corpus/interface/ipc/verified_pairs.jsonl` 标 `S2 / patch_root_cause_review`，
  两处不一致，**需要队伍核对哪一份是准的**（2026-10-10 报告已记，本轮仍未解）。
- **spike 的边界**：探针 A 只证明了「本机缺 `graphic_2d` 时编不过」，**不是**「该载体永远不可行」；
  探针 B 只证明了「该 TU 能编成 `.o`」，**不是**「该候选可提升」。

## 7. 复现命令

```bash
B=~/openharmony-audit/CyberSecurity-Innovation-Audit-b
cd "$B"

# 1) 全量回归（含 3 个真编译集成用例：vulnerable / fixed / patched）
.venv/bin/python -m unittest discover -s tests        # 463 tests, OK

# 2) 端到端 PoC + 修复重验
.venv/bin/python research/experiments/interface/poc/run_poc.py \
  --json outputs/reports/poc_auth01_descriptor_bypass.json \
  --md   outputs/reports/poc_auth01_descriptor_bypass.md

# 3) 只看重验块
.venv/bin/python -c "import json;d=json.load(open('outputs/reports/poc_auth01_descriptor_bypass.json'));\
print(d['patch_revalidation']['state'], d['patch_revalidation']['patched_sha256'])"

# 4) 手工复核补丁能否应用（在 pinned 漏洞版副本上）
R=~/openharmony-audit/ipc-research/repos/inputmethod_imf
mkdir -p /tmp/ir/services/src
git -C "$R" show e663b47013d534a56165ab7467fbb3e14bf7172b:services/src/platform_callback_stub.cpp \
  > /tmp/ir/services/src/platform_callback_stub.cpp
cd /tmp/ir && patch -p1 --dry-run -i "$B/src/ohscanner/poc/harnesses/auth01_descriptor_bypass/fix.diff"
```

**依赖**：`clang++`、`patch`、`~/openharmony-audit/ipc-research/repos/inputmethod_imf`（固定提交所在对象库）、
`~/openharmony-targets/commonlibrary_c_utils`（真实 `Parcel`）。缺任一项时集成用例自动 skip，
PoC 驱动明确报错而不是产出空记录。

**spike 复现**（只读，产物不入库）：把两个探针 TU 拷到 `/tmp`，用自动 include 闭包发现脚本反复
`clang++ -std=c++17 -fsyntax-only`；探针 B 若补一个 `#include <mutex>` 与 `HILOG_IMPL` 的 compat shim
即可 `-c` 出 `.o`。脚本留在 `/home/audit/wtmp/`（仓库之外）。

## 8. 版本绑定

| 项 | 值 |
|---|---|
| `inputmethod_imf` 漏洞提交 | `e663b47013d534a56165ab7467fbb3e14bf7172b` |
| `inputmethod_imf` 修复提交 | `5eaddcab19bc4b22544f4bee1e8894fc2d6505dc` |
| 目标文件 | `services/src/platform_callback_stub.cpp` |
| 漏洞版 sha256 | `59c980bf8923fe783ab1f02ac9d999b6eb0c6a3fbcf62a16b369000b5877e043` |
| 修复版 sha256 | `b6d7f66a909f23a92c7b38b5f6e6854480f464949d8e456733924af2e9b3c444` |
| 补丁后 sha256 | `7b7660ab9973e27fa5a104b76f7c713aa95a210cf504d507d7a6c2778389dba9` |
| 外部编号 | CVE-2023-0036 / OpenHarmony-SA-2023-0102；PR <https://gitee.com/openharmony/inputmethod_imf/pulls/228> |
| dsoftbus spike 载体 | `652f88e0261ce4d0610f73cc451c26b84d2597af`，`core/bus_center/extend/src/bus_center_ex_obj_stub.cpp`，blob `e6724982844898b8ed281ef5d703b73efffca65a`（67 行） |
| wwm spike 载体 | `perf-corpus/window_window_manager` HEAD `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`，`window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp`（2,088 行） |

所有源码一律按固定提交 `git show <commit>:<path>` 读出，**未把工作树当证据**。
