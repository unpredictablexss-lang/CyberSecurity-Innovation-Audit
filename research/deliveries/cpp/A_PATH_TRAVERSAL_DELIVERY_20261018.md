# A 线 C/C++ 文件路径 source-to-sink 研究 candidate

日期：2026-10-18。性质：detector 开发研究与开发者回归；所有 finding 均为 candidate，不是已确认漏洞、产品复现或独立标签。按用户请求推送到 `codex/a-path-source-sink-20261018`；尚未完成独立验收，不合并，也不改变 PR 状态。

## 问题陈述

A C/C++ detector family 基线以内存安全为主，没有路径穿越/source-to-file-sink analyzer。目标是在准确源码控制上验证一个范围受控的候选分析器：DataShare 外部字段/string 提取，经有限路径构造/变换，流入文件读写/删除 sink；仅在缺少可验证 containment、basename 限制或显式白名单时产生 candidate。路径拼接本身不告警。

## 基线来源与配置

### 固定身份

- Scanner 仓库：`openHarmonyScanner`；隔离 worktree：`D:\openHarmonyScanner\worktrees\a-path-source-sink-1c21ac6`。
- Immutable base：`1c21ac60890fca0ce6be5d50d82e4757dd5e4623`（完整 SHA）；tree：`4c833e2452413a7e9a404199439fe0a797b74ae9`。该 SHA 是本机集成记录的 `origin/main`，并经对象存在和祖先关系验证；没有发现独立集成 workspace manifest。
- Contacts source：仓库 `openharmony/applications_contacts_data`，漏洞源码 commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`，tree `2054824c04bb403eeea128a9262edfb3001efa4f`，path `dataBusiness/contacts/src/contacts_data_ability.cpp`，blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`，SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`，85339 bytes。Source manifest：`research/deliveries/a-line-sample30/20261018/poc/ohscanner-contacts-path-traversal/source_manifest.json`；manifest 中 8 个源对象的字节数、Git blob SHA-1 和 SHA-256 均已逐个核验。
- 规则实现：`src/ohscanner/detectors/cpp/path_traversal_detector.py`，detector `ohscanner.cpp.path_traversal`，rule `ohcpp-path-traversal-candidate-001`，版本 `0.1.0-research`，实现 SHA-256 `f1d2742c1e131b0a4e7e1954ceeec68554749056696a16742efa54d45e54589d`（最终回归后的文件）。未加入 Runner/Catalog，故当前不可由产品 profile 选用；没有共享协议改动。

### A0 实际 run

检查了 A0 per-project 真实 run 三件套 `openharmony-full-scan-20261017/projects/0030-applications_contacts_data-422d26e1b7/{request.json,run_meta.json,result.json}`。SHA-256 分别为 `3f1b21c33a0683f8282ad5903ba319c149d63d442d9870acbb1ff4e0141a67c5`、`c6f0c106e3a45508b3428d6ae555ba34904e4ea8e86d8fc168b7b37ad684a979`、`c3f4faf6cb464a4ccdcc0f8fe5d43affe779dbd7501a95831639dac5c5589fb7`。实际 Detector set 为 `ohscanner.interface.ipc`、`ohscanner.cpp.lifetime`、`ohscanner.cpp.shared_ptr_race`；profile `light-ast`；scope `.`；source tree/snapshot 与上述 Contacts revision 一致。360 个 source files，选中字节 4,724,819；C++ 218、ArkTS 118、JS 14、TS 10；parse complete 199、partial 19、not_run 142。A0 diagnostics 0，validated vulnerabilities 0，运行 45.899 秒，无进程内存记录。运行时每 detector 状态：lifetime blocked/0 diagnostics，shared_ptr_race failed/0，IPC completed/0。A0 元数据没有记录 scanner commit，因此不把该计数解释为当前 detector 实现的等价重放。

### 当前 immutable-base 基线重放

在任何新 detector 代码修改前，以相同目标源码、`light-ast`/`.`，显式仅选 A0 三个 detector 执行 baseline。确切命令（WSL）：

```sh
cd /mnt/d/openHarmonyScanner/worktrees/a-path-source-sink-1c21ac6
/mnt/d/openHarmonyScanner/ohscanner-test-venv-python314/bin/python -m src.cli ohscan-run \
  --repo-dir /mnt/d/openHarmonyScanner/openharmony/applications/standard/contacts_data \
  --repository openharmony/applications_contacts_data \
  --commit 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 \
  --detector ohscanner.interface.ipc --detector ohscanner.cpp.lifetime \
  --detector ohscanner.cpp.shared_ptr_race \
  --json-out /tmp/ohscanner-a-path-20261018/baseline-result.json \
  --md-out /tmp/ohscanner-a-path-20261018/baseline-report.md
```

保存的原始输出：[`baseline-result.json`](../../evidence/cpp/path_traversal_20261018/baseline-result.json)、[`baseline-report.md`](../../evidence/cpp/path_traversal_20261018/baseline-report.md)。重放诊断总数 29（shared_ptr 25、IPC 4、lifetime 0），validated vulnerabilities 0；detector 状态为 lifetime blocked、shared_ptr blocked、IPC completed；运行 10.978 秒，子进程峰值 RSS 252360 KiB。此为 A0 配置在 immutable-base scanner 上重放，和历史 A0 的 0 diagnostics/45.899s 不同。由于 A0 没有绑定 scanner commit，差异只能归为 scanner/runtime 状态不可比，不能推断准确率变化，也不是新 candidate detector 导致。

## 漏检归因

基线 A0 实际运行 set 中没有路径 source-to-file-sink 规则；现有 `ohscanner.cpp.lifetime` 与 `ohscanner.cpp.shared_ptr_race` 的目标分别是生命周期与并发内存安全，IPC detector 也不是路径写入分析。因此对 Contacts 的路径流没有匹配规则/数据流边，baseline 未产生 path finding 是 detector coverage 缺口，不是已证明的 safe verdict。

针对 Contacts 的研究扫描直接绑定固定 Git source commit/tree/blob 与完整源码 SHA；没有将第三方源码摘录纳入 fixture 包。保存的 `candidate-direct.json` 记录该次独立 detector 运行在原文件第 811、822 行产生的 2 个 source-to-sink candidate identities，运行整体为 blocked，限制和 obligations 均保留。它不是完整产品复现或漏洞确认。

## 算法与误报边界

- Source model 需要可审计类型/表达式：签名中 `DataShareValuesBucket`，并识别 string accessor（`GetString`/`GetStringValue`）或对象 getter 后的 `get_if<std::string>`。不以 `PortraitFileName` 等字段名、单仓库、方法名或 source hash 为规则特例。
- Dataflow 限于单 translation unit：局部赋值/拼接、最多 4 轮有界 helper return/out-parameter summary；source 到 sink 必须有变量级流证据。预算：单文件 1 MiB、最多 256 function、最多 4096 calls。超限或分析异常时 fail closed 为 blocked/unknown。
- Sink 限于直接 POSIX 常见文件 API：`open/openat/creat/fopen/freopen/unlink/unlinkat/remove/rename/mkdir/rmdir`，并检查 `rename` 两个 path 参数。只有到达 sink 才可能有 finding；同样路径字符串但无 sink 不报。
- 认可的窄安全控制：basename-only `filename()`；字面量相等白名单分支；显式 canonical(root / untrusted) + canonical(root) + `lexically_relative(root)`，并在 sink 前拒绝 empty 与首组件 `..`。这是静态形状控制，不证明 symlink、TOCTOU、root 身份或平台 API 语义。
- Candidate 表示有限源码证据中观察到未被上述模型验证的 source-to-sink，不断言攻击者可控、可达、越界成功或造成影响。未知外部函数接收 tainted 参数、跨函数无法总结、宏、重载歧义、partial/failed/not-run parse 均保持 blocked/unknown；已观察到的 finding 不因其它 unknown 路径被删掉。
- 误报风险仍包括语义别名、模板/宏展开、间接 sink、平台 wrapper、错误/不完整安全转换识别、控制流分支/异常路径和 canonical 文件系统语义。误报/漏报边界尚未通过独立标签评估。

## 变更文件与回归矩阵

仅涉及 A ownership 的 detector、私有测试/fixtures 与研究交付/证据；没有改 Runner、Catalog、共享协议、B IPC、UI、平台代码或 A1 工件。scope 脚本检查 20 个路径、0 violations。

| 类别 | 控制 | 预期/结果 |
|---|---|---|
| 正例 | 外部 DataShare string → 路径 → `open`；`creat`/`unlink`；有界同文件 return helper | 到 sink 才有 candidate，通过 |
| 源码锚点 | 固定 Contacts source 的 hash-bound 直接运行 | 2 identities，整体 blocked/unknown，通过 |
| fixed | basename、canonical containment、literal allowlist | 无 candidate，通过 |
| 安全 | 普通 basename、受限目录路径 | 无 candidate，通过 |
| 无关 | 同名但非 DataShare / 非目标 API | 无 candidate，通过 |
| sink control | 相同路径但无文件 sink；只有路径 concat | 无 candidate，通过 |
| unknown | 跨函数、外部 wrapper、macro、partial parse、overload | blocked/unknown，不判 safe，通过 |
| 异常/预算 | oversized unit 与分析异常 | fail closed，通过 |

Fixture manifest `tests/detectors/fixtures/cpp_path_traversal/manifest.json` 将每类标为开发回归控制；不构成产品复现、真值或独立漏洞标签。

## 基线对比

| 运行 | scope/profile/source | candidate identities | coverage/status | elapsed / memory |
|---|---|---:|---|---|
| A0 历史实际 run | Contacts commit，`.` / `light-ast` | path detector 未执行；path diagnostics 0 | 360 files；complete 199 / partial 19 / not_run 142；三个实际 detector 如上 | 45.899s / 未记录 |
| immutable-base 同配置基线重放 | 相同 | 0 path candidates（detector 未注册） | 29 total diagnostics；0 validated vuln | 10.978s / 252360 KiB child peak |
| 研究 detector 直接运行 | 相同 Contacts commit/tree/scope/profile；直接调用，不经 Runner/Catalog | 2（Contacts source lines 811、822） | 分析 138/218 C++ units；blocked；87 limitation entries | indexing 1.732s + detector 0.670s = 2.402s；process peak 63464 KiB |

直接研究运行的完整机器结果：[`candidate-direct.json`](../../evidence/cpp/path_traversal_20261018/candidate-direct.json)。这里的 coverage 是 detector 可分析完整单元数量，不代表仓库安全覆盖。运行路径与 Runner 基线不同，资源数据只分别报告，不做性能提升结论。候选数减少或增加都不代表准确率变化。没有独立真值，未报告 Precision/Recall。

## 验证命令与结果

所有命令在隔离 worktree `D:\openHarmonyScanner\worktrees\a-path-source-sink-1c21ac6`；Python 为 `/mnt/d/openHarmonyScanner/ohscanner-test-venv-python314/bin/python`（WSL）：

```sh
python -m unittest tests.detectors.test_cpp_path_traversal_detector -v
# 7 tests, OK
python -m unittest discover -s tests/detectors -v
# 138 tests, OK
python -m unittest tests.test_shared_ptr_race_poc tests.test_lifetime_uaf_poc -v
# 14 tests, OK, skipped=2（本机未保留可选历史源文件）
```

Windows shell（仓库 Python 环境）执行：

```powershell
python -m scripts.check_change_scope --base 1c21ac60890fca0ce6be5d50d82e4757dd5e4623 --lane cpp --repo .
# 20 checked paths; violations=[]
git diff --check
# exit 0; no whitespace errors
```

A suite 已覆盖正例、fixed/safe/unrelated/no-sink、跨函数/外部/macro/partial unknown、预算和异常降级。WSL 下调用 scope checker 曾因 `.git` worktree 文件内的 Windows 绝对 gitdir 路径被 WSL Git 错误解释而失败；Windows Git 下同一 checker 成功，最终 scope 结果以 Windows 调用为准。

## Limitations 与后续建议

1. 在发现的固定源码资料中，所谓 fixed Contacts manifest 指向的仍是同一漏洞源码 commit/tree；本机 Contacts refs 也未包含对应产品修复对象。没有可核验的上游 fixed commit/blob，因此不能声称已对真实修复版验证。synthetic canonical-containment/basename/allowlist controls 仅检验规则边界。取得修复对象后应新增 hash-bound fixture，并保持源码身份审计。
2. Source 片段和 detector 是轻量 lexical bounded analyzer，不是完整 C++ AST、CFG、别名/宏/模板或 filesystem 模型；partial 和其它 unresolved 路径必须维持 unknown。
3. 新 detector 未公开注册；无需 shared catalog 修改，也没有 owner exposure request。若要纳入产品执行，后续应单独提交 A owner review request，并先补齐真实 fixed source、平台 wrapper/sink model 与更广泛安全控制评估。
4. 该研究没有判定漏洞可利用性、产品影响、恶意输入可达性或安全修复有效性；需独立验收和产品上下文分析。
