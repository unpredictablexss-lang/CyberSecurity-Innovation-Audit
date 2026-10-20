# Contacts 固定源码复测：B 私有语法归一化与候选覆盖

日期：2026-10-19
B 集成工作树：`work/ipc-20261017`，HEAD `2fee193dd2d8a1849ac31e0683baef8c9a59d9c3`（本次运行包含未提交工作树改动）
Detector：`ohscanner.interface.ipc` 0.12.12；model `oh-ipc-2026.10-v32`

## 目的

核验 B 的私有语法归一化能否读取 Contacts 中因 `#include` 结束空格触发 Tree-sitter error 的 `poster_call_stub.cpp`，并确认这种局部恢复不会伪装成共享解析完整、不会抹掉候选的 unknown 义务。

## 固定输入

- Repository：`openharmony/applications_contacts_data`
- Commit：`341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`
- Tree：`2054824c04bb403eeea128a9262edfb3001efa4f`
- Scope：全仓 `--include .`
- 文件：`dataBusiness/poster/src/poster_call_stub.cpp`
- Git blob：`7cf9459f8f3b360dd85ba1587afc2a792e8a79fa`
- 原始源码 SHA-256：`da61331914d7d1f92afea3b58eff862d0b1b2f98ec102258d7807cf8798a7f50`
- 触发形状：第 21 行 `#include "contacts_common_event.h" `，闭引号后一个 ASCII 空格再接 LF。

B 分析代码文件哈希：

- `src/ohscanner/detectors/interface/analysis.py`: `84bf0d20089c10ee08c0b42c5799b650b234217af2b663ed4b63bd857143f374`
- `src/ohscanner/detectors/interface/m2_adapter.py`: `80cd2ccd7466de7fb208a08207fe928598fe9546ef6343a1b475c4bd3c24c2fe`
- `tests/test_ipc_detector.py`: `835c1afb82ad50a98b6e0614ec9ca50b99593cddc78bd4489386b80f9a8ddf45`

## 局部归一化探针

对固定 Git blob 读取原始 bytes；只在 B 私有 parser 输入副本中将该形状的尾随空格改为 CR。结果：

| 指标 | 原始源码 | B 私有解析副本 |
|---|---:|---:|
| Tree-sitter root error | 是 | 否 |
| 字节长度 | 1,815 | 1,815 |
| LF 偏移集合 | 基准 | 完全相同 |
| 函数定义 | 3 | 3，起止行一致 |
| 调用表达式 | 9 | 9 |

Git blob、原始 source hash、对外 SourceUnit 及公共 parse status 均不变。该探针只证明此一精确语法形状的内部解析恢复，不证明编译器语义等价，也不代表该文件在公共 parser 中变成 complete。

## 可见性宏归一化探针

继续分层复核 Contacts 的 19 个 partial 文件后，发现两个生产头文件的 Tree-sitter error 来自行首声明标记 `EXPORT` 与 `FFI_EXPORT`。在 B 私有语法副本中，仅当这两个精确 token 位于声明行首且后接已知内建类型或限定类型时，将 token 按等长空格处理；Git 原文、宏定义、SourceUnit 和公共状态均不改。该变换针对构建可见性标记，不改变权限/鉴权判断。

- `contacts/include/contacts_napi_utils.h`：归一化后私有 parse clean。
- `contactsCJ/include/contacts_ffi.h`：覆盖 `OHOS::ContactsFfi::...*` 返回类型后，归一化后私有 parse clean。
- 二者在公开 parser 仍是 partial；整仓 public parse 计数不能因此改写。
- 新增正例及反例测试，覆盖 built-in/qualified return types、变量名、相似函数名、注释及宏定义，确认长度和 LF 偏移不变。

## 接口描述符宏归一化探针

其余四个 IPC 头文件的 parser error 都由 `DECLARE_INTERFACE_DESCRIPTOR(u"literal")` 触发。OH IPC 接口文档说明该宏声明接口标识；项目中的 AUTH-01 Harness 记录了从真实 `iremote_broker.h` 复制的宏形态。B 私有 parser 只对**单个、不含转义的 u/U/L 字符串字面量参数**将整个调用等长留空；复杂表达式或其他参数形状保持原样并继续 partial。

描述符事实不会丢失：扫描器现有 `descriptor_symbol_expectation` 从未改写的 `SourceUnit.text` 读取接口宏中的字符串，并与实现侧符号进行比较；本归一化只影响私有语法树。固定 Contacts 的四个对应头文件私有 parse 均由 error 变为 clean，source bytes、blob、source hash 和公开 parser 状态不变。

## 全仓 CLI 复测

命令：

```bash
.venv-web/bin/python -m src.cli ohscan-run \
  --repo-dir /home/audit/oh-audit-targets/bline-campaign-100-retest-20261018/applications_contacts_data \
  --repository openharmony/applications_contacts_data \
  --commit 341cc3bf41b48e9a5f278dd088f40a2041d2f1c9 \
  --include . \
  --detector ohscanner.interface.ipc \
  --json-out /tmp/ohscanner-ipc-descriptor-macro-20261019/contacts.json \
  --md-out /tmp/ohscanner-ipc-descriptor-macro-20261019/contacts.md
```

实测结果：

- `status=completed_with_limitations`；固定 `git_tree` 与目标一致。
- `scope_files=218`，`scope_loc=61,024`，诊断 4 条，`validated_vulnerability=0`。
- 公共源解析状态：199 complete / 19 partial / 142 not_run；此次复测没有改变其覆盖口径。
- `poster_call_stub.cpp:44`、`:46` 的 `ipc.relay.descriptor-boundary` 候选仍在，来源 SHA-256 与固定原始文件一致；候选仍须复核 entry reachability、接口边界与安全影响。
- 其它两条观察为 `contacts_common_event.cpp:45` 的 `ipc.auth.missing` 和 `:67` 的 `ipc.relay.descriptor-boundary`。
- 与八仓基线报告 `research/deliveries/ipc/20261019-eight-component-current-v0.12.12/applications_contacts_data.json` 比较：候选按 `(file, line, rule_id, source_sha256)` 完全相同，4→4；新增 0、消失 0。解析计数也完全相同。
- 新 JSON SHA-256：`04d875eb9f5517b6daff7122cfebf7360b5edef89897255bac1ed59705952977`。

三类私有归一化均没有改变候选集合，也没有降低组件公开 partial 文件数。结果证明 B 私有解释器可以在固定原文的等长副本上恢复这些已审查语法形状；当前 Contacts 候选仍为 4，新增 0、消失 0。它不应表述为全仓“覆盖率提高”或“漏洞确认”。

## 回归

```text
.venv-web/bin/python -m unittest discover -s tests -q
Ran 734 tests in 22.072s
OK (skipped=36)
```

## 复现边界与后续

- 本次是固定公开源码的静态复测；没有产品编译、设备 PoC、Agent/Harness 运行，也没有独立 holdout。
- `validated_vulnerability=0`；4 条诊断仍是候选，不是 4 个漏洞。
- 更广的 shared parser 完整覆盖修复仍需公共 Parser owner 处理；B 不改公共 parser/runner/contracts。
- 更有价值的下一步是对 19 个 partial 文件做按错误形状分层，确认哪些错误会改变 IPC entry/guard/call-chain 恢复；只有能证明新增/修正候选身份的窄修复才作为召回改进，单纯把状态改成 complete 不算。

复测产物保存在 `/tmp/ohscanner-ipc-descriptor-macro-20261019/`，不随源码提交；本 Markdown 记录固定对象、命令、结果和边界。
