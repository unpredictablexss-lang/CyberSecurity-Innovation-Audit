# 队友 D：接口需求（初步 RFC）

日期：2026-10-17。状态：**拟议、待负责人审查**。本文中的字段、名称和伪代码不代表已实现接口。

目标检测器：拟议 `ohscanner.data.sensitive_exposure`；首发单规则 `data.log.sensitive-value`。

## 1. 请求背景

现有 SourceUnit/ScanContext、AST 摘要、Runner、Finding、EvidenceObligation 和 file_outcomes 可以复用。现有摘要不能完整表达语句顺序、赋值边、局部绑定、日志宏/格式化和类型身份；D 原型目前在独立模块中用 Tree-sitter 做私有详细语句遍历。

真实固定范围9文件中，公共 Runner 对6个 partial AST 文件不调用要求 AST 的检测器。其余3个也只有部分模型覆盖，因此需要先解决事实与覆盖资格，而不是只扩大规则。

## 2. 接口设计原则

- 负责人维护公共索引、合同、Runner、Catalog 和协议；D 不直接改动它们。
- 采用可选、版本化事实；未提供时返回 missing/unknown/partial，不伪造空集合代表安全。
- 同步保留仓库、commit、文件 SHA、profile、事实生产者/版本和证据来源。
- 区分“观察到语法依赖”和“证明类型、可达性、权限或实际影响”。
- 不把本线 Tree-sitter Node、任意网络客户端、Shell 或源码写权限变为公共输入。
- 事实只存符号、位置、关系和模型引用；不导出真实凭据值。
- 优先复用/扩展现有可选事实，不新增平行的通用 AST 或全局 Candidate 格式。

## 3. 当前可直接复用的合同

| 合同 | D 的用法 |
|---|---|
| SourceUnit | path/language/text/sha256/parse_status/parse_issues |
| ScanRequest | repository/commit/snapshot/profile/provenance 身份 |
| ScanContext.shared_facts | 请求可选事实，不擅自约定公共必填私有键 |
| Detector.detect | 使用实际 `detect(context, units)` 签名 |
| DetectorFinding | 单规则候选、位置、source_sha256、初步 CWE |
| EvidenceObligation | 类型、流程、日志读取权限、影响等待核实条件 |
| DetectorRun.file_outcomes | complete/partial/not_analyzed/failed 覆盖状态 |
| DetectorRegistry + run_reviewed_detectors | 在明确审查后做独立程序化实验，无需改 Catalog |

## 4. P0-A：局部语句、表达式和绑定事实

### 希望获取

- 函数/词法作用域 ID，形参位置、类型引用及声明绑定 ID。
- 表达式 ID、种类、源码范围、读写的绑定；成员字段与所属对象。
- 语句顺序、声明/赋值/覆盖、复制、调用参数和返回关系。
- 分支、提前返回、循环等结构以及“是否建立 CFG/路径证明”的明确状态。
- 不支持表达式及宏区域的范围和原因。

### 输入示例

```cpp
void Example(SessionKey *item) {
    const char *alias = (const char *)item->value;
    AUTH_LOGI(AUTH_KEY, "%{public}s", alias);
}
```

### 期望观察

`item.value → alias → call.argument[2]`，每条边可回溯文件 SHA 和位置。材料敏感性由 D 的模型判定，平台不直接宣布泄露。

### 必须通过的反例

- `alias = "redacted"` 后不能继续沿旧赋值当作当前敏感值。
- 内层同名变量不污染外层绑定。
- `item->len` 与 `item->value` 是不同字段。
- 条件/循环导致的可能传播保留未知可达性。
- 未解析间接调用不能制造 resolved_target。

## 5. P0-B：日志格式与宏到操作数的映射

### 希望获取

- 原始调用、已解析目标或宏定义引用，目标身份状态。
- 格式参数索引、解析出的固定格式或未知原因。
- 每个占位符的格式、public/private/default 状态、对应实参索引。
- `%%`、`*`宽度/精度、拼接字符串、PRI宏和位置参数的支持状态。
- 宏变体、构建 profile 与隐私规则模型的证据引用。

### 关键验收例

```cpp
AUTH_LOGI(AUTH_KEY, "%{private}s %{public}u", key->value, key->len);
```

应明确：私有字符串槽对应 value，公开整数槽对应 len。不能因为格式串中出现一次 public 就把 value 判为公开。

`%{public}*s` 的宽度和字符串是两个参数；`%%` 不消费参数。解析不了的 PRI/动态格式必须标未知，不能错位猜测。

默认 private 的推导须绑定具体 API 模型；不能套用到所有 printf 包装。生产隐私开关未证明时，不能把输出策略当作已验证产品安全保证。

## 6. P0-C：partial AST 的可分析区域与资格策略

### 请求负责人决定

1. 哪些错误允许局部分析，哪些错误必须整文件跳过？
2. 能否提供不含错误节点的函数/语句区间及其证据？
3. 如何区分文件解析完整性与规则分析覆盖？
4. 如何防止错误的宏分支、绑定或漏掉的前置语句影响“完整区域”结论？

### 验收要求

- 不允许检测器私自把 partial 改成 complete。
- 每个适用文件必须有且只有一个聚合结果，计数能闭合。
- 部分检查得到的候选和义务仍应保存，并清楚标注受限上下文。
- failed/not_analyzed 不能当作 miss 或 safe。
- 任何策略调整需要公共 Runner 兼容性测试，也要保留其它检测器既有行为。

## 7. P1-A：类型、调用身份和 out/status 语义

### 希望获取

- 源文件/头文件限定的类型及字段身份、typedef/using 来源。
- 调用的实际符号、参数到形参映射、是否为函数指针/同名局部定义。
- 受审 API 的输入、输出缓冲区、返回状态/长度等有限效果摘要。
- 解析失败、歧义和动态目标必须可单独表达。

### 验收例

`SoftBusGenerateSessionKey(out, n)` 中 out 为输出材料，返回 rc 是状态。不能把 rc 当材料；也不能认为调用一定成功或 out 已初始化。若它是同名函数指针或另一个库的函数，应拒绝套用模型或保留未知。

本地冒名 `struct SessionKey` 不能仅因名字相同被认定为官方会话密钥类型。

## 8. P1-B：模型来源与版本绑定

每条 source/sink 模型建议具有以下信息，最终字段名由负责人统一：

| 信息 | 用途 |
|---|---|
| model_id/version | 规则及模型升级时冻结旧解释 |
| repository + exact commit | 防止跨组件/版本误用 |
| definition file/blob/SHA + source range | 核实语义依据 |
| type/symbol/parameter/field identity | 绑定真实作用对象 |
| sensitivity rationale | 为什么是秘密材料，而非公开标识或状态 |
| build/profile/privacy assumptions | 明确生效前提 |
| review_status/evidence_refs | 区分拟议模型与已审核模型 |

默认不把一个已研究提交外推成“整个版本范围都支持”。模型跨版本沿用需要检查相应定义和调用语义。

## 9. P2-A：日志可观察性与验证事实

静态日志候选之外，还需可选证据：量产/工程配置、最低日志等级、隐私开关、日志落盘与权限、读取主体、保留周期、输出值可恢复性，以及是否跨授权边界。

这些证据可能来自构建配置、部署说明、人工审查和隔离重放，不能由“调用了 AUTH_LOGI”自动推断。没有证据时保持 unknown。

若接入验证，复用统一隔离 Worker，并用合成凭据。D 只提供家族级样例/断言，不另建运行系统或执行任意日志抓取命令。

## 10. P2-B：受限一跳调用摘要

后续再申请明确目标的一跳参数/返回/输出参数传播，带调用目标、输入输出映射、支持语句范围、递归/间接调用状态及预算。跨文件身份不明确时停止扩展，不猜测全程序路径。

验收例：公开日志包装的 format/参数索引保持正确；安全脱敏包装必须有语义证据，不能把任意 Hash/Mask 函数认定为充分脱敏。

## 11. 拟议事实外形（仅讨论示例）

下面不是已存在 JSON Schema，也不应直接提交到公共合同：

```json
{
  "fact_schema_version": "PROPOSED",
  "source": {
    "repository": "owner/repository",
    "commit": "FULL_COMMIT",
    "file": "service.cpp",
    "source_sha256": "FILE_SHA256",
    "profile_id": "PROFILE"
  },
  "producer": {"id": "OWNER_APPROVED_PRODUCER", "version": "VERSION"},
  "coverage": {
    "parse_status": "partial",
    "supported_regions": [],
    "unsupported_regions": []
  },
  "bindings": [],
  "value_edges": [],
  "log_operands": [],
  "limitations": ["No path feasibility, runtime visibility or impact proof"]
}
```

负责人可以选择把这些信息适配进现有 facts，而不是新增这个结构。字段中的占位值仅作说明，不能作为真实证据。

## 12. 最小协作与验收顺序

1. 确认 D 的拟议 ID 与单规则边界；保留当前补丁和证据。
2. 优先选 P0-A/B/C 中能解除实际阻塞的最小一项，不要求一次建完整语义平台。
3. 负责人提供可选事实版本及小型适配示例，D 添加正例、修正、安全、非目标和未知回归。
4. 既有公共回归、A/B/C 行为兼容检查与 D 专项均通过。
5. 使用冻结9文件范围复测，逐条解释候选/覆盖变化；不把数量变化称为准确率提高。
6. 负责人决定 Catalog 注册和 Draft PR 选择性集成，之后再安排真实修复对及独立 holdout。

本文只是接口申请。实现、冻结协议、注册平台和升级漏洞结论均未由本文自动授权或完成。

## D2 最小请求（2026-10-17，未获公共修改批准）

固定commit0e0c18c4的auth_session_key.c因LIST_FOR_EACH_ENTRY缺失标点被整文件跳过；私有探针
30函数中15个无直接错误交叠。这不是自动准入证据。优先请求一个可选函数事实：
file/blob/SHA、profile/解析器版本、函数范围、错误范围、局部绑定/赋值和日志operand，
并保留外围宏/类型依赖缺口。负责人先定义错误隔离/资格及兼容性测试，再考虑准入；
D不修改Runner。头文件单独提供受审声明/宏事实，不把无函数头文件说成flow complete。
验收最小对照：返回分支不流向后继、存活else继续产生候选；相同固定9文件覆盖计数闭合；
partial候选与unknown独立保留，不改A/B/C语义。完整依据见D2_COVERAGE.md/json。
