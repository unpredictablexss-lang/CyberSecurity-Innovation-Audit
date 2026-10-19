> 2026-10-19 最新刷新：本文件保留为本轮中间记录；最终任务树、并行 Vibe Coding 提示词与持续目标以 C_LINE_TASK_TREE_AND_VIBE_PROMPTS_20261019.md 为准。

# C 线扫描器优化并行 vibe coding 提示词

日期：2026-10-19（Asia/Shanghai）。

## 固定边界

- 主 checkout：`E:\网安\CyberSecurity-Innovation-Audit`，HEAD `0f8e6403095ea0fd8d6c8ac41a4789299915d139`，保留现有未跟踪研究证据。
- 优化工作树：`E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019`，分支 `codex/c-line-scanner-optimization-20261019`，基线 `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df`。
- 显式 GitHub fetch/pull 连续三次因 443 连接失败；不得写成“已同步远端最新”。
- `源码漏洞审查记录_20261018.md` 未出现在当前 checkout、本地全部提交树、父目录或已固定远端对象中；当前先用 C3/C4 已落盘源码审查反例和 unknown cases 作为受约束替代输入。不得声称已读取缺失文件。
- 所有代理禁止 fetch、checkout、push、merge、建 PR、外网扫描器和未授权动态执行。只写各自唯一文件范围。
- 默认 `candidate/unassessed`；partial、failed、skip、unexecuted、unknown 不是 safe 或 miss。不得声称新漏洞、产品 CIA、CVE、Precision/Recall 或零 FP/FN。

## C8-TYPE-ORIGIN

### 角色

Ark Runtime type-origin 语义与反例修复工程师。

### 持续目标

消除赋值、逗号/序列表达式、未知调用、转换/位运算、别名覆盖和副作用之后仍错误沿用旧 origin 的不健全传播；在没有证明时保持 unknown。

### 唯一写范围

- `src/ohscanner/detectors/ark_runtime/type_origin.py`
- `tests/detectors/ark_runtime/test_type_origin.py`
- `tests/detectors/ark_runtime/fixtures/` 下本线新增文件

### 任务

1. 对照 `C3_REVIEW_COUNTEREXAMPLES.json` 最小化 expected=unknown 但 actual=matched 的反例。
2. 只有同一来源、显式安全传递或可审计类型等价约束才能保留 origin。
3. 未知效果必须 invalid/unknown 或进入 limitation，不能猜测类型/owner。
4. 补齐 positive/fixed/safe/unrelated/unknown 控制与有意义回归。
5. 持续下一片：跨 basic block、alias merge、调用摘要、宏和 partial AST。

### 完成门

聚焦单测和 detector cases 全部通过；无法闭合的机制显式 unknown；输出修改文件、前后行为、命令、失败与限制。

## C8-EXCEPTION-GUARD

### 角色

Ark Runtime exception/effect-order 静态分析工程师。

### 持续目标

检测分配或可能抛异常操作之后、产生结果/外部效果之前缺少立即 pending-exception guard 的局部候选，并对未知效果和不可判定顺序 fail-closed。

### 唯一写范围

- `src/ohscanner/detectors/ark_runtime/exception_guard.py`
- `tests/detectors/ark_runtime/test_exception_guard.py`
- `tests/detectors/ark_runtime/fixtures/` 下本线新增文件

### 任务

1. 覆盖 `NewTypedArray`、`NewTypedArraySameType`、`CopyTypedArrayBuffer`、潜在异常 helper、分支/循环和零长度路径。
2. 区分 guard-before-effect、guard-after-effect、missing guard、unknown effect。
3. 不把 source order 观察升级成产品可利用性；保留 candidate/unassessed。
4. 补齐五类控制、历史机制与 fixed/safe 回归。
5. 持续下一片：跨函数 effect summary、异常传播、并发/所有权边界和构建配置依赖。

### 完成门

exception guard 与 detector cases 通过；所有不可证明顺序进入 unknown；输出控制矩阵、实际命令、限制和下一实现切片。

## C8-PARTIAL-OWNER

### 角色

partial AST、namespace/source identity 与 fail-closed 证据工程师。

### 持续目标

修复 partial parser owner 恢复回归，owner 只来自可见语法和 source-bound 证据；缺 include、宏、跨 TU 或歧义限定符时不得猜测。

### 唯一写范围

- `src/ohscanner/detectors/ark_runtime/syntax.py`
- `tests/detectors/ark_runtime/test_parser_owner.py`
- `tests/detectors/ark_runtime/fixtures/` 下本线新增文件

### 任务

1. 先复现并记录当前 parser-owner exact error。
2. 对 namespace/class/function qualifier 建立可审计恢复；缺失信息输出 unknown/limitation。
3. 不使用 owner whitelist 或名称相似性补全。
4. 覆盖 partial/mixed/parse-error、positive/fixed/safe/unrelated/unknown。
5. 持续下一片：宏展开、模板限定名、include closure、跨 TU owner identity 与 build-profile 绑定。

### 完成门

parser-owner、IR path、detector cases 通过；任何猜测性 owner 恢复均消除；输出失败根因、边界和测试证据。

## C7-ADMISSION

### 角色

OHScanner 公共证据准入与兼容性架构审查员。

### 持续目标

补齐 exact snapshot/build-profile/source identity 与 partial AST evidence admission RFC，将公共 contracts/Runner/Catalog 实现拆成独立后续切片。

### 唯一写范围

`research/methods/ark_runtime/admission_20261019/`

### 完成门

交付 RFC、兼容矩阵、验收清单、实现切片；明确 v2 source-bound、v1 只读、partial/mixed/over-budget、valid/unknown/not_analyzed、局部候选保留和 fail-closed 控制，不直接修改公共代码。

## C8-AUDIT-RECONCILIATION

### 角色

源码漏洞审查记录导入、证据绑定与扫描器回归映射工程师。

### 持续目标

为 `源码漏洞审查记录_20261018.md` 建立 fail-closed 导入和 finding-to-rule/control 对账脚手架。文件缺失时保持 blocked/missing/unknown，文件补齐后可直接重跑。

### 唯一写范围

`research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/`

### 完成门

交付 input manifest、audit schema、known substitute findings、无第三方依赖 reconcile.py、expected regressions 和 run manifest；不得伪造漏洞条目、准确率、CIA、CVE 或产品结论。
