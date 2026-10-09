# MethodCard: cpp.lifetime.unique-raw-alias-reset-v1

> 状态：detector-local **proposed implementation**。Detector Contract v1 尚未冻结，本文不宣称 `src.ohscanner` 插件接口已经可运行。
> 选定方向：`cpp.lifetime`。`bounds/length/Parcel` 仅完成独立研究切片，未提升为本轮正式 detector。
> 结果边界：只产生 `candidate / unassessed / validation_status=not_run` 的描述性静态证据；不自报 `confirmed`、`possible_hit`、`miss`、safe 或漏洞结论。

## 1. 问题与精确适用范围

本 detector 只处理一种所有权/生命周期形状：

1. 同一个已解析 C++ 函数内显式声明 `std::unique_ptr<T> owner`；
2. 通过 `T* alias = owner.get();` 建立 raw alias；
3. 之后执行 `owner.reset(...)`，使 alias 所指旧对象的生命周期不再由该 owner 保持；
4. 在没有 `alias = owner.get();` 重新绑定之前，出现 `alias->...`、`(*alias)...` 或 `*alias` 解引用；
5. 对 reset 与解引用做一种同步约束分类：是否位于同一个 `std::lock_guard` / `std::unique_lock` / `std::scoped_lock` 词法作用域。

同步分类**不会抑制候选**。锁只能说明观察到的词法区域可能被同一互斥对象串行化，不能证明旧对象仍存活，也不能证明锁序、条件变量、回调、跨线程 alias 发布或析构顺序。

## 2. required_facts

入口元数据：

- `detector_id = ohscanner.cpp.lifetime`
- `version = 0.1.0-proposed`
- `supported_languages = ("cpp",)`
- `required_facts`：
  - `repository_commit_profile_provenance`
  - `source_path`
  - `source_text`
  - `source_sha256`
  - `parse_status`

`lexical function block`、`ownership operation`、`raw alias`、`sync scope` 由本 detector 从 `source_text` 的有限语法切片计算，不要求主线新增公共 IR 字段。没有 `complete` 解析覆盖时不分析该文件，并保留真实 `partial/failed/not_run`。

## 3. 参考样本与数据拆分

当前 fixtures 全部是**自建 synthetic development fixtures**，不是公开 OpenHarmony 漏洞基准：

- vulnerable：`tests/detectors/fixtures/cpp_lifetime/vulnerable_unserialized.cpp`
- vulnerable + mutex scope：`tests/detectors/fixtures/cpp_lifetime/vulnerable_inside_mutex.cpp`
- fixed：`tests/detectors/fixtures/cpp_lifetime/fixed_alias_rebind.cpp`
- safe control：`tests/detectors/fixtures/cpp_lifetime/safe_use_before_reset.cpp`
- partial/unknown：`tests/detectors/fixtures/cpp_lifetime/partial_parse_macro_context.cpp`
- failed：`tests/detectors/fixtures/cpp_lifetime/failed_parse_unbalanced.cpp`

固定来源、fixture 类别、parse 状态和逐文件 SHA-256 在 `tests/detectors/fixtures/cpp_lifetime/manifest.json`。独立 holdout 尚未执行，设计见 `research/methods/cpp/cpp_lifetime_holdout_plan.md`；不得把上述开发 fixtures 当独立测试成绩。

## 4. 对照工具和工具证据

本轮没有运行 Semgrep、Cppcheck、Clang SA、CodeQL 或 Joern，也没有复制第三方规则、查询或实现。正式 detector 运行路径只使用 Python 标准库和传入的 source units，不启动外部扫描器。

历史工具记录只作为研究背景，不向 detector 导入 vulnerability verdict。`.reset()` 规则命中、文件/符号重叠或单条 warning 都不作为本 detector 的漏洞证明。

## 5. 自研算法草图

1. 对文本做保偏移的注释/字符串掩码，保留换行和位置；
2. 识别显式 `std::unique_ptr` owner、`owner.get()` raw alias、`owner.reset()`；
3. 用大括号配对得到有限函数与块作用域；
4. 只在同一函数 span 内按位置检查 `reset` 后是否有 alias 解引用；
5. 若 reset 与 use 之间出现同一 alias 从同一 owner 重新 `get()`，抑制候选；
6. 分类 reset/use 是否处于同一个 mutex lock scope；
7. 生成稳定 `diagnostic_id`，按 `(file,line,column,diagnostic_id,rule_id)` 排序并折叠重复 ID。

复杂度：文本/正则扫描为 `O(N)`；当前简单事件配对最坏为同一函数内 `O(A*R*U)`（alias、reset、use 事件数），适合窄原型，不代表全仓性能结论。

## 6. 为什么结构匹配之外仍不足

结构顺序只能说明“看起来可能在旧对象失效后使用 alias”。仍缺：

- 所有可达路径上的 guard dominance、early return、exception 与析构顺序；
- alias 是否逃逸、复制、闭包捕获、存入容器或跨函数传递；
- `reset` 参数是否建立新 owner，以及新旧对象和 alias 的真实绑定；
- 宏展开、模板实例化、编译配置和类型系统事实；
- 并发 happens-before、锁序、条件变量、回调和线程可见性；
- attacker control、安全影响与运行时触发。

因此证据类型只使用 `syntax`，confidence/severity 均为 `unassessed`。

## 7. OpenHarmony 专用约束

- 明确区分执行状态、解析覆盖和 benchmark 匹配状态；
- 输出 candidate sidecar，默认 `review_status=unassessed`、`validation_status=not_run`；
- mutex 事实只作为同步约束描述，不被解释为 lifetime proof；
- partial/failed/not_run 文件产生未知覆盖，不产生安全或 miss 结论；
- detector 不修改受检源码、不联网、不生成 exploit/PoC、不提升 review/vulnerability 状态。

## 8. 修复例、安全对照和失败/未知行为

- fixed：`reset` 后重新执行 `alias = owner.get()`，最终整合版不报；
- safe：先使用 alias，再 reset，最终整合版不报；
- partial：宏控制 reset 上下文未展开，不分析，coverage=`partial`；
- failed：合成的不平衡 reset 输入，不分析，coverage=`failed`；
- 输入 SHA 不匹配时，detector run=`failed` 且保留该文件失败记录，但不隐藏其它有效 unit 的候选。

## 9. 消融结果（本轮真实运行）

| 模式 | vulnerable | vulnerable+mutex | fixed | safe | partial | failed | 总诊断 |
|---|---:|---:|---:|---:|---:|---:|---:|
| base pattern | 1 | 1 | 1 | 0 | 0（未知） | 0（失败） | 3 |
| + alias liveness/rebind suppression | 1 | 1 | 0 | 0 | 0（未知） | 0（失败） | 2 |
| + sync-scope classification | 1 | 1 | 0 | 0 | 0（未知） | 0（失败） | 2 |

解释：alias rebind constraint 消除了 fixed fixture 的结构误候选；sync classification 不改变当前计数，只增加 `same_scoped_mutex_lock` 约束事实。这个结果只说明开发 fixture 行为，不是准确率或泛化结论。

## 10. 结果映射与状态语义

详见 `research/experiments/cpp/toolrunresult_v1_mapping_design.md`。简要地说：

- `detector_id/version -> tool/tool_version`
- candidate -> 现有 `ToolDiagnostic`
- `coverage[].parse_status -> ToolRunResult.parsing`
- explanation/limitations/constraints/missing_obligations/source_sha256 -> detector-local sidecar
- `completed/failed/blocked` 只映射执行状态
- detector 不输出 benchmark `possible_hit/miss/unknown/not_applicable`

## 11. 许可证与 provenance

本方法、代码、fixtures 和测试均为本分支自建；未复制第三方源码、规则、查询或数据库。仅使用 Python 标准库和仓库已经存在的 `src.benchmark.tool_result.ToolRunResult/ToolDiagnostic` 作为只读映射目标。无第三方许可证附加项。

## 12. 不成立或未验证的安全命题

- 不证明任何真实 OpenHarmony 代码存在 UAF；
- 不证明 mutex 能延长对象生命周期；
- 不证明 candidate 可达、可触发、可利用或具有安全影响；
- 不计算 Precision/Recall、false positive/negative 或全仓覆盖；
- 不把空诊断解释为 safe，也不把 partial/failed 解释为 miss。
