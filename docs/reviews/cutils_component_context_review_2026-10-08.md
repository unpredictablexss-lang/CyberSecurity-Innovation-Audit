# c_utils 固定版本静态上下文审查

日期：2026-10-08。源码提交 b807d3dadb7dbb7639fe85b3a5f72da18d318da2。
本次为助手的静态上下文审查，不是人工批准、动态验证或漏洞确认。

## 覆盖问题与编译分析

首轮 AST 的 30 个部分解析文件中，生产代码 6 个、测试代码 24 个。以下为源码中
观察到的语法/配置上下文，不能把相关性直接当作解析失败的唯一原因。

| 生产文件 | 观察到的上下文 | 本轮处理 |
|---|---|---|
| safe_map.h | 显式调用 operator=(rhs) | 保留 AST partial；未单独实例化该模板 |
| unique_fd.h | friend 模板比较运算符声明 | 保留 AST partial；不能声明所有模板路径已覆盖 |
| thread_safety_analysis_macros.h | 条件编译的 extern C 块与注解宏 | 保留 AST partial，未删改注解 |
| ashmem.cpp | Rust 分支下不同函数签名 | host 源文件列表不包含它，设备/Rust 路径仍未分析 |
| io_event_epoll.cpp | UTILS_FDSAN 条件分支中的 close/fdsan_close 结构 | host Clang TU 通过，设备分支仍未覆盖 |
| parcel.cpp | (this->*Write)(v) 等成员函数指针调用 | host Clang TU 通过；原始 AST partial 不改写 |

测试代码含 HWTEST_F 等宏，需结合原始宏定义和测试依赖继续归类。没有剥离宏或
修改第三方源码来让解析看似完整。Clang 某个配置下成功，不自动消除其他引擎的 partial。

## 生产代码诊断分层

首轮 Cppcheck 生产代码共 40 条：24 条 syntaxError 作为覆盖问题；其余 16 条主要为
functionStatic、useStlAlgorithm、virtualCallInConstructor、functionConst 和 unreadVariable。
Semgrep vendor 生产代码共 104 条：53 条 interesting-api-calls、22 条 access/stat 模式，
其余包含类型转换、释放操作、位运算等模式提示。API 出现或操作符形状本身不足以证明风险。

上下文记录保留 tool、原始运行状态、报告 SHA-256、诊断位置、源码上下文及未知审查字段。
加入 Clang 1 条 warning 和 CodeQL 11 条诊断后，生成 132 条生产代码待审查条目：
104 + 16 + 1 + 11。未去重、未合并根因，不能称作 132 个问题，更不能称作漏洞。
Clang 的 30 条路径 note 单独保留，不作为 30 个额外候选。

### 已查看的代表性上下文

- unicode_ex.cpp:187 的 utf8Len 分配提示：代码在加 1 前检查 utf8Len < 0 或 >= INT_MAX。
  :210 的 free(str8Temp) 对应辅助函数 Char16ToChar8 内的 calloc。规则没有跨函数绑定
  完整分配/释放关系；当前诊断不具备“已确认释放器不匹配”的证据。
- refbase.cpp 的 delete this 与引用计数/自销毁上下文相关；thread_ex.cpp 的 delete t
  与线程参数生命周期相关。仍需关联分配点、所有权与调用路径，不按释放语句直接定性。
- event_demultiplexer.cpp:185、event_handler.cpp:41、io_event_reactor.cpp:247/254 的
  位与操作位于事件掩码判定中。单靠 typos 规则不能证明本应使用逻辑与。
- CodeQL 的重复 include guard 涉及 4 对头文件、8 条诊断。已核对同名宏确实存在：
  event_demultiplexer.h / io_event_epoll.h，event_reactor.h / io_event_reactor.h，
  event_handler.h / io_event_handler.h，common_timer_errors.h / common_mapped_file_errors.h。
  后续需检查实际组合包含和行为影响；本次不修改公共组件头文件或声明安全影响。

## Parcel 的 Clang 候选

Clang 14 报告 parcel.cpp:404 的 core.uninitialized.Assign，源位置为 WritePadBytes
对数据与 mask[padSize] 的读改写。路径经过 WriteString16Vector → WriteVector →
EnsureWritableCapacity → WritePadBytes，并在路径 note 中给出 padSize=4032。

源码 parcel.h:819 的 GetPadSize 使用 size_t 表达式
`(((size + 3) & (~size_t(3))) - size)`，实际函数中的 SIZE_OFFSET 是 size_t。
该对齐差值按无符号模运算应位于 0～3；4032 与此约束不一致，需要进一步核对分析器
内联/约束丢失及分配器初始化模型。当前路径不能作为可达越界或新漏洞的证明。
原生 warning 与完整 note 均保留；reachability、input_control、security_impact 为 unknown，
runtime_validation 为 not_run。未执行 PoC、触发用例或动态验证。

## CodeQL 证据机制修正

本轮 11 条结果包含重复 include guard、冗余 free 前判空、注释代码与枚举风格提示，
不是统一的源到汇数据流证据。CodeQL adapter 不再仅凭 provider 名字将所有结果标为
dataflow，默认 evidence_type=unknown；具体机制须审查查询和原生 SARIF。
已有 SARIF 已重新归一化，查询本身和第三方规则未修改。历史分支尚未引入该公共修正。

## 待继续核验

逐条审查高价值生产代码候选；确认 Parcel 分析器路径的约束；准备产品锁定的依赖版本、
GN 导出的真实编译数据库，以及设备/Rust/测试配置。host 结果只覆盖声明的 21 个 TU，
不作为完整 OpenHarmony 产品或所有模板实例化的验收依据。

## 2026-10-09 候选字段与 AST 归因补充

现有 132 条生产待审查条目已逐条补齐可复核字段并绑定源报告路径与 SHA-256。
其中 Semgrep 104、Cppcheck 16、Clang SA 1、CodeQL 11，未去重合并。每条均保留
精确位置与上下文，并显式记录 input_control、destination_capacity、length_origin、
guard_evidence、reachability、security_impact、runtime_validation。未裁决字段保持
unknown，运行时保持 not_run；全部仍为 candidate / unassessed / draft，
validated_vulnerability=0。这里的 132 是审查账本条目数，不是问题数或漏洞数。

30 个 AST partial 文件已逐文件记录候选归因：生产 6、测试 24。生产侧区分模板或
未实例化、宏/注解、条件编译、成员函数指针或解析器方言；测试侧以测试框架/注解宏
为主，并保留条件编译、模板等相关上下文。所有归因均为 candidate_cause，
source_syntax_status 与 real_syntax_issue_status 保持 unknown。没有通过剥离宏、
删改注解或修改第三方源码来消除 partial。

Joern 4.0.649 的 nothrow/判空结构查询已绑定固定组件快照、123 个 C/C++ 文件哈希、
查询路径/SHA 和完整执行日志执行。c2cpg/查询退出 0，但解析覆盖只发现 62 个生产
文件且有 8 次 CASTProblem，61 个测试文件无覆盖行，因此结果为 blocked/unknown。
0 条查询命中不是 miss 或安全证明。设备、Rust、ashmem/设备分支、测试代码、
未实例化模板和产品 GN 编译数据库仍未覆盖。
