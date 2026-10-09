# MethodCard：interface-permission-graph-v0

状态：本地研究原型，正式 Detector ID 尚未登记。主线 Detector v1 尚未编码，未使用不存在的接口。
研究家族：IPC caller / authorization obligation。初步分类可以研究 CWE-862/863，但真实样本尚未满足标注资格，当前原型不输出 CWE 定性。

## 改进假设与自研算法
基础文本匹配只回答“是否有检查 API”。本原型在给定有向图上，用 BFS 遍历 (node, grants) 状态；grant 键为 (subject, permission, resource)。
授权分支增加对应 grant，拒绝分支撤销对应 grant，identity_change 清空已有 grant；敏感操作节点要求对应 grant。遇到未满足的义务保留第一条见证路径。
相同状态去重，循环可终止；最大 500 节点、2000 边、1024 默认状态预算。超预算时整体 unknown，撤回不完整候选。
潜在状态组合呈指数增长，预算阻止无界分析。真实 CFG、多态、别名和调用者身份生命周期需后续扩展。

## 输入与事实要求
本轮输入仅为明确 synthetic=true 的人为图。每例绑定仓库、完整 commit、profile、相对路径。图 complete 和 parse complete 是自建标签，不是自动解析结果。
required facts 提案：入口 dispatch、函数/调用索引、调用者 token provenance、授权 API 语义、成功/失败边、权限对象与资源、异常/退出/宏覆盖状态。
没有这些事实则 blocked/unknown；未经过核心批准，不建立另一套公共 IR。

## 数据与许可
固定研究对象：openharmony/multimodalinput_input@2468d204d3f276c373841e057af35985296c8421。用于结构研究，未标注为真实漏洞正例。
真实修复对：none。公开 CVE：本次未关联。12 份本地文件（含 LICENSE）来源/哈希见 manifest，源码许可证头为 Apache-2.0；源码只保留在忽略目录，不打包转交。
7 个自建图为 design/regression split；无 independent holdout，不能报告检出率/Precision/Recall。fixture 用虚构 permission/resource，不伪装为真实 OpenHarmony API。
算法为独立实现，尚未完成 CodeQL/Joern/Clang 离线对照；不声称超过这些工具或学术首创。

## 已验证与未验证
33 项标准库单测验证授权键、路径和失败语义；源码核验验证 Git blob / SHA-256，与运行时权限语义无关。
Windows Python 3.10.11 实跑；WSL、主线回归和 CI 未验证。只有 7 个自建样例复放，不是真实组件扫描。
不能证明服务对任意应用可达、socket 获取等于越权、HAP/NATIVE/SHELL 策略不合理、检查 API支配所有实际执行路径、设备权限提升或可利用性。

## 下一轮
优先将真实入口和 guard 语义表交给负责人确认，再按冻结接口接入受限函数内/一跳源码事实。
选择独立的公开修复对与相似安全对照。建立基础模式 / 绑定身份对象 / 加拒绝边的消融，冻结算法后再评估 holdout；本轮没有伪造这些实验。


## 第二轮扩展：真实C++输入

新增cpp_permission.py受限AST结构分析，研究接口cpp-permission-model-v0仍不是公共Detector协议。输入绑定源码hash，真实入口和权限需求须显式审查，输出syntax。60项测试通过；6个自建C++样例及3个真实MMI函数复放，MMI全为unknown。依赖固定tree-sitter 0.25.2，保留0.26.0崩溃记录。详见cpp_source_handoff.md；前文33项是第一轮历史结果。


## 第三轮实测

新增自动IPC入口索引、源码权限helper链、受限宏展开和虚调用/回调候选目标。真实固定MMI产生33入口/23源码约束，全部仍partial。92项本地回归通过，无独立holdout，无漏洞确认。详见third_round_handoff.md；未将已有源码政策当独立完整安全需求。
