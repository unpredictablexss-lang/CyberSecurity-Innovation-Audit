# C3：类型来源与生成图实现

算法冻结提交：`4ea5f4020884aed5860a88d50f5a926610e7b98a`；基线：`33242fbd2b58e2f510fa74f1521e247fea08db27`。
Detector / model：`0.2.0`；模型 SHA-256：`1421ec97eb81e0f08910a83d7b72cfdd9d5bcd22aa752105739faf36341c72fe`。
规则仍为 `ark.runtime.typedarray-store-type-origin`。运行参数、源码身份和耗时见 `C3_RUN_MANIFEST.json`、`C3_SOURCE_EVIDENCE.json`；测试见 `C3_VALIDATION.json`。

## 深化现有 module

保留 `analyze_unit` interface。`OriginEvaluator` / `OriginState` module 在一个内部 seam 处理表达式求值、调用副作用、赋值和事实寿命；research 与 strict detector adapter 复用同一算法。改进 locality，使新增表达式位置不能绕开事实失效。没有增加公共 interface 或第二个扫描器。相同 interface 上的机制回归提供 leverage；删除这种集中处理会把失效规则重新分散到调用者。

对象身份、捕获 token 的来源、该 token 是否仍描述对象的当前类型是三个概念。不可变 GateRef token 的复制保留采样身份；重新采样产生新的身份。species 调用可能改变运行时状态，因此使旧类型事实失效，但不改写已捕获 token 的历史来源。不同来源只能形成有待证明实际类型差异的 candidate，不能直接证明数值类型不同或产品漏洞。

`equivalent` 绑定具体 token 与当前目标；`invalidated` 保存失效对象身份；`predicates` 随赋值/未知副作用清除。旧 token 的新副本不能被另一次新采样重新验证。比较两个陈旧 token 不能证明当前目标同型。未知调用在声明初值、赋值 RHS、条件、成员调用、嵌套表达式和 Sink 实参中都先处理；未核验引用传参还会遗忘实参的当前绑定。

按源码核验的 GateRef 按值传递只保证 C++ 绑定不被重绑，不保证运行时纯度。`FastGetPropertyByIndex`、`NewArray`、species 创建及 JS 调用仍会失效旧事实。只为已审查的精确 receiver、签名和构建假设保留有限只读/宿主配置摘要。`CallStubBuilder` 仅接受已审查的 1/8 实参形式；显式 callback 构造不因名称获准。摘要对应的 12 份源码在两提交中逐一核验，见来源 JSON；普通生产适配器不能据此宣称真实产品编译绑定已验证。

## 图及宿主 C++

`BRANCH/Bind/Jump/LoopBegin/LoopEnd` 按 Label 定义身份连接。终止块不因后续 Bind 自动恢复可达；缺失/重复/外部绑定保留 unknown。宿主无条件 return 停止后续图发射；带表达式的 return 和未建模的生成 Return/Throw 保持 unknown。迭代 SCC 识别循环，循环内创建身份及重复类型采样不被当作一般迭代敏感证明。

普通 C++ GateRef 重赋值与 DSL Variable 写入不同。生成控制开始后的普通宿主重绑保守阻塞该函数。递增/递减、嵌套赋值、可写指针/引用、未审查构造析构、new/delete 等经统一预检转 unknown；即使未知构造位于运行时 detached block，也不能把宿主副作用当作未执行。现阶段不实现完整 C++ 求值顺序或跨块 SSA/Phi。

按函数及状态去重；观察绑定实际限定符号、函数字节区间、路径和副作用点。预算中断丢弃当前未完成函数的观察，保留此前完整完成函数的有效局部证据；覆盖仍为 partial，状态仍为 limited/timed_out。不会把截断的函数候选集合伪装为完整。

## 修改范围与剩余义务

修改 C 私有 `analysis/model/type_origin/runtime_ir/syntax/detector` 和专项测试。公共 Runner/Catalog/contracts/API/DB/UI 未改，`required_facts=('ast',)` 不变。`syntax.py` 对 deleted/defaulted 无函数体成员不再假设存在 body，防止真实头文件调查崩溃。

模型使用 `assumed:NDEBUG=1;ENABLE_ASM_ASSERT=0;not_product_build_verified`。不同/未知配置拒绝分析。LoadHClass 等断言依赖尚未通过产品构建核验；宏、跨 TU 类型解析、完整路径可满足性和异常语义仍需证据。candidate / matched 都是有界模型观察；matched 不是整函数安全结论。
