# D线第7轮：D91/T90 闭环与 D92/T91 启动（2026-10-20）

D91/T90 独立研究核实了固定 OpenHarmony N-API 声明 `napi_typeof(env, napi_value, napi_valuetype*)`、一般实现的类型枚举输出与 napi_status 返回，以及 `napi_get_value_string_utf8` 的写缓冲行为。证据来自本地固定的 arkui_napi、third_party_node 和 certificate framework Git objects；所需实现/声明有 partial parse 状态，certificate framework 的组件依赖可见但 manifest/GN 没有把 N-API实现版本绑定到 e270 目标构建。故不加全局白名单，也不减少原范围候选。

准确角色：第185行 `napi_typeof` 类型查询；第192行 `napi_get_value_string_utf8` 是 `nullptr`/零长度查询；第208行才把 UTF-8 字节写入缓冲区。三处都继续保留 unknown candidate。D91没有改扫描器src或版本，只增加具名可见元数据函数体正控制和同名材料输出反控制。D91自有6项、T90独立10项通过；负责人重跑D91/T90合并16项、完整data193项通过。

固定 fresh-src 回放：严格T85三文件两版均19 direct/19 Runner，诊断、调用事实与coverage一致；加入其他仓库声明/实现后单独组成的九文件集合两版均21 direct/19 Runner，声明/实现partial、无证书构建绑定。扩展范围从未冒充原产品构建或原三文件改进。T90独立报告给出源码身份、API角色摘录与混合collection证据。

下一项从既有真实 trace 中选出：`CERT_PRIVATE_KEY="key"` 在 `napi_cert_utils.cpp:298` 作为 `napi_get_named_property` 的property-name参数，却因当前规则只审过 `CERT_PASSWORD="password"` 而被启发式当材料源。D92/T91将只挑战这个精确schema-key绑定，确保输出实参及其后真正的private-key材料仍有候选。结构化提示词与权威状态见并行计划、任务树和持续目标文件。

本轮 D91/T90 证据/测试/报告已集成在owner本地分支；没有推送，也没有引入第二层模型。
