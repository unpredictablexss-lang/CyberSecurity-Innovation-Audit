# D线第8轮：D92/T91 固定源码角色修复（2026-10-20）

D92/T91 已完成。固定 certificate framework commit `e270363a042bf8f0126881c76d1341ad457cc187` 中，`CERT_PRIVATE_KEY="key"` 在 `napi_cert_utils.cpp:298` 被传给 `napi_get_named_property` 的0基 arg2。之前代码只识别 `CERT_PASSWORD="password"`，把 `CERT_PRIVATE_KEY.c_str()` 当成疑似敏感来源。D92只加入精确的符号/字面值对，不把其他const string或任意literal当安全key；`napi_has_named_property`只产生状态/存在性，不造敏感材料。

同一 get 调用的 arg3 才是 property value 输出。旧分析因中性变量名 `data` 没有建立该来源；D92为取值加入 private-key-property output source，保留未解析目的地义务和后续消费者候选。因此固定三文件 direct/Runner 均从19增到26：只移除 line298 schema-key输入候选，新增8条源自该输出的下游 unresolved候选（261、268、304、316、839、883、890、915）。其余18条共同legacy诊断ID/message/direct evidence相同，原始638个调用位置、三文件原始bytes/hash及3文件partial coverage保持不变。新候选表示可追踪到真实property输出的分析路径，不是八个已确认漏洞或准确率提升主张。

开发8项、T91独立12项（基线8个direct/Runner子例失败，修订版全通过）、负责人完整data213项和兼容61项通过。开发与独立fresh-source replayer都确认direct和Runner 19→26，常量/输出/has/get/真实字节getter、shadow、变值、宏、wrapper及partial控制边界吻合。完整输出和逐案身份记录在D92_VALIDATION与T91_FIXED_PRIVATE_KEY_REPLAY中；stable/occurrence身份仍有unknown边界。

本轮实现提交 `0420a3905b1558e1d1251ac11e5e2034e6c3e45d`，独立测试 `55df3dbaf821a38813d1e40c6efcfd262655e395`，报告/重放证据及负责人任务更新已集成。本地owner分支尚未推送；按用户本轮指令，待最终检查后推送该分支。
