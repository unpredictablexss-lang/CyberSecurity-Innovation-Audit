# D线第9轮启动：D93/T92 UTF-8长度查询边界（2026-10-20）

D92/T91 已在远端负责人分支闭环，当前远端HEAD为`fc4cb8da2216002bf058aa1315c5328bebab9dc2`。基于其固定源码证据，D92新增八条来自 `CERT_PRIVATE_KEY="key"` property output source 的后续unknown路径。本轮从中挑选第890行：`napi_get_value_string_utf8(env,arg,nullptr,0,&length)`是长度查询；第915行才把UTF-8字节复制进实际缓冲区。

D93/T92已并行启动，研究该N-API调用的固定API身份、证书BUILD/include与API声明/实现之间是否有版本绑定，以及长度元数据后续是否流向可见sink。严格要求实际字节写入仍产候选，同名自定义body/callback、宏覆盖、未知wrapper、missing/partial声明不享受名称豁免。若证书构建无法绑定外部API实现，第890行保留unknown也是有效结论。

两条结构化提示词和当前任务状态见`D_LINE_PARALLEL_PLAN_20261020.md`与`D_LINE_TASK_TREE_20261020.json`。当前远端分支已包含截至D92/T91的全部整合；D93/T92结束后再固定验证并按既有远端交付方式推送新结果。
