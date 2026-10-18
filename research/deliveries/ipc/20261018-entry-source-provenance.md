# IPC 候选入口来源与 G 盘实测复核

日期：2026-10-18
工作线：work/ipc-20261017
代码基线：共同基线 6a41dc9b1aa030158e09be6241e2b14341f9256d，实现前 HEAD 1ff4cc09e415534959a1aaa5e20f3a8898601859

## 结论

G 盘 campaign-100-20261017 的原始 full-ab.json 中，IPC 共 47 条静态候选：ipc.auth.missing 18、ipc.relay.descriptor-boundary 18、ipc.capability.export 11；validated_vulnerability 为 0。它们不能表述为 47 个漏洞。

对 communication_netmanager_ext@8c35917b7e2f152813b13a20530a8452cf73d938 做候选文件范围的固定源码复跑后，11/11 条候选的 file/line/rule_id 与原报告一致；新报告进一步显示，11 条都由三个 test/.../fuzztest/..._fuzzer.cpp 入口产生，并逐条带有 entry_build_membership=unknown 义务。这些发现可能是 fuzz harness 的行为，也可能是 fuzz 对生产代码的调用链；仅凭路径不能判定误报，必须核对目标构建成员关系。新增输出让审阅者可以看到真正的入口来源，而无需从函数名猜测。

## 改动

- 每条 IPC 候选消息现在包括 entry-source=<入口定义文件>。
- 如果入口路径包含精确目录段 test/tests/unittest(s)/fuzz/fuzztest(s)/fuzzer(s)/mock(s)/rdbmock，保留候选并添加 entry_build_membership 未知义务。它只是路径提示，要求核实固定版本的产品构建目标；不自动删除结果、不认定误报，也不把路径当作产品安全边界。
- contest、mockery 等包含相似字符但不是完整目录段的路径不触发该标记。
- 检测器版本从 0.9.1 升至 0.9.2，解释模型从 oh-ipc-2026.10-v10 升至 oh-ipc-2026.10-v11；规则和候选判定逻辑没有改变。

## 固定源码复验

输入与输出：G 盘镜像组件 Git 对象、原 full-ab.json 指定 commit、报告里 11 条 IPC 候选涉及的 6 个文件；只读 Git 对象扫描，报告写到 /tmp/ohscanner-b-ipc-provenance-20261018/。

- 组件 commit/tree：8c35917b7e2f152813b13a20530a8452cf73d938 / e26372f6cd65be928b9c1cf4a96d3c7dd5ece804
- 原 campaign IPC 版本/候选：0.9.3 / 11
- 本次候选范围复跑版本/候选：0.9.2 / 11；定位集合精确匹配 11/11（file,line,rule_id）
- 三个入口定义均位于 test/.../fuzztest/..._fuzzer.cpp；11 条候选均有 entry_build_membership 未知义务。
- 本次仅纳入候选锚点涉及文件，不是整仓重跑；一个源文件为 partial，覆盖未知仍按义务保留。不能拿这个窄范围结果替代整仓验收，也不能据此报告 Precision/Recall。
- campaign 原报告 profile 是 light-ast，未锁定产品构建 manifest，未运行宏展开，也没有编译/运行时验证。静态候选仍是 candidate/unassessed。

其他仓库的候选文件范围复跑用于回归，不当作整组件差异：aafwk 16/19 个原位置可重现，缺少 3 条需要入口/dispatch 来源文件的原始窄范围；relational_store 0/1，其来源文件没有纳入候选锚点范围；graphic 9 条（原 8 条位置均保留，另多 1 条）。因此这些数字只能说明“只包含候选锚点文件会改变跨文件分析上下文”，不能当作检测器真实候选增减。其余四个小范围组件的锚点集合与原报告相同。

## 回归

- IPC 定向：70 项通过。
- 仓库全量：650 项运行、614 项通过、36 项跳过；首次全量复验有 1 项因 holdout 清单仍锁定 0.9.1 失败，清单版本绑定更新后最终全量复验通过。
- 新增语义测试覆盖：产品路径、测试/fuzz 路径、Windows 分隔符、相似但非独立路径段，以及 fixed 控制。路径提示不会改变 candidate finding 集合。

## 不作出的结论

本次没有确认或排除漏洞，没有提高可声称的召回率/精确率，没有注册 ArkTS/JS，也没有改公共平台协议、Catalog、A/B 其他分支或主线。路径分类不是 GN 构建图；下一项高价值工作是解析固定 commit 的 GN target 依赖，证明入口是否进入选定产品目标，再把“产品构建成员/测试 harness/未知”作为带来源的覆盖事实，而不是按目录名静默过滤。
