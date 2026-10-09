# cpp.lifetime independent holdout plan

> 当前状态：设计完成，holdout 尚未收集或执行。当前六个 lifetime fixtures 全部属于开发/契约 fixture，不能计入独立成绩。

## 1. 隔离单位

按 `root_cause_instance_id` 隔离，而不是按 warning 行。相同 CVE、backport、同补丁复制或同项目近重复文件必须进入同一 split，避免泄漏。

## 2. 分层要求

每个 split 至少保持：

- vulnerable：显式 unique_ptr owner + raw alias + reset 后 alias use，包括无条件、
  条件和非直行 rebinding 变体；
- fixed：改变 ownership/alias 语义后风险形状消失，包括无条件直行 rebinding；
- safe：相似 API/变量/锁但没有 stale alias use；
- partial parse：宏、模板、缺类型或不完整编译上下文；
- failed：解析器失败/超时/错误配置；
- sync variants：同一互斥锁、不同锁、无锁、锁作用域不覆盖 reset/use。

真实 OpenHarmony 样本必须绑定 repository、完整 commit、file blob SHA-256、profile/build scope 和 source artifact；合成 fixture 单独标记，不能混入公开历史 benchmark。

## 3. 推荐拆分

- development：本轮 synthetic fixtures，仅用于算法和回归测试；
- validation：另建不同变量命名、不同 owner 初始化、不同 lock 类型和 alias 重绑定位置；
- holdout：跨项目/跨组件，至少一个不同 smart-pointer wrapper 或 OpenHarmony idiom；在 detector 代码冻结前不查看结果；
- failure holdout：宏控制 reset、lambda capture、template alias、跨函数 owner move、析构回调。

## 4. 运行和报告要求

- 固定 detector commit、fixture manifest SHA、Python 版本和命令；
- 先记录 parse coverage，再解释 candidate；
- 报告原始 count、逐 fixture 解释、failed/unknown 占比和消融；
- 不计算 Precision/Recall，除非样本量、独立标签和覆盖分母满足 `vulnerability_corpus_bakeoff_protocol.md`；
- detector 输出 `candidate/unassessed`，benchmark 匹配由独立 evaluator 在绑定修复对后决定。

## 5. 当前禁止结论

本计划没有执行数据，因此不能写 holdout pass、泛化能力、误报率、漏报率或真实 OpenHarmony 检出能力。
