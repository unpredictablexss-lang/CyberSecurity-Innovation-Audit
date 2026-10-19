# D43：CM_LOG 格式语义与状态返回数据流复核

日期：2026-10-19。用途：基于 D41 的一个固定源码候选做检测器开发诊断；不是独立 holdout、漏洞确认或产品验证。

## 固定源码证据

来源为 openharmony/security_certificate_manager commit 5fcc0b6379567a70176307c281360be2ba281d6b。

- frameworks/cert_manager_standard/main/common/include/cm_log.h，blob 0b591ef6b531b49333e5a9f2e3bda48b60f05983：CM_LOG_I/W/E/D(...) 将参数传给 CmLog(level, __func__, __LINE__, __VA_ARGS__)，因此源格式位于参数 0。
- frameworks/cert_manager_standard/main/os_dependency/log/cm_log.c，blob 94e2e5ca9667944f861bd8fc1fcd31ced810ce01：先用 vsnprintf_s 生成缓冲区，再输出该缓冲区。I/W/E 使用 HiLog 的 %{public}s，D 使用 %{private}s。所以这组封装不能直接按普通 HiLog 的 %{private} 标注解释内部格式；遇到这种注解时检测器保留格式解析候选，不把它当作已证明安全或已证明泄漏。
- interfaces/kits/ani/cm_ani_common/utils/include/cm_ani_utils.h，blob 9577bad6f249e3f1ad751f06c9eda8fa3972c53e：AniUtils::GenerateCredentialObj 返回 int32_t，通过 ani_object &resultObjOut 写对象。调用的返回值是状态码，不应继承敏感对象的污点；输出对象的传递仍是待绑定的候选。
- 同一 builder 文件中 CMResultBuilder::credentialSetStringProperty 为 int32_t 方法。此调用者在同 owner 内以未限定方法名调用；本次检测器仅在同 owner 唯一匹配定义时扩展方法体。可见的 Object_SetPropertyByName_Ref/Int 仍保留为 unresolved escape 候选。

被扫描文件 interfaces/kits/ani/cm_ani_common/builder/src/cm_result_builder.cpp 的 blob 为 dab8f8d2358da084923e6ab786c9b373957bfe3c，SHA-256 为 81381d6a4978990b93f9219cbd1c9f2bf1d7a30743dd5420dd7b6ce03f042e98。

## 实现与验证

detector 从 0.17.0 升到 0.18.0，sink model 从 0.7.0 升到 0.8.0：

- 加入 CM_LOG 四个级别的格式位置和公开/私有输出语义；仅把普通 C 格式中实际绑定的操作数映射为污点。HiLog {public/private} 注解对 vsnprintf_s 阶段不作猜测，保持 candidate。
- 为 NAPI/ANI 对象属性设置等状态返回 API 记录返回值语义。实参仍在调用点形成 unresolved escape candidate；状态码不再被误当成秘密值传播到后续日志。
- 同一 owner 中唯一同名的未限定 C++ 方法调用可以展开方法体；多个可能定义、递归、超深调用和跨文件调用仍保持不确定。

新增 D2 语义测试覆盖公开 CM_LOG、私有级别、未支持的 privacy 标注、安全元数据字段、同名本地函数遮蔽、对象属性设置候选与状态码回流。命令：

~~~text
.venv-web/bin/python -m unittest tests.detectors.data.test_d2_semantics -v
~~~

扫描复现（仅从已有本地 Git 对象读取，不 fetch、不 checkout、不写源仓库）：

~~~text
.venv-web/bin/python research/data_sensitive/d43_cm_log_replay.py   --git-repo <已有的 security_certificate_manager 本地 Git 仓库>   --output research/data_sensitive/D43_CM_LOG_REPLAY.json
~~~

本次输出：D41 0.17.0 在该文件记录 14 条 unresolved-escape；D43 0.18.0 对同一 commit/blob 重放得到 10 条 unresolved-escape，文件 coverage 仍为 partial、DetectorRun 为 blocked。这个单文件开发诊断没有标签，不能称为 4 个误报已修复或精确率提升。结果在 [机器回放](D43_CM_LOG_REPLAY.json)。

## 结论边界和后续

所有剩余候选都指向 credential 对象创建/序列化边界。尚未核验对象内数据字段、ANI 调用实现、未授权接收主体、产品构建、可达性和 CIA 影响。状态仍是静态 candidate/unknown，validated_vulnerability=0；本轮没有动态 PoC，也没有产品修复效果验证。

D41 候选明细已用于开发诊断，不能继续作为这版 detector 的独立准确率 holdout。M2 仍未满足；需要在冻结 0.18.0 及 source/sink model hash 后，另选未用于调参的真实源码并由独立审查者标注。D43 不更改 D41 的冻结记录或历史输出。
