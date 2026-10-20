# D 线接续切片：D87 / T86

本轮从 T85 的证书框架源码继续：固定全局常量 `CERT_PASSWORD="password"` 是 NAPI 属性键，不是属性值。D87为敏感流检测器增加窄范围参数角色绑定，T86独立反例测试并发现三类引用遮蔽误抑制。修订后负责人集成 HEAD 为 `2dd69e99e8038c905d1e81250207365aa911906f`，敏感检测器版本0.21.4。负责人分支仍为本地分支，未推送。

D87只在解析完整、同一命名空间、唯一显式可见的常量定义和精确已知NAPI属性名参数都被AST绑定时，排除属性键文本流。D87初版错误使用同名全局常量解释 `const std::string& CERT_PASSWORD` 参数、右值引用参数和局部引用别名，导致真实未知值候选丢失。T86向开发线给出最小反例；D87改为识别引用声明的被声明名称，并以独立测试复验。真实属性内容输出仍会建立材料流；未知helper、动态属性名、实际密码值和不完整解析保持候选。

T86对最终固定实现跑了13项独立测试和132项data测试，均通过。对照负责人0.21.3基线时，13项测试含6个失败子用例；修订后引用遮蔽的三个失败闭环。固定证书源码三文件、81,770字节的严格同范围复放保持21个候选，明细与覆盖不变；`cf_log.h` 仍partial，绑定逻辑因此保守不授予属性键排除。另一个仅两文件的诊断范围21→20只用于说明属性键绑定效果，不替代严格源范围，也不被报告为正式精度指标。

负责人在集成提交后重新验证：

- `python -m unittest discover -s tests/detectors/data -t . -q`：132项通过。
- `python -m unittest tests.detectors.test_known_disclosed_cves tests.detectors.test_known_case_corpus tests.detectors.test_d83_adversarial -q`：39项通过。
- `D87_verify.py --revision 23abc16652866edf06f6d86d8c11ec5deb5be784`：属性键正例1→0；未知wrapper、硬编码/动态材料、引用遮蔽和属性值保持1→1；严格实源Wi-Fi 3→3、证书21→21。
- `T86_verify_argument_roles.py --after-commit 23abc16652866edf06f6d86d8c11ec5deb5be784`：独立测试13项0失败；真实证书三文件21→21，候选与覆盖不变。

报告与逐案例角色证据见 [D87 handoff](D87_HANDOFF_20261020.md)、[T86 handoff](T86_HANDOFF_20261020.md)。结果仅限固定源码与静态候选，不证明组件完整覆盖、运行时影响或正式准确率；第二层模型未实现。

下一项从报告边界中选出：固定 `cf_log.h` 因分开条件编译的C++ `extern "C"` 链接括号被当前语法前端标为partial。D88/T87已启动，开发线只处理明确成对且可保持偏移的结构，测试线独立覆盖未配对/歧义控制并复跑原证书三文件范围。当前完整任务状态见 [任务树](D_LINE_TASK_TREE_20261020.json)。
