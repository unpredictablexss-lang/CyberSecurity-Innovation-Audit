# receiver_guard 别名与重绑定独立测试复核（2026-10-20）

## 范围与基线

本复核只分析与测试，不修改生产代码。测试工作树为 `codex/c-static-alias-test-20261020`，HEAD 为 `71950e65f46e204e6aec21210c8de73fa4f2a1a9`，已包含开发提交 `ae5792f84` 和 `71950e65`；因此此工作树不是两提交之前的 pre-fix 基线，不能把本次结果冒称为旧代码基线。

命令与结果：

- `python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v`：10 passed，1 skipped。历史回归因没有配置固定 Ark Git store 而跳过。
- `python -m unittest discover -s tests/detectors/ark_runtime -t . -p 'test_*.py' -q`：155 passed，3 skipped。三个历史用例均需固定本地 Git store。
- 临时内存 harness 调用 `analyze_receiver_guard(unit(wrap(body)))`，无临时文件或生产代码改动。

## Source-bound 场景矩阵

| 场景 | 实际输出 | 评估 |
|---|---|---|
| `alias = input`，通过 `LoadHClass(alias)` 并 guard，sink 使用 `input` | `unknown / receiver_type_guard_not_resolved` | 代码形态表达同一引用，但当前分析器只认直接同 binding。是精度/覆盖边界；未证明存在不安全访问。 |
| `alias = count`，通过 alias guard，sink 使用 `input` | `unknown / receiver_type_guard_not_resolved` | 不把异对象的 guard 传播给 input，保守且符合预期。 |
| guard input，sink 使用 count | `unknown / receiver_type_guard_not_resolved` | 不把 input 的 guard 传播给 count，保守且符合预期。 |
| guard input 前 `saved = input`；guard 成功后 `input = count; input = saved`；sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 静态赋值显示恢复为 guard 前捕获的同一 binding，但分析器不跟踪 alias provenance。候选不等于漏洞；这是降低误报密度的潜在精度改进。 |
| guard input 前 `saved = count`；guard 后 `input = count; input = saved`；sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 实际恢复到未 guard 的 count，candidate 是恰当保守结果。 |
| guard input 后把 token 变量重采样为 `GetObjectType(LoadHClass(count))`，sink input | `matched / receiver_type_guard_dominates_backing_buffer_read` | guard 已在重采样之前成功执行，token 后续赋值不撤销已发生的控制流事实；此判断 sound。 |
| guard input 后执行 `input = input`，sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 仅自赋值不改变引用，但通用 assignment 规则清除了 guard。属于保守精度边界，不是漏洞。 |
| guard input 后先 `input = count`，再 `input = ResolveReceiver(input)`，sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 最终来源无法证明回到被 guard 的引用，candidate 正确保留。 |

## 结论与反馈

本次没有发现会将异对象 guard 误用于 sink 的 soundness 缺陷。别名案例仍是 `unknown`，负例保持 `unknown`，guard 后 token 重采样维持 `matched`；这几个判断符合当前直接同 binding 的分析边界。

值得作为后续独立优化评估的两个低风险精度点是不可变 alias 的来源传播，以及 receiver 自赋值的 no-op 识别。`saved=input` 后经过另一对象再恢复 saved 的情形也可能有价值，但需要确保 alias 未被覆盖、逃逸或受到未知副作用影响。建议开发线只在能证明来源等价且保留异对象负例时实现；否则继续保留 `candidate`，不扩大语义范围。本报告没有把候选数、Precision/Recall 或产品影响外推为准确率结论。
