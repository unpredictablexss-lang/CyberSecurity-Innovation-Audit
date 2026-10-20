# receiver_guard alias identity 提交独立复验（2026-10-20）

## 被测提交与运行基线

- 开发线原始提交：`2d79560cad45db75bb1b0c6d0677200294e17d10`（`feat: preserve receiver guard across proven aliases`）。
- 复验工作树：`codex/c-static-alias-test-20261020`；已从该提交 cherry-pick 到本分支，复验 HEAD 为 `cd52fc1899112ed23b82bfe168f2056a58715b95`。该 cherry-pick SHA 不同，但 tree 内容来自上述原始提交，且测试工作树此前仅有已提交复核文档。
- `python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v`：16 passed，1 skipped（17 tests total）。
- `python -m unittest discover -s tests/detectors/ark_runtime -t . -p 'test_*.py' -q`：158 passed，3 skipped（161 tests total）。
- 三个 skip 是需要预置固定本地 Ark Runtime Git store 的历史对照，不进行隐式拉取。
- 扩展场景用临时内存 harness 构造 `unit(wrap(body))`，调用 `analyze_receiver_guard`；没有改生产代码或添加测试代码。

## 扩展 source-bound 场景

| 场景 | 实际输出 | 复验判断 |
|---|---|---|
| `alias = input`，从 alias 获取 HClass、guard alias，sink input | `matched / receiver_type_guard_dominates_backing_buffer_read` | 同一 GateRef 值拷贝来源被保留，符合预期。 |
| guard input，之后 `alias = input`，sink alias | `matched / receiver_type_guard_dominates_backing_buffer_read` | guard identity 可传给 sink alias，符合预期。 |
| `alias = count`，guard alias，sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 没把 count 的 guard 误传给 input；candidate 表示未受 guard 支配，不等于漏洞结论。 |
| guard input，sink count | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 反向异对象负例仍未匹配。 |
| guard input 前 `saved = input`；guard 后 `input = count; input = saved`；sink input | `matched / receiver_type_guard_dominates_backing_buffer_read` | 稳定 alias 恢复到被 guard identity 后保留证明。 |
| guard input 前 `saved = count`；guard 后 `input = count; input = saved`；sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 恢复到未 guard 的对象，负例符合预期。 |
| guard input 后把 token 重新采样为 `GetObjectType(LoadHClass(count))`，sink input | `matched / receiver_type_guard_dominates_backing_buffer_read` | 之前成功的 guard 控制流事实不受后续 token 赋值撤销。 |
| guard input 后 `input = input`，sink input | `matched / receiver_type_guard_dominates_backing_buffer_read` | 同一 binding 自赋值保留 identity。 |
| guard input 后 `input = ResolveReceiver(input)`，sink input | `unknown / receiver_guard_path_unresolved`，file outcome `partial` | opaque 结果来源无法证明，未擅自继承 guard。 |
| `alias = input ? count : input`，guard alias，sink input | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | 条件 alias 来源不唯一，未证明 input 被 guard。 |
| `GateRef &saved = input`，guard input 后通过引用写 `saved = count`，sink input | `unknown / receiver_guard_path_unresolved`，file outcome `partial` | 可写引用具有别名副作用，保持未知。 |
| guard input 前 `saved = input`，随后重绑定 `saved = count`，sink saved | `candidate / backing_buffer_read_not_dominated_by_receiver_type_guard` | alias 被改写后不再继承旧证明。 |

仓库新增的单元回归也分别覆盖 alias 正例、稳定 alias 恢复、异对象重绑定、条件 receiver 重绑定和 reference-alias 写入，均在上述 17 个 receiver_guard 测试中通过。

## 结论与限制

在该精确开发提交的 tree 上，提交目标 alias 传播路径通过独立复验。测试未复现同源 alias 误用为异对象的问题；跨对象使用仍给出 candidate，复杂/可写/opaque 来源保留 unknown。没有把 candidate 当作已确认漏洞，也没有从合成矩阵推导准确率或产品影响。

历史源代码对照未运行，因为本机未提供其固定 Git store；因此本报告验证的是 detector 与合成 source-bound 场景及当前 Ark Runtime 单测，不替代官方历史仓库重放，也不作产品级结论。
