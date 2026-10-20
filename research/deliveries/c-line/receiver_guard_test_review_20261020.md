# Receiver guard 独立测试复核（2026-10-20）

## 范围与基线

- 测试工作树：`D:\openHarmonyScanner\worktrees\c-static-test-20261020`
- 分支/基线：`codex/c-static-test-20261020`，HEAD `d07dc397ca1ff3bddc0be52cfa98c6e4c783fd03`（`origin/codex/c-line-static-20261019`）
- 检查对象：`src/ohscanner/detectors/ark_runtime/receiver_guard.py` 中 `analyze_receiver_guard`
- 命令：`python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v`
- 结果：4 个普通测试通过；历史 Git 对照 1 项 skipped（未设置 `OHSCANNER_ARK_OFFICIAL_GIT`，项目约定不隐式 fetch）。总计 `OK (skipped=1)`。

以下用例在临时 Python harness 中调用现有 `tests.detectors.ark_runtime.support.unit/wrap` 和 `analyze_receiver_guard`，没有更改生产代码或测试文件。模板函数签名由 `wrap(body)` 生成，sink 均为 `GetViewedArrayBuffer(input)`。这些是合成组件用例，不代表某个上游版本已触发该问题。

## 反例与观察

### 1. 取反谓词，成功边仍被视为已保护（误报 matched）

复现 body：

```cpp
Label typed(GetEnvironment());
BRANCH(!IsTypedArray(input), &typed, slowPath);
Bind(&typed);
GateRef buffer = GetViewedArrayBuffer(input);
```

实际输出：`completed/complete`, observation=`matched: receiver_type_guard_dominates_backing_buffer_read`。

按 C++ 布尔语义，通往 `typed` 的边满足 `!IsTypedArray(input)`，并不能证明 input 是 TypedArray；该 sink 在真实控制流上可未通过目标类型 guard。相反布局 `BRANCH(!IsTypedArray(input), slowPath, &typed)` 实际输出 `candidate: backing_buffer_read_not_dominated_by_receiver_type_guard`。未取反控制 `BRANCH(IsTypedArray(input), &typed, slowPath)` 输出 `matched`；把 sink 放在其 false 边则输出 `candidate`。这确认成功边方向在普通条件下区分正确，取反时却没有被保守处理。

### 2. OR 复合谓词可绕过类型检查（误报 matched）

复现 body：

```cpp
Label typed(GetEnvironment());
BRANCH(IsTypedArray(input) || TaggedIsNotUndefined(input), &typed, slowPath);
Bind(&typed);
GateRef buffer = GetViewedArrayBuffer(input);
```

实际输出：`completed/complete`, observation=`matched`。在 OR 的第二项为真而 `IsTypedArray(input)` 为假时，true 边仍可达，因此这不是类型安全证明。建议对不能证明 true 边蕴含类型谓词的复合表达式返回 `unknown`，或在路径建模后给出 candidate。

对比：`!!IsTypedArray(input)` 是语义等价的双重否定，实际也输出 `matched`；这单独看是合理结果，不能作为误报证据。`IsTypedArray(input) && TaggedIsNotUndefined(input)` 输出 `matched`，其 true 边蕴含类型谓词，结果可由该谓词支撑。

### 3. 类型 token 被改写后仍沿用旧初始化来源（误报 matched）

复现 body：

```cpp
Label typed(GetEnvironment());
GateRef tag = GetObjectType(LoadHClass(input));
tag = GetObjectType(LoadHClass(count));
BRANCH(IsFastTypeArray(tag), &typed, slowPath);
Bind(&typed);
GateRef buffer = GetViewedArrayBuffer(input);
```

实际输出：`completed/complete`, observation=`matched`。分支处的 `tag` 来自 `count`，而静态 guard 解析仍找到 `tag` 的 `input` 初始化器并据此认定同接收者保护。控制条件并没有检查 input 的运行时类型。

### 4. 接收者参数被重绑定后仍沿用旧保护（误报 matched）

复现 body：

```cpp
Label typed(GetEnvironment());
GateRef tag = GetObjectType(LoadHClass(input));
BRANCH(IsFastTypeArray(tag), &typed, slowPath);
Bind(&typed);
input = count;
GateRef buffer = GetViewedArrayBuffer(input);
```

实际输出：`completed/complete`, observation=`matched`。分支保护的是赋值前的 input 对象；sink 使用的是赋值后的对象。结果提示规则按绑定身份匹配，却没有在该检查中体现中间赋值对对象来源的影响。

## 保守性控制

- 用 `count` 的 HClass 生成 tag，再保护 `input`：输出 `unknown: receiver_type_guard_not_resolved`，符合不同对象不互相保护的预期。
- 用 `GateRef alias = input` 从 alias 取 HClass，再保护 `input`：输出相同 `unknown`。这说明简单别名尚未证明同对象关系，当前是保守不匹配；此合成例没有产生误报。
- 同名变量遮蔽未发现可靠、可运行的复现；本轮不对遮蔽行为下结论。

## 结论

该基线测试覆盖了正向 guard、不同对象、命名变化和 guard 前 sink，但没有覆盖谓词取反、复合谓词或 guard 后重绑定。上述第 1–4 项都能稳定复现为 `matched`，应作为独立测试线反馈给开发线；这是规则行为层面的误分类证据，不足以推出真实 Ark Runtime 产品影响或漏洞。

## 开发修复提交复验（2026-10-20）

按开发线要求，在本测试工作树 cherry-pick 了相同源提交 `ae5792f84e6b641e8857d0d58fab508f3a306af4`（本地 cherry-pick commit `f9b49b9ea`），然后重新执行测试和同一组临时 harness 用例。

命令：`python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v`

结果：新增 negation/compound/direct-positive 回归后，8 个非历史测试通过；固定官方 Git store 未配置，历史对照 1 项仍 skipped。总计 `OK (skipped=1)`。

修复提交后的 harness 实际输出：

| 输入条件 | 输出 | 复核 |
|---|---|---|
| `!IsTypedArray(input)` true 边到 sink | `unknown: receiver_type_guard_not_resolved` | 原先误报 matched 已消除 |
| `!IsTypedArray(input)` false 边到 sink | `unknown: receiver_type_guard_not_resolved` | 保守 unknown |
| `IsTypedArray(input)` true 边到 sink | `matched` | 正向控制保留 |
| `IsTypedArray(input)` false 边到 sink | `candidate` | 反向控制保留 |
| `IsTypedArray(input) || other` | `unknown` | 原先误报 matched 已消除 |
| `IsTypedArray(input) && other` | `unknown` | 未证明复合条件，保守 unknown |
| `!!IsTypedArray(input)` | `unknown` | 双重否定未被识别，保守结果；属于能力限制，不是误报 |
| `input` 类型 token 被另一对象的类型写覆盖 | `matched` | 原反例仍在，旧初始化来源仍被接受 |
| guard 后 `input = count` 再读取 | `matched` | 原反例仍在，接收者重绑定仍被接受 |

因此该提交修复了直接谓词取反和 OR 复合导致的误报，并新增对应测试；但本次其余两个数据流反例仍可复现。它们不属于该提交覆盖范围，已作为独立测试发现保留，交开发线评估。以上仍是合成组件级行为观察，未证明上游实际调用点存在相同数据流。

## 第二轮修复提交复验（2026-10-20）

在同一测试工作树 cherry-pick 开发提交 `71950e65f46e204e6aec21210c8de73fa4f2a1a9`（本地 commit `3a0122e8a`），基于第一轮修复提交后复验。命令仍为 `python -m unittest tests.detectors.ark_runtime.test_receiver_guard -v`：10 个普通测试通过，历史对照 1 项 skipped（未提供固定官方 Git store），总计 `OK (skipped=1)`。

先前两个残余反例的复测结果：

- 类型 token 从 input 类型改写为 count 类型后再做 `IsFastTypeArray(tag)`：`unknown: receiver_type_guard_not_resolved`，不再误报 matched。
- 通过 guard 后执行 `input = count` 再读取：`candidate: backing_buffer_read_not_dominated_by_receiver_type_guard`，不再误报 matched。
- 未改写的 input 类型 token 正向 guard：仍为 `matched`。
- 已有新增回归 `test_reassigned_receiver_before_fresh_type_query_remains_supported` 通过，说明对接收者重新赋值后重新读取类型的路径仍受支持。

额外边界 harness（使用 `unit/wrap` 生成相同目标函数）观察：

| 场景 | 输出 | 说明 |
|---|---|---|
| guard 后 `input = count; input = saved;` 再读 | `candidate` | 采用“曾发生重绑定即失去保护”的保守策略；尽管恢复原变量值，该分析未恢复别名证明 |
| guard 后参数重绑定，谓词为直接 `IsTypedArray(input)` | `candidate` | 同样正确撤销旧保护 |
| token 改写成非类型 GateRef (`tag = count`) | `unknown` | 不把旧初始化器当作当前 token 值 |
| token 再次从同一 input 采样类型后用于 guard | `unknown` | 保守能力限制；此路径未被证明为安全或不安全 |

这次修复提交新增测试覆盖两处原误报，定向用例全部通过。报告仍仅说明合成组件行为；没有据此认定真实上游调用点或产品漏洞。当前测试工作树包含两个被复验的开发提交，以及本报告的独立提交；没有推送。
