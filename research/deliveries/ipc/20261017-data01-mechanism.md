# 交付项 5：DATA-01 为什么在真实代码上 0 候选（2026-10-17）

- **lane / branch / base**：`lanes.ipc` / `work/ipc-20261017` /
  `6a41dc9b1aa030158e09be6241e2b14341f9256d`
- **检测器（只读固定）**：`src/ohscanner/detectors/interface/`，`0.8.0` /
  `oh-ipc-2026.10-v6`，来源树
  `/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b` @
  `635b3e0449c552f0ccc25118850d245962845568`
- 相关：[交付项 3 实测](20261017-six-family-component-measurement.md)、
  [交付项 4 形状普查](20261017-shape-census-silent-rules.md)、
  [交付项 2 控制](20261017-six-family-depth-unit.md)
- **本交付同时修正交付项 4 的一行结论**，见 §4。

---

## 0. 一句话结论

DATA-01 在 1.53M 行上 0 候选，不是一个原因，是三个，且都不是"规则坏了"：

1. `position-underflow`：**形状确实存在**（`communication_ipc` 2 处），但两处都在
   `HitraceInvoker` 里，而调用它的是**另一个翻译单元**；解释器只沿入口根走、
   同文件内解析被调函数，跨 TU 的那一跳不走，于是这两处**从未被求值**。
   用"删掉守卫"的 A/B 实验证明**守卫不是原因**（§2.2），用 7 例探针定位**跨 TU 是原因**（§2.3）。
2. `copy-range`：665 次拷贝调用按"长度实参"分类后，**没有一次**的长度来自请求
   （规则的前置条件），所以静默是**正确的**（§3.1）。
3. 附带发现：规则给 `ReadRawData` / `ReadBuffer` 取的长度实参下标（2）**超过它们的实参个数**，
   这两类调用在本语料里**永远不可能触发**该规则（§3.2）。这不是本次 0 候选的原因
   （因为按真实下标也没有一次长度来自请求），但它是一条**潜伏的覆盖缺口**。

## 1. 两个问题

- 交付项 3 实测：18 个组件、100 条候选里 DATA-01 两条规则**都是 0**。
- 交付项 4 给了"形状 0 次 ⇒ 未被行使"的结论，其中 `position-underflow` 用的是正则代理
  `RewindRead\([^)]*-\)`。**这个代理是错的**（§4）。

于是本次换一种做法：先找形状**是否真的存在**，存在就逐处**读代码**，并设计
能区分"守卫"与"可达性"的实验。

## 2. `ipc.parcel.position-underflow`

### 2.1 形状确实存在，交付项 4 那一行是错的

`communication_ipc` @ `bbb92dbb2f52`，
`ipc/native/src/core/invoker/source/hitrace_invoker.cpp`：

```cpp
115 bool HitraceInvoker::TraceServerReceive(uint64_t handle, uint32_t code, MessageParcel &data, uint32_t &flags)
...
122     // padded size(4 bytes) of uint8_t
123     if (data.GetDataSize() < PADDED_SIZE_OF_PARCEL) {
124         ZLOGE(TRACE_LABEL, "The size of the data packet is less than 4");
125         return false;
126     }
127     data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL);
128     // the padded size of traceid
129     uint8_t idLen = data.ReadUint8();
130     if ((idLen >= sizeof(HiTraceIdStruct)) && (idLen <= (data.GetDataSize() - PADDED_SIZE_OF_PARCEL))) {
131         // padded size (4 bytes) of uint8_t
132         data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);
```

规则要的形状正是 `RewindRead(<parcel>.GetDataSize() - <expr>)`
（`analysis.py:1287` 把 `GetDataSize()` 标成 `parcel_size`，`:1428` 在 `left` 是
`parcel_size` 时产出带 `terms` 的减法值，`:1474` 的 `check_subtractions` 才是发射点，
而且它**只**从 `RewindRead` 的实参进入，`:1289`）。

两处**都有匹配的守卫**：

| 站点 | 守卫 | 判定 |
|---|---|---|
| `:127` | `:123` 的 `GetDataSize() < PADDED_SIZE_OF_PARCEL` 提前返回 → `size_lower` 里就有这对操作数 | 正确静默 |
| `:132` | `:130` 的 `idLen <= (GetDataSize() - PADDED_SIZE_OF_PARCEL)` → `upper` 里就有这对操作数 | 正确静默 |

**但"读代码觉得有守卫"不是证据**，所以做了下面两个实验。

### 2.2 实验一：把守卫删掉，规则**仍然**不响 ⇒ 守卫不是原因

在**语料之外的本地克隆**里，于 pinned commit 之上做一个只删这 5 行守卫的 scratch 提交，
同一个检测器、同一份 argv 跑两次：

| 运行 | commit | 候选 | 按规则 | `position-underflow` |
|---|---|---|---|---|
| A 原样 | `bbb92dbb2f52` | 12 | AUTH-01 10 / AUTH-02 2 | **0** |
| B 删守卫 | `7471b8420de5` | 12 | AUTH-01 10 / AUTH-02 2 | **0** |

记录在 `research/evidence/interface/ipc/hitrace_guard_pair_20261017/pair.json`
（含两次 `report_sha256`、被删代码块原文、argv）。

**结论：** 删掉守卫后候选一条没多，说明这两处**根本没有被求值**——
"守卫把它压成 0"与"它压根没被看"在报告上长得一样，这个实验把两者分开了。

### 2.3 实验二：7 例探针，定位到"跨翻译单元"

用同一批源码文本在内存里造单元组（不写仓库、不写语料），跑 base 与 complete-ast 两个检测器
（两者结果一致）：

| 例 | 形状位置 | 结果 |
|---|---|---|
| `entry_unguarded` | 入口内，无守卫 | **命中 1** |
| `entry_guarded` | 入口内，有守卫 | 0 |
| `helper_called_from_entry` | **同文件**的 helper，入口按名调用 | **命中 1** |
| `helper_same_file_qualified` | 同文件，`Stub::DoRewind(data)` 限定调用 | **命中 1** |
| `helper_cross_file` | helper 在**另一个文件**，入口跨 TU 调用 | **0** |
| `real_body_in_entry_unguarded` | 上游那两条语句**原文**放进入口，无守卫 | **命中 1** |
| `real_body_in_entry_guarded` | 同上，带守卫 | 0 |
| `REAL_hitrace_pair_only` | 真实两文件（`.cpp` + `.h`）原样 | **0**（`.cpp` 为 `partial`） |

（`REAL` 两例另附 `common_types.h` 也仍是 0。）

`analysis.py:1670` 的 `run()` 只从 `_entry_roots()` 开始走；被调函数由
`resolve()`（`:633`）解析，而它带条件 `f.file == fn.file`——**同文件**。
跨文件的唯一通道是 `delegated()` 的那一种单例形态（`:643`），
`HitraceInvoker` 不属于那一种。

真实调用点：

```text
ipc/native/src/core/invoker/source/binder_invoker.cpp:1008   HitraceInvoker::TraceServerReceive(...)
ipc/native/src/core/dbinder/include/dbinder_base_invoker_process.h:129  HitraceInvoker::TraceServerReceive(...)
```

两处都在**别的文件**里 → 这一跳不走 → `hitrace_invoker.cpp` 的函数虽然被登记
（`Interpreter.functions` 里有它，见 `/home/audit/wtmp/registered_functions.py` 的输出），
**永远不作为根被走过**。

**所以 `position-underflow` 的静默是覆盖层面的**：规则能被行使（7 例里 4 例命中），
本语料里的形状落在一次**跨 TU 跳转**之后。这与 `caller-class` 的 IDL 缺口是**同类**问题
（可达它的那条边不在建模里），不是"规则未行使"。

### 2.4 这一节不支持什么

- **不支持**"这两处是漏洞"。它们有匹配守卫；`RecoveryDataAndFlag`（`:103`）里
  `SetDataSize(...)` 的那次算术更不是本规则的形状（规则只从 `RewindRead` 进入）。
- **不支持**"把跨 TU 解析补上就会有候选"。补上之后这两处仍会被守卫压成 0；
  真正改变的是"**别处**跨 TU 的站点有没有被漏掉"这一类召回问题，本次**未测**。
- 探针用的是**我在内存里拼的文本**，不是语料里的完整 TU；它证明的是"同文件走、跨文件不走"
  这一条机制，不是"真实组件里所有跨 TU 站点都漏"。

## 3. `ipc.parcel.copy-range`

### 3.1 665 次拷贝调用，按"长度实参"分类

规则只在**长度来自请求**时才有前提（`analysis.py:1062`：`args[index].kind == "request"`）。
把 665 次按实参分类（脚本 `research/deliveries/ipc/copy_range_arg_classes.py`，
括号配平扫描，不是正则猜）：

| 长度实参 | 次数 |
|---|---|
| 标识符（局部变量/字段） | 273 |
| 调用或表达式 | 170 |
| 实参个数不足（规则的下标取不到） | 100 |
| `sizeof` | 61 |
| 其它表达式 | 60 |
| 空 | 1 |

对 273 个标识符长度，在**同文件内**回溯它是否由 `Read*()` 赋值：**0 个**。

也就是说，**没有一次拷贝的长度来自 parcel**。再加上
"拷贝实参里出现 `Read*()`"这一形态在 10,413 个已扫描文件里也是 **0 次**
（交付项 4 §2 修正后口径），`copy-range` 的静默是**正确静默**：
它要的形态在本语料里不存在，不是规则看漏了。这与交付项 4 写的
"665 次待逐条核"相比是把这一条**结清**了：逐条核的结果是**没有一条符合前置条件**。

### 3.2 附带发现：两个具名调用的长度实参下标是够不到的

`copy_calls` 里 `ReadRawData` / `ReadBuffer` 走的是 `index = 2`（非 `_s` 分支）。
本语料里：

| 调用 | 实参个数分布 | 规则的 index=2 能否取到 |
|---|---|---|
| `ReadRawData` | 1 个 71 次、2 个 7 次 | **78/78 取不到** |
| `ReadBuffer` | 1 个 11 次、2 个 11 次、3 个 2 次 | 22/24 取不到，2 次取到（第三个实参，分类为"调用或表达式"） |

而它们的**长度其实是第 0 个实参**（`ReadRawData(size_t size)`、
`ReadBuffer(uint32_t length)`）。所以只要 call 名在这张表里，规则就基本不会看它。
本次对 78+22 次的第 0 个实参也做了同样的回溯：**0 次**来自 `Read*()`，
因此这是**潜伏缺口**，不是本次 0 候选的成因。

**这属于规则定义的改动**（改 `copy_calls` 的取值方式或每个名字的实参下标位置），
落在 `analysis.py` —— 并发 import 正在写的文件，本线**未动**。建议由集成人裁决：
要么按名字给下标，要么把这两个名字从 `copy_calls` 移出（它们不是"拷贝进目标缓冲"的形态）。

## 4. 修正：交付项 4 的 `position-underflow` 那一行

交付项 4 §2 的表里写"`RewindRead(<含减号>)` 出现 0 次 ⇒ 未被行使"。**该结论作废**，
原因是普查脚本自己的正则：

```text
旧：r"\bRewindRead\s*\([^)]*-[^)]*\)"      # [^)]* 跨不过 data.GetDataSize() 的 ')'
新：r"\bRewindRead\s*\([^;]{0,300}-"        # 扫描到语句结束，多算，命中逐条读
```

用修正后的口径在**同一批 10,413 个已扫描文件**上重算：

| 形状 | 旧口径 | 新口径 | 站点 |
|---|---|---|---|
| `RewindRead(` | 19 | 19（不变） | comm_ipc 18 / imf 1 |
| `RewindRead(<实参里含减号>)` | **0（错）** | **2** | `hitrace_invoker.cpp:127`、`:132` |
| `拷贝调用实参里含 Read*()` | — | **0** | — |

同一脚本新增 `--detail` 参数，会把命中逐条列成 `组件 相对路径:行号`，
所以修正后的数字可复核。**其余各行（`caller-class` 70、`copy_calls` 665、
`owner_calls` 2、`identity-domain` 0）不受影响**：它们的正则没有嵌套括号这道坎，
其中 `identity-domain` 的两条在 18 个组件里确实都是 0。

顺带记一笔：**上一版把"未被行使"当成四条规则的共同解释**，正确的分法是
`position-underflow` 属于**覆盖**（形状在、不可达），
`identity-domain` 才是**未被行使**（形状 0 次）。

## 5. 这些数字不说明什么

- 100 条候选仍全部是 `candidate`；本交付**没有产生任何新候选**，也没有改检测器一行。
- `copy-range` 的结论建立在**文本回溯**上：长度若经容器、结构体或函数传递，
  这个方法看不见。273 个标识符里有相当一部分属于这种情况，因此"0 次来自请求"
  是**本次方法的结论**，不是"世界上没有这种代码"的结论。
- `position-underflow` 两处站点是**真实上游代码**，本案只把它当**形状样本**用，
  没有把它提交到仓库（切片也不入库），也没有声称它是漏洞。
- 未做：跨 TU 一跳的召回测量；`ReadRawData`/`ReadBuffer` 下标修正后的重跑。

## 6. 复现

```console
# 2.2 的 A/B（本地隔离克隆，不碰语料）
$ bash /home/audit/wtmp/hitrace_guard_pair.sh

# 2.3 的 7 例探针（内存构造单元组，只读）
$ cd /home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b
$ .venv/bin/python -I /home/audit/wtmp/where_is_data01.py

# §3 的实参分类（从仓库根运行）
$ .venv-web/bin/python research/deliveries/ipc/copy_range_arg_classes.py \
    --audit-root <每组件 report.json 的目录> \
    --corpus-root <corpus root> [--corpus-root <corpus root>]

# §4 的修正普查（逐条列出命中站点）
$ .venv-web/bin/python research/deliveries/ipc/silent_rule_shape_census.py \
    --audit-root <同上> --corpus-root <同上> --detail position-underflow
```

前两条脚本在 `/home/audit/wtmp`（不入 Git，与交付项 3 的 `run_ipc_audit.py`
同一处理方式）；后两条在本线允许面内，随提交入库。
