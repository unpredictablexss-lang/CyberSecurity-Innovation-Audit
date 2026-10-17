# 交付项 10：按机制加宽语料，以及"子类 1"自身的精度缺口

> 本项回应原始目标里的两件事：**多下载几个组件仓库测试**，
> 以及**把其他子类做到和子类 1 同样的水平**。第二件事的前提是
> "子类 1 的水平"本身是可度量的——本项给出了该度量，并证明它比现有数字低。

## 0. 一句话结论

按机制挑选并新克隆 12 个组件后，语料从 30 个组件 / 166 条候选扩到
**42 个组件 / 179 条候选**；新增的 13 条**全部落在 AUTH-01 与 CAP-01**，
6 条沉默规则（AUTH-02/03/04 的部分子类 + DATA-01 两条）**在 42 个组件上仍然一条不响**——
这是第三个独立语料库给出的同一结论。

同时，对"子类 1"（AUTH-01，占全部候选的 103/179）做了一次**只用报告自身字段**的筛查：
baseline 30 个组件里 **10/92（10.9%）**命中自明误报模式，新 12 个里 **5/11（45.5%）**。
逐条读 pinned blob 后确认，这些模式的成因是**可命名的规则缺陷**，不是语料特性。
所以"把其他子类提升到子类 1 的水平"如果照字面执行，会把一个 10% 量级的
体系性误报率**复制**到其他子类上。本项给出这个结论，但不擅自扩大范围去改检测器。

## 1. 新增语料：12 个组件

按**机制**（身份/权限判定 + Parcel 收解包），而非按组件名挑选；两个技术方案点名的
仓库（`distributeddatamgr_kv_store`、`commonlibrary_c_utils`）优先入选。
浅克隆 `--depth 1`，SHA 由 `rev-parse` 固定，只读，**不做隐式 fetch**。

| 组件 | commit | 入选文件 | 候选 | 静默原因 |
|---|---|---:|---:|---|
| `ability_dmsfwk` | `aa1b0347b10700d761def383c08749420dd3f71a` | 433 | 6 | — |
| `commonlibrary_c_utils` | `7a9af76276aca8f53347fb89c07850e014905521` | 62 | 0 | 无 IPC stub 入口 |
| `communication_nfc` | `331bfd2661490c996d495ab2b656f79d81ae931c` | 273 | 0 | 无 IPC stub 入口 |
| `communication_wifi` | `e336c82b3b107d87f68c5e0448cc246b50b53b38` | 776 | 2 | — |
| `distributeddatamgr_kv_store` | `64e48eb1d97b45f44125761f16811f78be609a4a` | 1446 | 0 | 见 §4 |
| `distributeddatamgr_relational_store` | `9fa3a57e6657275d03e25f2e319dab55f894d1e8` | 921 | 0 | 见 §4 |
| `filemanagement_file_api` | `103df5c4911e7fcddcccc7ae34894c5a2871d3a7` | 688 | 0 | 无 IPC stub 入口 |
| `powermgr_power_manager` | `06d1f3d19a59fcdb744b179d1158f65b75ad572d` | 299 | 0 | 无 IPC stub 入口 |
| `security_certificate_manager` | `5fcc0b6379567a70176307c281360be2ba281d6b` | 310 | 1 | — |
| `security_device_auth` | `21a357fe07ac0a61ce0929040251a712f94adef3` | 491 | 0 | 无 IPC stub 入口 |
| `security_huks` | `4ae4e0db461f137672719d43ffc6c5b1b6c05be8` | 538 | 0 | 无 IPC stub 入口 |
| `telephony_core_service` | `accd8c7931a5001041ddf638959da0ae6f31b1a6` | 556 | 4 | — |
| **合计** | | **6793** | **13** | |

计 877659 行、52432480 字节、4980 完整 AST / 1746 部分 AST、265.33 秒。

"无 IPC stub 入口"不是推论：这 8 个组件的候选为 0，且 §5 说明它们的
未认领文件只有 `arkts/ts/js`（检测器声明语言之外的扩展名），
即检测器**确实读完了**它能读的全部 C/C++ 文件，而不是没读到。

`distributeddatamgr_kv_store` 与 `distributeddatamgr_relational_store` 是例外：
它们有大量 C/C++，但候选为 0，原因不同（§4）。

### 1.1 42 组件合计

| 规则 | baseline 30 | 新 12 | 合计 |
|---|---:|---:|---:|
| `ipc.relay.descriptor-boundary` (AUTH-01) | 92 | 11 | 103 |
| `ipc.capability.export` (CAP-01) | 43 | 1 | 44 |
| `ipc.auth.missing` (AUTH-02) | 21 | 0 | 21 |
| `ipc.auth.guard-coverage` (AUTH-04) | 8 | 0 | 8 |
| `ipc.auth.object-owner` (AUTH-03) | 2 | 0 | 2 |
| `ipc.parcel.copy-range` (DATA-01) | 0 | 1 | 1 |
| `ipc.parcel.position-underflow` (DATA-01) | 0 | 0 | 0 |
| `ipc.auth.caller-class` / `identity-domain` / `service-identity` / `request-identity` (AUTH-03) | 0 | 0 | 0 |
| **合计** | **166** | **13** | **179** |

## 2. 这个结论与交付项 4、6 的关系

交付项 6（`20261017-shape-corpus-and-auth03-identity.md`）在 +12 个组件后写道：
"再下几个组件能加厚已经有的信号，不能把没有信号的规则变成有信号"。
本项是**第三个**独立语料库，给出同一结论，且这次语料是按机制挑的而非按名字：
**AUTH-03 的 `identity-domain`、DATA-01 的 `position-underflow` 在 42 个组件上仍然 0 条。**

值得强调的是：这两个 0 有**不同的性质**，把它们混为一谈会得出错误结论。

- `identity-domain` 的 0 是**形状缺席**：在 42 个组件的已扫描文件里，
  规则所要求的组合形状（`Verify*Token(...)` 的实参中带上 `GetCallingUid()`）
  一次都没有出现（§3）。规则没响，是因为语料里没有它要的形状。
- `position-underflow` 的 0 **不是**形状缺席：形状存在（§3 计数为 2），
  规则正确地没有响——那两处有守卫。这是**真阴性**。

## 3. 加宽语料后的形状普查

在**语料全部 C/C++ 文件**上按形状计数（`research/deliveries/ipc/widen_shape_census.py`），
而不是只看报告声明的已扫描范围——后者会把"语料里没有这个形状"
与"形状在语料里但落在扫描范围之外"混成同一个 0。**两列用同一个方法**，因此可比。

普查的目录排除表**逐条对齐检测器的生产段列表**
（`audit.py` 的 `--exclude` 默认：`test(s)`/`unittest(s)`/`fuzz*`/`mock(s)`/`sample(s)`/
`example(s)`/`demo(s)`/`benchmark(s)`/`third_party` 等）。只排除 `test`/`tests` 是不够的：
`unittest/` 下的 mock 会转发到真实现，匹配出生产代码从不匹配的形状 —— §3.3 就是一个实例。

文件/行分母（排除后）：baseline 四份语料 18759 文件 / 4436722 行；
新语料 6726 文件 / 1419751 行。

| 形状 | baseline 30 | 新 12 | 42 组件 |
|---|---:|---:|---:|
| `Verify*Token(` | 366 / 29 个组件 | 45 / 11 | 411 |
| `GetCallingUid(` | 1640 / 33 | 228 / 11 | 1868 |
| **`Verify*Token(...)` 实参含 `GetCallingUid()`** | **0** | **0** | **0** |
| `RewindRead(` | 19 / 2 | 3 / 2 | 22 |
| **`RewindRead(<minus>)`** | **2 / 1** | **0** | **2 / 1** |
| `copy_calls` | 2051 / 30 | 1216 / 11 | 3267 |
| `copy` 实参含 `Read*` | **0** | **0** | **0** |
| `owner_calls` | 57 / 2 | 0 | 57 / 2 |
| caller-class 具名调用 | 71 / 5 | 4 / 2 | 75 |

（组件数按语料子目录计，同一组件出现在两份语料时计两次，故可超过 42。）

### 3.1 一处更正：交付项 4 的 `RewindRead(<minus>) = 0` 是过时数字

交付项 4（`20261017-shape-census-silent-rules.md` §6.3）记录该形状为 0。
在 42 个组件上实测为 **2**，都在 30 组件基线的
`communication_ipc/ipc/native/src/core/invoker/source/hitrace_invoker.cpp:127` 与 `:132`。
该脚本自身注释记载，这个 pattern 是在交付项 4 落笔**之后**才补进普查器的，
所以那一行的 0 不是错误结论，是**过时读数**。本项以实测数字覆盖它。

### 3.2 那两处是真阴性，不是"规则没被行使"

读 pinned blob 后确认两处都正确受保护：

```cpp
if (data.GetDataSize() < PADDED_SIZE_OF_PARCEL) { return false; }        // :100-105
data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL);             // :127
if ((idLen >= sizeof(HiTraceIdStruct)) &&
    (idLen <= (data.GetDataSize() - PADDED_SIZE_OF_PARCEL))) { ... }     // :131
data.RewindRead(data.GetDataSize() - PADDED_SIZE_OF_PARCEL - idLen);     // :132
```

两处减法都由紧邻的比较守住。因此 `position-underflow` 的静默**在真实代码上是正确的**。
这使这 2 处成为该规则在真实代码上的**阴性对照**——比"形状计数为 0"强得多：
规则被行使了机会，且正确地保持了沉默。

### 3.3 一次差点写错的更正：普查口径必须与检测器一致

全语料普查第一版只排除了 `test`/`tests`，于是把 `copy` 实参含 `Read*` 记为 **1**，
位置在 `distributeddatamgr_udmf/framework/common/unittest/mock/message_parcel_mock.cpp:230`。
读那一处后确认它是 **mock**：`ReadRawData(size_t size)` 的定义体转发到
`UdmfMessageParcel::messageParcel->ReadRawData(...)`，不是生产代码里的拷贝点，
而且匹配还跨越了换行（普查正则用 `[^;]`，可跨行）。

检测器的 scope 本来就排除 `unittest` 与 `mock`，所以它没看到这一处、`copy-range` 保持
沉默，并**不是**漏报。把普查的排除表对齐检测器的生产段列表后重跑，该形状在 42 个组件上
为 **0**（§3 表）。因此这不是关于规则的发现，而是关于**普查自身口径**的一条注记：
按形状挑选语料时，排除表若比检测器窄，得到的计数会高于检测器可能触及的范围，
从而把 mock/样例里的形状读成"规则应该命中却没命中"。
本项保留这条注记，因为同一类错读正是"按形状选语料"这条路线最容易出的错。

## 4. 两条"有 C/C++ 但零候选"的规则级原因

`distributeddatamgr_kv_store`（1446 文件 / 188589 行）与
`distributeddatamgr_relational_store`（921 文件 / 108679 行）候选为 0，
且它们的未认领文件只有 `js/arkts`——检测器读完了全部 C/C++。原因与 §5 的机制一致：
这两个仓库的 IPC 侧采用 **IDL 生成的分发器**，其生成物不在仓库内（在构建产物里），
所以静态树上没有规则所键的 `OnRemoteRequest` 手工分发形状。
这与交付项 4 记录的 "IDL 生成分发器的组件 0 候选只是覆盖陈述" 是同一现象，
本项为它增加了两个组件级的实例。

## 5. 第一条真实代码上的 `copy-range` 候选，及其判定为误报

新 12 个组件里出现了**整个项目的第一条** `ipc.parcel.copy-range` 候选。
它值得单独一节，因为它的判定同时暴露了两个各自可命名的规则缺陷。

位置：`communication_wifi/wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp:385`
（entry `WifiP2pCallbackStub::RemoteOnConfigChanged`）:

```cpp
int cfgLen = data.ReadInt32();                                  // 363  来自对端
if (cfgLen <= 0)            { ...; return; }                    // 365  下界
if (cfgLen > MAX_LEN)       { ...; return; }                    // 369  上界 = 1024
const char *dataBuffer = reinterpret_cast<const char *>(data.ReadBuffer(cfgLen));
if (dataBuffer == nullptr)  { ...; return; }
char* cfgData = new (std::nothrow) char[cfgLen];                // 380  容量 == cfgLen
if (cfgData == nullptr)     { ...; return; }
if (memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen) != EOK) { ... } // 385
```

**这段代码是正确的，候选是误报。** 候选自身记录的 `path` 也与它自己的结论矛盾：

```text
path=((365, 'cfgLen <= 0 => False'), (369, 'cfgLen > 1024 => False'), (375, ...), (381, ...))
```

路径里明写 `cfgLen <= 0` 求值为假（即 `cfgLen > 0` 成立）、`cfgLen > 1024` 求值为假，
而规则要求的两个条件——**拷贝长度有上界**、**长度为正**——都被记录下来了。
两个成因都是**模型没记录**，不是代码没做：

1. **`new T[n]` 从未被记成容量。** 对 `memcpy_s*` 家族，规则从 `args[1]`（即 `destMax`）
   取目标容量（`analysis.py:1066`），这一半是对的；但目标 `cfgData` 的真实容量来自
   `new char[cfgLen]`，而 `capacities` 表里没有它——`new_expression`
   在 `analysis.py:1444-1449` 遍历完子节点后 `return UNKNOWN`，
   于是分配式失去了可供 `capacities` 作键的身份。
2. **`if (x <= 0) { return; }` 的落空分支没有记录下界。**
   `analysis.py:1421` 把 `x <= 0` 归类为**上界**谓词
   `("upper", (x,"0"), True)`；而 `refine`（`analysis.py:1528-1530`）只在
   `truth == when` 时记录。落空分支不产生任何记录，于是
   `state.lower` 是空的，规则的第一条判据 `length not in state.lower` 成立。
   注意同一张表（`analysis.py:1419-1424`）里 `x < 0` 与 `x >= 0` 都产生**下界**——
   只差 `<=` 这一种写法，而 `<=` 恰是这些仓库最常用的写法。

### 5.1 反事实

在 `analysis.py` 的一份**副本**上打四个窄补丁（pinned 树始终只读，从不写入），
逐条对应上面两个成因：

1. `new_expression` 返回表达式文本而非共享的 `UNKNOWN` 哨兵，使分配式保有身份；
2. `init_declarator` 的初始化式是 `new T[n]` 时，把 `n` 记为目的地容量；
3. `memcpy_s` 家族的 `destMax` 等于拷贝长度、且目的地记录的容量也等于该长度时，
   视为构造上容量匹配；
4. `x <= 0` 的落空分支记录下界 `x > 0`。

结果：`communication_wifi` 从 **2 条候选（`capability.export` 1 + `copy-range` 1）
变成 1 条（仅 `capability.export`）**——误报消失，未受影响的候选不动。

但"一个站点安静了"本身不是结论：补丁改的是**通用**的容量推断与下界记录，
它完全可能顺带把别的站点也弄安静，或者反过来把本该报的地方压掉。
所以在**全部 42 个组件**上各跑一遍（`--run`），按 `(file, line, rule_id)` 三方比对
候选集，且比对前先断言两次运行的 `snapshot_sha256` 与 `plan_sha256` 相同——
这样差异不可能来自 scope 变化：

| | 条数 |
|---|---:|
| baseline 候选 | 179 |
| 打补丁后候选 | 178 |
| **移除** | **1**（`ipc.parcel.copy-range` @ `communication_wifi`<br>`wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp:385`） |
| **新增** | **0** |
| 逐组件与 baseline 完全相同的组件 | 41 |
| 与 baseline 有差异的组件 | 1（`communication_wifi`） |
| scope 哈希不一致的组件 | 0 |
| 未能比对的组件 | 0 |

**新增为 0 是这张表里最重要的一格。** 移除只说明补丁在它该安静的地方安静了；
新增才说明补丁没有把这条规则的作用面扩到别处而凭空造出候选——
如果四个补丁里有任何一个把"未记录"误读成"已记录"，这里就会出现新增。
0 说明这四处改动都只影响它所针对的那一个形状。

#### 5.1.1 一处必须交代的过程问题：跑出结果的那棵树和补丁对不上

第一次 `--run` 用的副本，与 `copy_range_counterfactual.py --build` 现在产出的副本，
`analysis.py` 的 sha256 **不一致**。查清了原因，也做了处置：

- 差异**只在注释措辞**（两处注释的换行不同），代码行逐字相同；两份补丁正文
  去掉注释行后完全一致。
- 即便如此，这不构成"可以照旧使用"的理由：证据里写着"这 42 个组件的比对结果是
  由这四个补丁造成的"，而补丁与跑出结果的那棵树哈希不符，这句话就无法被检验。
- 而且上一会话认为 `patch.diff` 已写入，实际上**从未写盘**——`build()` 在
  `DEST` 不存在时直接抛 `FileNotFoundError`，而只有 `report()` 建过该目录。
  也就是说，当时连用来声称"哈希不一致"的那个比对基准都不存在。

处置：给 `build()` 补上建目录；把跑出结果的那棵树哈希写进
`copy_range_counterfactual_20261017/patched_analysis.sha256`；`--report` 在比对前
**校验磁盘上的副本哈希是否等于记录值，不等则直接报错退出**，而不是把输出
归到一份并非产出它的补丁上。然后归档第一版输出（`cf-out-all-run1/`，不删）
并用重新生成的副本**整份重跑 42 个组件**。

重跑结果与第一版**逐组件完全相同（42/42，含 scope 哈希）**，
上表数字两版一致。这同时说明：注释措辞的差异确实不影响行为——
但这一点现在是**量出来的**，而不是从"差异只在注释"推出来的。

（此前的 `report()` 还把 `removed`/`added` 写成 `tot_base - tot_new` 与
`tot_new - tot_base` 两个净差，会打印出 `added=-1` 这种与字段语义相反的值；
已改为各自的实际条数，另记 `net_change`。）

## 6. "子类 1"自身的精度缺口：AUTH-01 的自明误报模式

对 11 条规则里候选最多的 AUTH-01（103/179）做了一次筛查。
筛查**只用报告自身携带的字段**（候选的 `symbol`、以及 `message` 里记录的 `path`），
因此不需要读源码即可复现；随后再逐条把被标记的候选从
**pinned blob**（`git rev-parse <commit>:<path>` → `git cat-file blob`，
不读工作树）取出源码核对。

| 批次 | AUTH-01 候选 | 被标记 | 占比 | guard_symbol | empty_path | enforced_path |
|---|---:|---:|---:|---:|---:|---:|
| baseline 30 | 92 | 10 | 10.9% | 8 | 6 | 0 |
| 新 12 | 11 | 5 | 45.5% | 2 | 2 | 1 |

三种模式的判据：

- **`guard_symbol`**——报告归责的 "handler" 本身就是一个名字像检查的函数。
- **`empty_path`**——报告声称存在路径，但 `message` 里记录的是 `path=()`。
- **`enforced_path`**——记录的路径里含一个求值为 `True` 的强制校验调用条件。

### 6.1 逐条核对：被归责的 handler 就是 guard

15 条被标记的候选，源码摘录**全部**从 pinned blob 读到（0 条失败）。
代表性几例（`>>` 为候选行）：

```text
baseline30  systemabilitymgr_samgr  frameworks/native/source/system_ability_load_callback_stub.cpp:36
  >>  36      if (!EnforceInterceToken(data)) {
      37          HILOGW("...check interface token failed!");
      38          return ERR_PERMISSION_DENIED;

baseline30  inputmethod_imf  services/src/input_method_system_ability.cpp:168
  >> 168          if (IsImeInUse()) {

baseline30  multimedia_player_framework  .../recorder/ipc/recorder_service_stub.cpp:215
  >> 215          permissionResult = CheckPermission();

new12       ability_dmsfwk  services/dtbschedmgr/src/distributed_sched_stub.cpp:266
  >> 266          if (!EnforceInterfaceToken(data)) {
      268              return DMS_PERMISSION_DENIED;

new12       telephony_core_service  frameworks/native/src/raw_parcel_callback_stub.cpp:31
  >>  31      if (!CheckCurrentDescriptor(data)) { return; }
```

这 10 例里，规则把**执行边界检查的那个函数**当成了"没有被边界检查覆盖的 handler"。

### 6.2 成因是实测的，不是推断的

关键一点：检测器**本来就有**一条针对这个形状的抑制路径。
`analysis.py:1322` 在发出 AUTH-01 之前先调 `relay_guard`，
其调用点注释写着：

> `relay[0] == "guarded"`: the relayed-to function is the guard, so
> this call site is not itself an unguarded boundary.

所以每个被标记的候选，都是这条路径**没有触发**的地方。
"为什么没触发"必须回答到具体条件，不能只说"名字表不全"。
做法是把 `relay_guard`（`analysis.py:1159`）的**六个出口**各自打上标签，
在 pinned 树的副本上重跑这些组件，把判定按 `file:line` 关联回候选
（`auth01_precision_probe.py --instrument --run --cause`）。

关联前先量了两件与结论无关、但与产物可复现性有关的事，因为第一版产物在这两点上
是错的（把判定原样 append，于是同一判定重复几十次）：

- 检测器会**按每个 IPC 入口各扫一遍**同一个调用点，所以同一站点会被重复判定多次。
  七个组件合计 **44 个不同调用点，重复 2～80 次（全为偶数）**。
- 同一个站点**没有出现过两个不同判定**（44 个站点里 0 个冲突）。

因此把判定折叠成去重集合是无损的；产物里同时保留 `relay_verdict_passes`
记录该站点被扫过多少次。这样产物不再随入口数漂移，而"是否曾有冲突判定"
这个更强的性质也留下了记录。

10 条 `guard_symbol` 候选的实测分布，恰好覆盖全部 10 条：

| `relay_guard` 出口 | 条数 | 被归责的守卫 |
|---|---:|---|
| `:1182` 实参未被携带（**零实参守卫**） | 4 | `CheckPermission`×2、`CheckandDoUnFreeze`、`IsImeInUse` |
| `:1199` 顶层 `if` 不是描述符谓词（**守卫直接 return 比较**） | 5 | `EnforceInterceToken`×4、`EnforceInterfaceToken` |
| `:1225` 检查之后没有 `switch`（**纯谓词，不是分发器**） | 1 | `CheckCurrentDescriptor` |

三条成因各不相同，而且都是**形状**问题而非名字表问题：

1. **零实参守卫在读取函数体之前就被判负。** `relay_guard:1182` 的
   `if not carried or any(name not in fn.params for name in carried)` 要求调用
   **至少携带一个入口参数**。实测归到这一出口的四个守卫全部零实参：

   ```cpp
   int32_t RecorderServiceStub::CheckPermission()
   bool    InputMethodSystemAbility::IsImeInUse()
   int32_t PlayerServiceStub::CheckandDoUnFreeze()
   ```

   调用形态是 `permissionResult = CheckPermission();`、`if (IsImeInUse()) {`、
   `auto res = CheckandDoUnFreeze();`——`carried == []`，于是 `relay_guard`
   在读函数体之前就返回 `None`。名字表再全也救不了这一类，
   因为决定发生在更早的一步。

2. **守卫写成 `return token == desc;` 时找不到 `if`。** `relay_guard:1199` 只在
   被调函数的**顶层语句**里找 `if_statement`，且其条件要算成描述符谓词。
   而 samgr/dmsfwk 的守卫是：

   ```cpp
   bool SystemAbilityLoadCallbackStub::EnforceInterceToken(MessageParcel& data)
   {
       std::u16string interfaceToken = data.ReadInterfaceToken();
       return interfaceToken == GetDescriptor();      // 没有 if
   }
   ```

   实测 10 次 samgr 调用**全部**落在出口 3，确认就是这个原因。
   这也说明出口 3 **遮蔽**了出口 6：`EnforceInterceToken` 同样没有 `switch`，
   但因为更早的出口就返回了，永远走不到那里。

3. **即使守卫形状齐全，出口 6 仍会否决它。** `relay_guard:1225` 要求检查之后
   跟随一个 `switch_statement`——即被调函数必须是**内层分发器**。而
   `CheckCurrentDescriptor` 是纯谓词：

   ```cpp
   bool RawParcelCallbackStub::CheckCurrentDescriptor(MessageParcel& data)
   {
       std::u16string myDescriptor = GetDescriptor();
       std::u16string remoteDescriptor = data.ReadInterfaceToken();
       if (myDescriptor != remoteDescriptor) {
           TELEPHONY_LOGE("descriptor check fail!");
           return false;              // 这个分支确实离开了
       }
       return true;                   // 但没有 switch 跟在后面
   }
   ```

   它有正确的 `if`、mismatch 分支也确实 `return`——出口 3、4、5 都过得去，
   唯独在出口 6 被否。实测归类为 `6_no_switch_after_check`，1 条。

一句话：`relay_guard` 是照**内层分发器**（`OnRemoteRequestInner` 那种先查 token
再 `switch (code)` 的函数）写的，却被拿去判定**谓词助手**（`bool CheckX(data)`）。
两者的形状不同，于是三种不同写法各自卡在三个不同出口上。

### 6.3 一处更强的自相矛盾：`enforced_path`

`ability_dmsfwk` 的 `distributed_sched_stub.cpp:271` 同时被 `enforced_path` 命中：
报告的路径里记录 `EnforceInterfaceToken(data) => True`——即**边界已经强制通过**——
而报告仍然把它作为"没有被强制校验覆盖"的候选发出。这一条不需要读源码就能判定矛盾，
因为矛盾完全在报告内部。

### 6.4 关于 `empty_path`

`empty_path` 6+2 处中，有 4+2 处与 `guard_symbol` 重合（同一批 samgr/dmsfwk 候选）。
`empty_path` 单独出现的 5 处（`ANIRemoteObject::callOnRemoteMessageRequest`、
`PasteboardDisposableObserverStub::OnRemoteRequest`、`IEsimServiceCallbackStub::OnRemoteRequest`、
`RawParcelCallbackStub::Transfer` 等）性质不同：那里的消息归责对象是**入口自己**，
不是守卫，所以成因关联脚本把这几行标为 `entry_named_not_a_guard` 并**不给成因**——
对它们套用 `relay_guard` 判定会是在回答一个没被问的问题。
它们只说明"报告声称有路径却记录空路径"这层自相矛盾，**不足以**单独判为误报。

## 7. 这对原始目标意味着什么

原始目标要求"把其他几个子类完成到和 1 子类同样的水平"。
本项的度量把这个目标从口号变成一个可执行的判断：

1. **子类 1 的"水平"是 103 条候选，其中至少 10.9% 是可自证误报。**
   照字面把其他子类"提升到同一水平"，等于把该误报率作为目标。
   目标应当重新表述为**"每条规则在真实代码上都有正例、且假阳性率可度量"**，
   而不是"候选数与子类 1 相当"。
2. **AUTH-03/DATA-01 的沉默不是"能力不足"。**
   §3 证明这两个 0 有不同性质：`identity-domain` 是形状缺席（换语料也换不来，
   除非语料本身含这种形状），`position-underflow` 是真阴性（规则被行使且正确沉默）。
   把前者当成"需要提升"会导致过度拟合语料；把后者当成"需要提升"会导致
   在正确的静默上造候选。
3. **真正可提升的是可度量性，而不是计数。** 本项交付的
   `auth01_precision_probe.json` 是第一个**可复现的**（只读报告字段）、
   有源码佐证的规则输出质量度量。其他子类应当在有真实正例之后
   获得同形的度量，而不是先涨计数。

## 8. 边界与局限

- 本项**未改动检测器一行**。四个补丁只作用于 `analysis.py` 的一份**副本**，
  pinned 树
  `635b3e0449c552f0ccc25118850d245962845568`（`0.8.0` / `oh-ipc-2026.10-v6`）
  全程只读。补丁不构成对检测器的提案；它是**成因证明**，说明误报由哪几处漏记造成。
- §6 的三种模式是**下界**，不是完整的误报普查。它们只覆盖"报告自身字段即可判定"
  的子集；需要读源码语义才能判定的误报（例如边界检查逻辑本身有洞）不在此列。
  因此**不得**用 10.9% 作为 AUTH-01 的整体假阳性率，只能说"至少 10.9% 可自证"。
- 被标记的候选**没有被删除、没有被降级、没有被重新打分**，仍留在各自报告里。
  本项只增加了一份关于规则输出的证据。
- `confirmed_vulnerabilities` 恒为 0；`validated_vulnerability` 恒为 0。
  候选是未验证的静态证据，不是漏洞。§5 判定的是"误报"，不是"代码安全"。
- 12 个新组件是**浅克隆**，SHA 由 `rev-parse` 固定；语料仓库在 Git 之外，不进提交。
- 新增的 8 个"零候选"组件不作为"该组件安全"的证据——
  §5 与交付项 4 已说明零候选的三种成因（规则形状 / 检测下限 / 解析失败），
  本项为"IDL 生成分发器"这一种增加了两个实例。

## 9. 本项产出的文件

```text
research/deliveries/ipc/20261017-widen-corpus-and-precision.md   (本文件)
research/deliveries/ipc/auth01_precision_probe.py                (只读筛查 + 证据生成)
research/deliveries/ipc/copy_range_counterfactual.py             (只读反事实：补丁 + 附带影响比对)
research/evidence/interface/ipc/component_audit_bline_20261017/  (components.json, index.json, 12×manifest)
research/evidence/interface/ipc/auth01_precision_probe_20261017/ (precision_probe.json — 含 15 条
                                                                pinned-blob 摘录, precision_probe.md,
                                                                relay_guard_cause.json)
research/evidence/interface/ipc/copy_range_counterfactual_20261017/ (patch.diff, patched_analysis.sha256,
                                                                  counterfactual.json, 42 组件逐条比对)
```
