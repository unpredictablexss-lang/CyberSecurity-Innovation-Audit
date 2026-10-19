# 交付项 15：再下 7 个组件——1 条候选、四种静默成因

> 本项继续回应原始目标里的"**多下载几个组件仓库测试**"，
> 以及"**把其他子类完成到和子类 1 同样的水平**"中的**测量**部分。
> 本项不修改检测器、不删除任何候选、不改变任何语料克隆。

## 0. 一句话结论

按 IPC 机制新克隆 7 个组件（1859 个入选文件、11979860 字节、4977 次
`Interpreter.value` 调用）后，11 条规则合计只产出 **1 条候选**，属于
AUTH-01；读 pinned 源码后确认它是**已知宏守卫误报类的第二个独立实例**
（`FALSE_RETURN_V` 的宏体含 `#exec` 字符串化，展开器拒绝，守卫不可见）。
其余 10 条规则为 0，且这 7 个零**不是同一个陈述**：2 个组件没有任何入口根，
1 个组件的唯一入口在 mock 路径下，4 个组件入口被真实走到
（4—16 个根、155—3352 次 value 调用），但都没有满足其余 10 条规则中任何一条的合取
（其中 `multimedia_media_foundation` 只命中了 AUTH-01）。
本项给出这三类的区分证据，并把"AUTH-03 为什么在这批语料上仍为 0"
落到一条可复现的机制上：全语料只有 **2 次**权限谓词求值，且
`subject` 都是 `unknown`（`analysis.py:1364-1365`），caller-class 合取
按构造不可能成立。

## 1. 语料：7 个组件与固定版本

浅克隆 `--depth 1`，SHA 由 `git -C <repo> rev-parse HEAD` 固定，
`clone-manifest.txt` 与报告里的 `commit` 一致；**本轮没有做任何 fetch**。

| 组件 | commit | 入选文件 | 字节 | 完整/部分 AST | 候选 |
|---|---|---:|---:|---:|---:|
| `communication_netmanager_ext` | `8c35917b7e2f152813b13a20530a8452cf73d938` | 482 | 3,419,149 | 409 / 51 | 0 |
| `distributeddatamgr_objectstore` | `1a63f5a9827dc68ebd9b02b58935cd18996b2c1b` | 63 | 256,540 | 56 / 6 | 0 |
| `distributeddatamgr_preferences` | `bff9efd79afc0d7d1ed22a63ff355f1600404596` | 341 | 2,118,436 | 277 / 64 | 0 |
| `multimedia_media_foundation` | `486aae6c8ed9c22499e6bc171748fb44fe7d88b0` | 534 | 3,172,759 | 352 / 182 | **1** |
| `powermgr_battery_statistics` | `271a545acc0ececc746cfe0bb7c1501943df7c64` | 77 | 414,803 | 62 / 15 | 0 |
| `powermgr_display_manager` | `6b2ee24ce30ca93a3fba451b912e0af59538b794` | 102 | 530,105 | 94 / 8 | 0 |
| `telephony_sms_mms` | `41cef006c6c4b7fdc9ee0bb8d9ae659ee2ebbfd8` | 260 | 2,068,068 | 238 / 21 | 0 |
| **合计** | | **1859** | **11,979,860** | **1488 / 347** | **1** |

7 份报告 `bucket_closure.closed` 全为 `true`，`files_unaccounted` 全为 0；
`files_in_scope_without_a_claiming_detector` 只在
`telephony_sms_mms` 出现 1 个 `ts` 文件，其余组件没有检测器声明语言之外的文件。
也就是说：**每个组件的 C/C++ 文件要么进了完整 AST，要么进了部分 AST，
没有"在范围内但没人读"的文件**。

## 2. 唯一候选：AUTH-01 的宏守卫误报

`openharmony/multimedia_media_foundation`，
`src/buffer/avbuffer_queue/avbuffer_queue_producer_stub.cpp:49`：

```cpp
45    FALSE_RETURN_V(it != stubFuncMap_.end(), IPC_STUB_INVALID_DATA_ERR);
46    FALSE_RETURN_V(it->second != nullptr, IPC_STUB_ERR);
47    FALSE_RETURN_V(GetDescriptor() == arguments.ReadInterfaceToken(), ERR_INVALID_STATE);
48
49    return (this->*(it->second))(arguments, reply, option);
```

候选自己的摘录里就能读到第 47 行的描述符比较，报告却给出 `path=()`。
原因不在这一行，而在宏的定义（`interface/inner_api/common/log.h:393-400`）：

```cpp
#define FALSE_RETURN_V(exec, ret)                                       \
    do {                                                                \
        if (!(exec)) {                                                  \
            MEDIA_LOG_E_NO_RELEASE("FALSE_RETURN_V " #exec);            \
            return ret;                                                 \
        }                                                               \
    } while (0)
```

宏体含 `#exec`（字符串化），`cpp_macros.py:235-237` 的拒绝条件命中
`variadic_stringify_or_token_paste`，守卫不进入被解释的程序，`path=()` 为空，
AUTH-01 的"无法证明校验发生"分支成立。

这与交付项 11 §3 记录的
`pasteboard_disposable_observer_stub.cpp:48`（`ENFORCE` 宏）是**同一类、不同宏名、
不同组件、不同仓库**的第二个独立实例。它说明该误报类不是某个宏的特例，
而是"宏体含字符串化"这一条展开器边界的系统性后果。

候选的来源字段：

- `passes: ["all-files"]`；
- `file_parse_status: partial`、`file_analysis_status: not_analyzed`、
  `file_analysis_reason: incomplete_ast:partial`；
- 该组件 `complete-ast` 走完 352 个完整单元，`all-files` 因 1 个诊断被标
  `blocked`，但两者都在按设计发出候选。

**判定：静态候选，误报（守卫在源码中可见且位于候选行之前）；不从报告中删除。**
`validated_vulnerability` 在 7 份报告中均为 0。

## 3. 其余 10 条规则为 0：四种成因，不是一句话

`components.json` 的 `zero_reason` 字段把 6 个零候选组件分开：

| 组件 | 入口根 | 根文件数 | value 调用 | 判定 |
|---|---:|---:|---:|---|
| `distributeddatamgr_objectstore` | 0 | 0 | 0 | `no_entry_roots` |
| `powermgr_battery_statistics` | 0 | 0 | 0 | `no_entry_roots` |
| `distributeddatamgr_preferences` | 1 | 1 | 2 | `mock_only_entry_roots`（`preferencesmock/external_inner_kit/ipc/mock_ipc_object_stub.cpp`） |
| `powermgr_display_manager` | 4 | 4 | 794 | `entry_roots_walked_no_rule_conjunction` |
| `telephony_sms_mms` | 11 | 6 | 674 | `entry_roots_walked_no_rule_conjunction` |
| `communication_netmanager_ext` | 16 | 6 | 3352 | `entry_roots_walked_no_rule_conjunction` |

前两行只说明"这个组件里没有被建模的入口"，**不构成"规则没响"的证据**；
第三行的入口是 mock（`is_mock_path` 只做位置分类，不断言代码语义）；
只有后三行才把零归因到规则的合取条件。

### 3.1 为什么后三个组件的零可以归因到规则

根探针（`root_probe_site`）记录的是解释器实际开始走的入口与它调用
`value` 的次数，不是文本里有几个 `OnRemoteRequest`。后三个组件的根文件包括：

- `communication_netmanager_ext`：`services/netfirewallmanager/src/netfirewall_stub.cpp`、
  `services/networkslicemanager/src/networkslice_stub.cpp` 等 6 个真实 service stub；
- `telephony_sms_mms`：`services/sms/sms_interface_stub.cpp` 等 6 个；
- `powermgr_display_manager`：4 个 zidl callback stub。

`netfirewall_stub.cpp` 是一个可读的反例：它在 `OnRemoteRequest` 里显式做
描述符比较（第 113 行）与权限检查（`CheckFirewallPermission`，
第 101 行调用 `NetManagerPermission::CheckPermission`），所以 AUTH-01 不响
是正确的；AUTH-02 也不响，因为权限谓词被建模成守卫。这与"没有入口"是两件事。

### 3.2 AUTH-03 的 0：全语料只有 2 次谓词求值，subject 都是 `unknown`

`attribution.json` 记录（`value_attribution`）：

- 7 个组件中只有 1 个求值过任何权限谓词；
- 共 **2 条**记录，都在 `communication_netmanager_ext`
  `services/netfirewallmanager/src/netfirewall_stub.cpp:101`
  （同一个站点被走到两次）；
- `evaluations_by_subject = {"unknown": 2}`；
- `distinct_sites_by_caller_class_set = {}`，`reached_without_a_caller_class = []`。

`analysis.py:1364-1365` 的规则是：`subject` 取第一个
`caller`/`self`/`request` 类参数；若没有，且被调函数是
`TelephonyPermission::CheckPermission` 则取 `caller`，否则取 `unknown`。
这里被传进去的是权限名字符串（`itFunc->second.strPermission`），
不是身份值，所以 `subject=unknown` 是**按构造**的结果，不是解析失败。
AUTH-03 的 identity-domain / service-identity / request-identity 需要
caller/self/request 形态的参数；caller-class 需要
`caller_class_sensitive_call` 且状态里没有 caller class——本批语料
一次这样的求值都没有，所以
`caller_class_sensitive_calls_reached_without_a_caller_class = 0`
是"没有可命中的站点"，不是"命中了但被放过"。

这就是本批 7 个组件对 AUTH-03 的全部信息量：**零候选 ⇔ 零可满足站点**，
两者在这个语料上恰好同义，不能外推成"这些组件没有身份类问题"。

## 4. 这批数据支持什么、不支持什么

支持：

1. AUTH-01 的宏守卫误报不是一个孤例，已在第二个组件的第二个宏上复现；
2. 零候选必须带 `zero_reason` 才能读：`no_entry_roots` 与
   `entry_roots_walked_no_rule_conjunction` 是两种不同的事实；
3. AUTH-03 的沉默在本批语料上有精确的机制解释（谓词求值次数与 subject 形态），
   而不是靠"规则应该没问题"的推断。

不支持：

1. 不支持"这 7 个组件安全"——6 个组件的零里有 3 个不是规则层面的陈述，
   而 4 个走到入口的组件也没有被动态验证；
2. 不支持"其他子类已和子类 1 同水平"——本项只增加测量面，没有改动任何
   规则、策略或模型；`validated_vulnerability` 仍为 0；
3. 不支持"宏守卫误报可以靠加白名单消除"——本项没有加白名单，也没有改
   展开器；修复需要在共享的宏展开层做，属于 integrator 面。

## 5. 复现

检测器：只读 pinned 树
`/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit-b`
@ `635b3e0449c552f0ccc25118850d245962845568`，版本 0.8.0，
模型 `oh-ipc-2026.10-v6`。每个组件的 argv 相同，仅替换 `--repo-dir` /
`--repository` / `--commit` / 输出目录：

```bash
cd <pinned tree>
<...>/.venv/bin/python -m src.ohscanner.detectors.interface.audit \
    --repo-dir /home/audit/corpus-ipc-extra/<component> \
    --repository openharmony/<component> \
    --commit "$(git -C /home/audit/corpus-ipc-extra/<component> rev-parse HEAD)" \
    --out-dir <out>/<component> \
    --json-out <out>/<component>/report.json \
    --md-out <out>/<component>/report.md
```

两个仪器只是在同一 argv 上加 `PYTHONPATH` 与一个环境变量
（`IPC_ROOT_LOG` / `IPC_PROBE_LOG`），不改检测器返回值。

证据文件（提交在本仓库 `research/evidence/interface/ipc/extra_corpus_20261017/`）：

| 文件 | sha256 |
|---|---|
| `components.json` | `6e547f9857494126b78ffcc5882df03936b9cdedc6151d00a984520ce8a3c027` |
| `attribution.json` | `9c180cbeebde413edb9cfbfd045db7c3fba7fe85f4b9c111dad791d2c8463b64` |

仪器与生成器：

| 文件 | sha256 |
|---|---|
| `research/deliveries/ipc/probe_site/sitecustomize.py` | `67177e28683de37037e6b0b2bb88db86f2cd8453c80f5fbef452db95b23a5c9e` |
| `research/deliveries/ipc/root_probe_site/sitecustomize.py` | `8e49770f2e1db6dd3d9c3f9bd53e26fb2b0fb4b14f82f4338c05eac78ecaca16` |
| `research/deliveries/ipc/extra_corpus_measurement.py` | `1062142d4514b7144cf36047f029b869dd807e443fac4605cdc20e2230cb026b` |

生成器不重算任何检测结论：候选数、解析状态、哈希都从
`report.json` 读取；入口根与谓词记录分别来自两个仪器的产出。

## 6. 限制

- 语料是 2026-10-17 的 `master` 浅克隆快照，不覆盖分支与历史；
- `complete-ast` 只读完整单元，`all-files` 会把部分解析的单元也走一遍，
  本批 347 个文件是部分 AST，其中 1 个产出了候选（§2）；
- `zero_reason` 的 `mock_only_entry_roots` 是**路径分类**，不是语义判断；
- 本轮没有动态验证，所有候选与结论停留在静态证据层；
- 7 个组件之外仍有未测组件，本批数字不能代表整个 OpenHarmony。
