# Unsafe-memory 分层复核样本框（2026-10-18）

## 当前状态

这是基于固定全扫描产物建立的**临时抽样框**，尚未完成人工复核。任务目标提供的总体数是 8,994 条；目前能核验的全扫描产物 `openharmony-abcd-full-scan-20261018-final` 含 9,323 条 `ohscanner.cpp.unsafe_memory_call` 原始观察行，差额 329 条。两者不能合并或互相替代；本样本仅用于推进 9,323 行产物的来源形状盘点，待查明 8,994 对应的扫描输入/规则版本后再锁定目标抽样总体。

该固定产物的 `run_signature` 为 `1696df82f39e2564e0821c0ad2e837a00c6d83f9276bf5e0c38a3bd1f511700b`，扫描器提交为 `0d9357ea22224b72c9756864dbd14b71a4723924`，manifest SHA-256 为 `52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`。抽样输入 CSV 和项目规模清单的哈希见 `sampling_manifest.json`。

对账确认 9,323 行的 diagnostic ID 全部唯一，按 ID 去重减少 0 行；分析状态为 partial 9,317、analyzed 6。因此差额 329 不能由重复诊断 ID 或分析状态筛选解释，必须找回对应 8,994 的原始 run/config 或明确过滤口径。

同一 `run_signature` 的交付报告目录 `openharmony-scan-reports-20261018` 再次核对了扫描器提交、manifest SHA、run signature 和 detector 数：四项身份/数量一致，`checksums.json` 中 compact summary 和 detector summary 的哈希也匹配。该报告确认的 unsafe-memory 数同为 9,323；它没有给出 8,994 的来源。抽样生成器可通过 `--report-root` 强制执行这项交叉校验，并将结果哈希写入机器清单。

## 分层与盲审材料

从 9,323 条原始记录按 rule ID、诊断消息中的 sink callee 形状、仓库选中源码文件数四分位分层；种子为 `20261018`，固定抽取 160 条。总体按 rule 为 8,661 条 format-string 观察、662 条 unsafe memory-call 观察；样本按 rule 为 147/13。具体每层总体数、样本数、纳入概率和结果来源 hash 均在机器清单中。

固定扫描产物（修正前）的消息形状统计如下。这里的 callee 形状来自扫描器消息的结构化提取，仅用于描述触发分布，不能推导 FP/TP：

| Rule | 消息中识别的 callee 形状 | 总体 | 样本 |
|---|---|---:|---:|
| `ohcpp-format-string-candidate-002` | `fprintf` | 8,452（90.66%） | 134 |
| `ohcpp-unsafe-memory-call-candidate-001` | 消息中无法按当前模式解析 | 662（7.10%） | 13 |
| `ohcpp-format-string-candidate-002` | `printf` | 129 | 5 |
| `ohcpp-format-string-candidate-002` | `vfprintf` | 52 | 4 |
| `ohcpp-format-string-candidate-002` | `vprintf` | 23 | 3 |
| `ohcpp-format-string-candidate-002` | `syslog` | 5 | 1 |

`fprintf` 是主要候选来源形状，下一步要由盲审检查 format 参数是否动态、受控以及调用路径约束；当前仍无人工 FP 标签，不能据此收紧规则。

## 已确认的参数位缺陷与待验证误报形状

2026-10-19 复核发现，旧版 detector 对 `fprintf` 和 `vfprintf` 错把第一个实参（`FILE *` stream）当成 format；它们的 format 参数是第二个实参。`printf`/`vprintf` 的 format 参数是第一个，`syslog` 的 format 参数是第二个。旧版因而会把 `fprintf(stderr, ...)` 报成 format=`stderr`。

0.2.0 起按 API 分开 format 参数索引。0.3.0 起，限定调用和同文件可见的同名函数声明不再套用标准 API 参数位，而保留为 `partial/unknown`。最终 0.3.0 固定重放覆盖 829 个源码文件，所有输入 hash 均匹配；基线逐字段重现原始 8,504 行。新版得到 217 条 format 候选（`fprintf` 166、`vfprintf` 51），其中 8,287 条旧位置候选消失、217 个位置改为正确 format 表达式；825 个文件 outcome 为 complete，4 个为 partial（4 个签名未知文件均已列在 JSON 工件）。旧消息中有 6,395 条明确把 `stderr` 当成 format。机器结果与重放脚本见 `research/tests/a_null_03_unsafe_memory_review/replay_format_argument_positions.py` 和 `format_argument_positions_before_after_20261019.json`。

重放期间发现同名声明检测的首版正则会在 `third_party_glfw/tests/glfwinfo.c` 的 40,892 字节输入上发生严重回溯；已改为逐行、有长度上限的 fail-closed 检查，并增加超长行回归。最终重放是在此性能修正后完成，报告中的 after-source SHA-256 绑定到该版本。

2026-10-19 后续复核又在原扫描的 format 候选中找到 14 条条件表达式：原扫描 detector 0.1.0 在 7 个 hash 匹配源码文件上逐条重现 14/14。0.4.0 对两侧均为字符串字面量的 8 条表达式不再产生 format 候选；另 6 条含 `PRIx64`、`PRId64`、`PRIo64` 等宏 token 的表达式仍保留候选。该语法边界重放不证明源码整体安全，也不构成全扫描误报率。0.5.0 将原始字符串格式从固定 CSV census 中找出的 4 条直接 raw-string 候选也分类为编译期字面量，并在 4 条 hash-bound source replay 中全部抑制。修正后的定点 replay v4 绑定 pinned detector 与 helper：共复现 18/18 原始观察，11/11 源码 hash 匹配；8 条 literal conditional 抑制、6 条 macro/dynamic conditional 保留、4 条直接 raw-string 格式抑制。机器结果见 `literal_format_conditional_replay_20261019_v4.json`。同一 pinned candidate CSV 的表达式级 census 覆盖 157 条 `printf/vprintf/syslog` 记录（129/23/5）：14 条条件表达式、12 条当前识别的纯字面量格式（8 条条件分支 + 4 条 raw string）。其余记录未逐一 source replay，不能由该定点验证外推。更早 v2/v3 replay 保留作历史，不作为完整 0.5.0 结论；原始脚本为 `research/tests/a_null_03_unsafe_memory_review/replay_literal_format_conditionals.py`。0.5.0 合成 controls 覆盖全字面量、嵌套字面量、动态分支、raw string 以及 `fprintf` 参数位。此前本地 audit harness 是一致性核对，不属于外部独立人员验收，仍须由 T 线 reviewer 独立复核。

这是由 API 签名和输入字节支持的规则实现缺陷，不是对余下候选的人工标签或全扫描准确率结论。该重放覆盖旧 `fprintf`/`vfprintf` 候选源码文件，不等于对 92,228 个适用文件重新全扫。当前保留的动态 format 候选仍需独立复核其来源、可信度、输入控制和路径约束；不能仅凭其数量判断 FP/TP。

2026-10-19 又在相同 829 个源码文件上对 0.5.0 完整重放。第一次 v5/v6 运行仅加载 pinned detector 文件，基线相对导入了工作树的 `memory_safety.py`；虽逐条重现 8,504 行，但共享依赖没有冻结。v7 起重放器把 base commit 的 detector 和 `memory_safety.py` 放进隔离模块命名空间加载；v8 同时记录 before/after 两侧 detector 与 helper source hash。完整依赖固定后仍逐条重现 8,504 行且 829/829 个源码 hash 匹配；新版保留 456 条正确 format 参数候选（`fprintf` 405、`vfprintf` 51），825 个文件 complete、4 个因签名未知为 partial。相较 0.3.0 的 217 条，0.5.0 仍保留 239 条“表达式以字符串字面量开头、后接标识符/宏”的候选，例如 `"[LOG] " fmt "\\n"`；旧版 `startswith('"')` 规则会把这些动态拼接误当作固定字面量而抑制。这个差异说明语法边界修正，不是 239 条漏洞标签。新增合成 control `format_literal_prefix_macro.cpp` 锁定字符串前缀后接未展开宏仍保留候选；另一个 control 确认 raw string 格式字面量安静，raw-string 内标点不改变实参切分。该语法修正确认后，本轮 829 个原候选文件的 format 计数仍为 456。共享实参切分器对旧扫描中的 unsafe-memory-call 规则做 pinned 子集回放：235 个源码文件 hash 235/235 匹配，旧版 662/662 行复现，新版仍为 662 行、无 finding 差异，230 个 complete、5 个 partial。该检查仅覆盖原先有 finding 的文件，不是全库重扫，也无法排除旧扫描无 finding 文件中新产生的观察。format 主重放与依赖 hash 见 `format_argument_positions_before_after_20261019_v8.json`；unsafe-memory-call 子集见 `unsafe_memory_call_argument_split_replay_20261019_v3.json`。条件和 raw-string source replay 见 `literal_format_conditional_replay_20261019_v4.json`。这些仍是开发侧重放，须由 T 线独立复算，不能外推全扫描准确率。

针对这 456 条候选另生成表达式清单（v8 canonical artifact）：按语法形状计有 122 条 call/macro invocation、79 条纯标识符、239 条字面量前缀混合 token、15 条其他复合表达式和 1 条条件表达式。对 239 条字面量前缀表达式逐项重新读取源码并匹配 SHA-256（239/239），其中 177 条紧接 `PRI*` 格式宏、21 条为 `TIFF_SSIZE_FORMAT`，其余是项目宏或变量（含 `fmt`、`format`）。120 条 call/macro invocation 的外层调用名是 `_()`；专项只读审计逐项匹配源码 SHA（120/120），发现 118 条 `_()` 参数是纯字面量序列、2 条含 `PROJECT_NAME` 宏；110 条源码直接包含 gettext 头，10 条未直接包含，120 条均未在同文件定义 `_`。这是 gettext 来源形状证据，尚未核实所有跨文件定义、catalog 内容或运行时可控性。v8 census 见 `format_argument_positions_before_after_20261019_v8.json`；逐条记录与脚本为 `gettext_format_candidate_source_audit_20261019_v3.json` 和 `research/tests/a_null_03_unsafe_memory_review/audit_gettext_format_candidates.py`。这些 census 只描述字符形状和源码身份；宏/本地化语义仍需 T 线独立验证，不可自动当作安全或漏洞标签。

对候选源码自身再做只读定义/包含检查：239 条中有 18 条源码直接包含 `<inttypes.h>`/`<cinttypes>`，14 条所在源文件直接定义了首个尾随宏 token（包括 `MaybeUInt64_FMT`、`XML_FMT_STR`、`WORD*`、`SIZE_T_FMT` 等）。可见的部分替换值是字符串字面量或宏别名；这仍不证明条件编译下的生效定义、跨文件定义链或构建参数。广泛递归搜索受仓库 symlink/访问权限错误影响，不作为完整宏定义证据。因此本轮不抑制任何候选；下一步应在固定 compile context 下由预处理或 AST 验证，再决定常量宏能否归类为非风险观察。

- `reviewer/blind_review_queue.csv`：供复核者使用；包含 repo/commit/file/line/source hash 及已校验的源码上下文，隐藏 rule、扫描消息和分析状态。
- `reviewer/review_protocol.md`：固定盲审边界、标签定义、证据记录与回交格式。
- `coordinator/review_key.csv`：协调者私有映射；包含稳定原始诊断 ID、rule、scanner message、状态和权重。人工标签冻结前不要与盲审队列一起交给复核者。
- 标签冻结后用 `research/tests/a_null_03_unsafe_memory_review/merge_review_labels.py` 校验回收 CSV 并合并私有映射；须提供回收文件 SHA-256，解盲结果只能写在 coordinator 目录下。该工具只校验完整性，不验证复核者身份或结论正确性。
- `sampling_manifest.json`：固定输入身份、分层、权重、计数口径和阻塞项。

样本 160/160 的候选源码文件 hash 与扫描诊断的 `source_sha256` 匹配。复核标签仍为空，当前人工复核数是 0；不得把 `source_bound` 当作安全/漏洞标签。

## 四类报告计数

| 计数 | 当前结果 | 口径 |
|---|---:|---|
| 原始观察行 | 9,323 | 固定 CSV 中该 detector 的逐条 diagnostics，保留每个位置。 |
| 仓内根因簇 | 未建立 | 没有经人工/程序事实验证的根因键；不能拿同文件、同规则或文本相似代替根因。 |
| 跨仓相同源码簇 | 0 | 按 rule ID + 完全相同 source SHA-256 分组，且至少跨两个仓库；这里只报告源相同簇。 |
| 人工复核结论 | 0 已复核 / 160 待复核 | 盲审结果未回收；不得以模型/扫描器输出代替人工标签。 |

源文件哈希聚类没有移除原始记录。当前产物的 9,323 行与任务目标 8,994 行总体不一致；临时样本不支持 Precision/Recall，也不授权全局过滤或降权。

## 函数形状盘点与更新的盲审 pilot（2026-10-19）

为满足按规则、函数形状和仓库规模抽样的需求，新增 `research/tests/a_null_03_unsafe_memory_review/audit_function_shape_distribution.py`，对每条候选的固定源码先核对诊断 SHA-256，再用扫描器已有的 bounded lexical function-span helper 标注最内层**具名外层函数**形状。9,323/9,323 行源码 hash 匹配，audit status PASS；该脚本只做抽样分层特征，不判断告警真假、可达性或 CFG。lambda/宏展开、模板实例和编译配置不由该函数形状分类器解析；源码位置不在可识别具名函数内的记录明确放在 `outside_named_function`。

形状分布：

| Rule | 自由函数 | 成员方法 | 宏定义体 | 具名函数外 |
|---|---:|---:|---:|---:|
| format-string（8,661） | 8,004 | 524 | 123 | 10 |
| unsafe memory-call（662） | 599 | 57 | 4 | 2 |

共有 20 个非空 `rule × function shape × repository scale quartile` strata。比例抽样 pilot 固定抽 160 条，每层至少 1 条，其余按层内总体量分配；源文件 hash 160/160 匹配。当前唯一推荐的审阅队列为 `function_stratified_pilot_20261019/reviewer/blind_review_queue.csv`，reviewer 文件不暴露函数形状、rule、scanner message、状态或权重；协调员 key 独立保存在 `function_stratified_pilot_20261019/coordinator/review_key.csv`。原始 callee-shape pilot 保留作历史工件，不要把两份各 160 条队列当成同一个样本或合并标签。

- 函数形状 census：`function_shape_audit_20261019_v2.json`，SHA-256 `3f4e648e5421934b03f913a0f742feb3ec3c04447e7f519833b91f48473c6f4e`。
- Sampling manifest：`function_stratified_pilot_20261019/sampling_manifest.json`，SHA-256 `acee6a439b8726a8a6eafa3467e9bf6f991249cd94c515c68df9ad8e6c4b8e07`；其 function-shape census 输入 SHA 与上列一致。
- Reviewer queue：SHA-256 `ccbf798b49789a246e854f8aa225f06bd7d7d9b11330dba767392d27e0a1ef16`；当前 0/160 标签，pending independent review。

本 pilot 仍基于 9,323 行 provisional frame，expected 8,994、observed 9,323、差 329；不能代表未绑定目标总体，也不能据此报告 Precision/Recall 或收紧规则。
