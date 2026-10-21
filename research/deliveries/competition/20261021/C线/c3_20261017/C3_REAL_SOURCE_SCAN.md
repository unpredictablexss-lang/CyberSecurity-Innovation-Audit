# C3：真实 Runtime 范围与零新增候选解释

算法冻结：`4ea5f4020884aed5860a88d50f5a926610e7b98a`；Detector/model `0.2.0`；具体模型、parser 和预算见 `C3_RUN_MANIFEST.json`。

目标仓库为官方组织 GitHub 镜像 `openharmony/arkcompiler_ets_runtime`。固定父提交 `830e85b40240677039719fcbf14f721ad3b19050`，修复提交 `a0e30483ab3e4aead67ecfb5c708489915e447f9`。目标文件仅 `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`。commit/tree/blob/source SHA 和 12 个摘要依赖逐版本核验记录见 `C3_SOURCE_EVIDENCE.json`。无隐式 fetch；对象同步与分析分开。

## 历史对照仍成立

同一 Filter 限定符号与签名、同一 C3 规则和预算：父提交独立研究执行 1 candidate，修复提交 0 candidate、1 matched。分别探索 263 / 266 个状态步骤。父版本 Store 1498 行把 `thisValue` 的 arrayType 用于 newArray；修复版本 1499 行使用从 newArray 读取的 newArrayType。词法引用记录与实际符号路径观察分别保存，词法引用本身不冒充路径证明。

两次目标函数子树均无解析错误，但整文件仍 partial；错误位置和函数字节范围保留在普查 JSON。正式 Runner 两次均 blocked/not_analyzed、0 diagnostics。固定算法未因 skip、异常或未解析 Filter 得到修复后零候选；该函数确实产生 matched 观察。C2 同 Git 源码比较器也单独保存，不作为生产真值或历史 verdict 依赖。

## 扩展调查

结构索引识别同一文件中 53 个精确 owner 函数。只有 Filter、CopyWithin、Set、With 的精确 caller 与六参数签名进入已审查配置；其余 49 个没有据此宣称完成语义分析。见 `C3_CENSUS.json` 的函数范围、子树解析状态、类型源、创建调用、Sink、来源引用及受阻原因。

- Filter：修复版本从目标新对象取 token，得到 matched；仍是研究范围。
- Set：另一个真实写入路径，目标 token 就地从目标对象取样，得到 matched；没有新来源不一致候选。
- CopyWithin：同一对象上的旧类型采样经过未闭合的调用副作用，得到 unknown。CalculatePositionWithLength、LogicAndBuilder、FastGetPropertyByIndex 等路径尚无足够类型稳定性摘要；按值传参并不使旧事实恢复有效。
- With：包含 NewTypedArraySameType、CallNGCRuntime 等未建模创建/调用语义，得到 unknown。不能仅根据 SameType 名称认定安全。
- Slice、Map：出现 NewTypedArray，但没有当前规则对应的 StoreTypedArrayElement Sink；没有按此规则执行完整语义验证。
- ToSorted、ToReversed：出现 NewTypedArraySameType，但没有该 Sink；不能把当前零候选解释为这些路径安全。

固定修复版普查新增 candidate 为 0，原因是 2 个配置得到来源匹配、2 个配置未知，另有创建路径不对应当前 Sink。53 是索引函数数，4 是配置适用数，不能称 53 个函数均已验证安全，更不能称整个 Runtime 无漏洞。

## Species 与动态证据

源码 `NewObjectStubBuilder::NewTypedArray` 快路径按源 HClass 创建并设置 on-heap HClass；slowPath 调用 TypedArraySpeciesCreate。因此不能从 creator 名称或传入 srcType 推导最终对象同型，调用也不能当纯函数。模型把不同创建结果与旧 token 来源作为条件性候选；species 最终返回身份/实际元素类型、路径条件同时可满足及产品入口仍是义务。

未执行上游构建或动态 PoC。提升权限后已确认本机 Ubuntu-22.04 / Python 3.10.12 可运行本项目回归；未发现 cc、Docker、Podman、bwrap/nsjail 或 Docker socket，也未准备上游工具链/依赖。WSL 存在不等于具备安全执行上游构建与 PoC 的环境。不得把早先访问拒绝继续写为“没有 WSL”。后续需隔离构建环境、完整上游依赖、固定构建参数及双版本输入；不能把静态状态步骤当运行时复现。

GitCode 主库的精确历史交叉核验仍 unavailable；本轮官方镜像对象链验证不等于真实发布分支、产品受影响版本或 CVE 映射验证。无新增 confirmed/reportable 漏洞，无可报告 CIA 影响或产品 PoC。
