# C7-DEP Ark Runtime 模型依赖语义漂移审查

状态：complete_with_explicit_unknowns；所有安全结论：candidate/unassessed。

## 已核验事实
- 只读 pinned `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df` / tree `f4db05167c5cec007270c782c6bb97711e6414ae`；无 fetch、checkout、外部扫描、公共契约修改。
- C3 comparison：19 dependencies、1 unchanged、18 changed；unchanged 为 `profiler_operation.h` blob `e68a2db48f222945629adb637cd50be8a0f93651`。
- 18 个 changed blob 已逐项绑定 expected/current；C7-DEP-018 与 017 只证明 manifest row duplicate。
- C3 comparison/model 均为 0.6.2（C3 记录 model SHA-256 `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`）；C4_SOURCE_BINDINGS 明确为 0.6.1，pinned model.py 核验为 0.6.2，未混写版本。
- model 0.6.2 保留历史 reviewed binding；OHScanner 对象库中 33 个 unique expected/current upstream blobs 均不存在，本地 Ark source store 亦缺失，均记 unknown，未当通过。

## 18 项逐项审查
分类边界：equivalent=已证等价；semantic_drift=已证相关语义变化；needs_re_review=字节变化待重审；unknown=证据不足。基于现有证据为 equivalent=0、confirmed semantic_drift=0、needs_re_review=18、source-semantic unknown=18。

| ID | 角色 | 路径 | expected blob | current blob | 分类 | 已核验事实 | unknown |
|---|---|---|---|---|---|---|---|
| C7-DEP-001 | effect_summary | `ecmascript/compiler/stub_builder.h` | `b784eb0812c27f11c1bfd8673cda4bf884a6a9cd` | `9e2fbd3ede1da91133dcd936018285e597944515` | needs_re_review / unknown | blob changed | declarations, overloads, inline effects, calling convention |
| C7-DEP-002 | effect_summary | `ecmascript/compiler/stub_builder-inl.h` | `8658e6ee729c3b171639772ad3a1ada06442abd0` | `c0521ab7a55cd63850736c2db8a290115965373c` | needs_re_review / unknown | blob changed | inline implementation, template instantiation, side effects |
| C7-DEP-003 | effect_summary | `ecmascript/compiler/stub_builder.cpp` | `8aae4bfa151e8b8dbd58d03a5cd881f3315151c2` | `c630a6200215705843d11c0dd86c565709e8c6c4` | needs_re_review / unknown | blob changed | helper call graph, exception and return effects |
| C7-DEP-004 | effect_summary | `ecmascript/compiler/hcr_circuit_builder.h` | `176dd0a5ee320f814049c2b671119515c746380d` | `e66c414a7a739284b474c234e6f90bae0368cd11` | needs_re_review / unknown | blob changed | HCR branch, guard and control-flow semantics |
| C7-DEP-005 | effect_summary | `ecmascript/compiler/mcr_circuit_builder.h` | `631911dec663addd62533d6a6808ffe699a6f884` | `297a46c06349c0ed7e881ee4475291a41361f743` | needs_re_review / unknown | blob changed | MCR branch, state writes, exception effects |
| C7-DEP-006 | effect_summary | `ecmascript/compiler/lcr_circuit_builder.cpp` | `af4d27bcd46ea0a4a2980a805dd7de77970ffb56` | `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c` | needs_re_review / unknown | blob changed | LCR implementation and fail-closed behavior |
| C7-DEP-007 | effect_summary | `ecmascript/compiler/circuit_builder.cpp` | `b4bf452cac6bdeb820b78334be98cb3dc11330cb` | `225f09385632bfc2a6ff20bbdf2bfd8694fcffb6` | needs_re_review / unknown | blob changed | scalar, branch and exception primitive semantics |
| C7-DEP-008 | effect_summary | `ecmascript/compiler/new_object_stub_builder.h` | `f411d72cbca7915e56b9d851beeb57b788e438ac` | `ecdf871b20e884e013ce0f26877ef404e4950cb0` | needs_re_review / unknown | blob changed | NewTypedArray declarations, parameters, return type |
| C7-DEP-009 | effect_summary | `ecmascript/compiler/builtins/builtins_stubs.cpp` | `715c5d65164369bc93a82aa4a6cc1d19b7970143` | `f9c026f6b732cf090aca9df620c4d79bf7597f3b` | needs_re_review / unknown | blob changed | builtin helper parameters, effects, result type |
| C7-DEP-010 | effect_summary | `ecmascript/compiler/builtins/builtins_array_stub_builder.h` | `88e131561f756db9bd9e57b3078df22ac3c34c6a` | `c9b5a66c12c657533047286ec79406a639fb8232` | needs_re_review / unknown | blob changed | host constructor, helper signatures, species effects |
| C7-DEP-011 | effect_summary | `ecmascript/compiler/call_stub_builder.h` | `f1f44f44679a9a6d648c8dd0182864d4af7c24f7` | `d1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa` | needs_re_review / unknown | blob changed | JSCallArgs arity, call effects, argument ownership |
| C7-DEP-012 | effect_summary | `ecmascript/base/typed_array_helper-inl.h` | `3adadba4324927a18ff715efa99b2aa9cd15bc41` | `172fa188b64ed23d0714c4f4cd0ef66bcbb8e1cf` | needs_re_review / unknown | blob changed | same-type creation and copy fast path |
| C7-DEP-013 | effect_summary | `ecmascript/base/typed_array_helper.cpp` | `17f4b8f50ea126eb646ef011e9b7fa7e461394dc` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` | needs_re_review / unknown | blob changed | slow path, buffer copy, exception handling |
| C7-DEP-014 | effect_summary | `ecmascript/stubs/runtime_stubs.cpp` | `c7ce18a76e25289ee7274354fd85950fa9b17af8` | `14dc06350881b1fa0fdabeeb8465ae9063224d6c` | needs_re_review / unknown | blob changed | CopyTypedArrayBuffer effects, return convention, errors |
| C7-DEP-015 | effect_summary | `ecmascript/js_typed_array.cpp` | `892e376de57c08c768831936503a8e4dac4b39bb` | `098c2a22cae3152af3a59063dda25e145f03bbd7` | needs_re_review / unknown | blob changed | TypedArray identity, detach behavior, length semantics |
| C7-DEP-016 | type_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `757b8d050d306d349822600deacb295c7a54245e` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | needs_re_review / unknown | blob changed | NewTypedArray/NewTypedArraySameType type propagation and exceptions |
| C7-DEP-017 | exception_guard_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | needs_re_review / unknown | blob changed | pending exception, LoadHClass order, caller propagation |
| C7-DEP-018 | exception_guard_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | needs_re_review / unknown | blob changed | duplicate obligation meaning and current semantics |

## Unknown 账本
U-001 expected/current 源码字节缺；U-002 comparison commit/tree/父链缺；U-003 函数/宏/类型/模板/构建语义缺；U-004 NewTypedArray、NewTypedArraySameType、CopyTypedArrayBuffer、HasPendingException、LoadHClass 语义缺；U-005 TU/产品构建闭合缺；U-006 重复义务含意缺；U-007 独立标签/指标缺；U-008 可达性/权限/CIA/产品版本缺。

## 结论
changed blob 不证明语义漂移或安全。model 0.6.2 只保留历史 scope；current snapshot 必须按 replay_plan.md 完成逐项重审，再按 versioning_proposal.md 决定 0.6.3 或 0.7.0。partial、failed、skip、unknown 均不是 safe/miss。