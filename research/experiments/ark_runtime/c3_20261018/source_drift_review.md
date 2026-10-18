# C3 model source dependency drift review

Model `0.6.2` SHA-256 `662c74d79b75b2a111f7ec0eca4cb819a8b1f092ea3e9f7e6cff63621a3d8a1a`; parser Tree-sitter 0.26.0 / tree-sitter-cpp 0.23.4; profile `light-ast`.

Old source revision `a0e30483ab3e4aead67ecfb5c708489915e447f9` tree `82af11ced4297818410ccf61906b703d25b69165`; current `a65a2853ccae13da167d9aa4720ab8b11ec16656` tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.

This inventory binds the exact raw source bytes and diffs. Semantic applicability remains `unknown` until each listed changed hunk is reviewed against macro expansion and the product build profile; no unchanged-impact inference is made. Exact-source binding and the partial gate are unchanged.

| ID | Kind | Path | Old blob / SHA-256 | New blob / SHA-256 | Changed lines | Functions/types/macros/calls | Rule applicability |
|---|---|---|---|---|---:|---|---|
| D01 | effect_summary | `ecmascript/compiler/stub_builder.h` | `b784eb0812c27f11c1bfd8673cda4bf884a6a9cd` / `37757e96a98a20c3598af837d27003912d0f41a6a633e5ec99c04078ef2c8c1d` | `9e2fbd3ede1da91133dcd936018285e597944515` / `a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0` | 1014 | unknown | unknown |
| D02 | effect_summary | `ecmascript/compiler/stub_builder-inl.h` | `8658e6ee729c3b171639772ad3a1ada06442abd0` / `a41ac4bc896fc56c93176b80590620976f0fedd8105bff61f30d9548b0da2520` | `c0521ab7a55cd63850736c2db8a290115965373c` / `e3e840771be228a2c5e6c15576ecdf3f06175622b5840525520345f1d22d76be` | 1914 | unknown | unknown |
| D03 | effect_summary | `ecmascript/compiler/stub_builder.cpp` | `8aae4bfa151e8b8dbd58d03a5cd881f3315151c2` / `6a58a43a3bc1dd018acb57bf54b8c85bda5bbf197eedf7f4fd41dd63941799b8` | `c630a6200215705843d11c0dd86c565709e8c6c4` / `978f507daa99982b115f2db4e63ce629c653f011b4b998ac9e20255ab786b25a` | 5566 | unknown | unknown |
| D04 | effect_summary | `ecmascript/compiler/hcr_circuit_builder.h` | `176dd0a5ee320f814049c2b671119515c746380d` / `c43c0a5de7474f763ca1c37e2276e5129e911324c31993c3043d5441f1758c51` | `e66c414a7a739284b474c234e6f90bae0368cd11` / `380940bddd7790a8c65e5297ed0646ff2dd5301b2a1197fa78b3766ab8653497` | 272 | unknown | unknown |
| D05 | effect_summary | `ecmascript/compiler/mcr_circuit_builder.h` | `631911dec663addd62533d6a6808ffe699a6f884` / `a92932e25ab94f020403bdfd30a5848076bcd444e587461b61d3630805de5ba9` | `297a46c06349c0ed7e881ee4475291a41361f743` / `15d10575db365d6f938b1af4832f1afc65ea7bedb52f5685f4e1c411a500ebe0` | 408 | unknown | unknown |
| D06 | effect_summary | `ecmascript/compiler/lcr_circuit_builder.cpp` | `af4d27bcd46ea0a4a2980a805dd7de77970ffb56` / `838a127ac98866a44f73ff71b574820b7175b8424a0fbb1fda0dfb3cedfd1739` | `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c` / `4575cf4b84cef1046cf617d5328bd1c2c61b5a29f4550b4cbfba5b8ba4d289db` | 129 | unknown | unknown |
| D07 | effect_summary | `ecmascript/compiler/circuit_builder.cpp` | `b4bf452cac6bdeb820b78334be98cb3dc11330cb` / `beb2668526a760d30c2fe8ae181a1cd5544a45d4b6bf888d92f96fb10452077c` | `225f09385632bfc2a6ff20bbdf2bfd8694fcffb6` / `33fac8872f897163ec8261674cad91e8722609e005732a30d675628145974a29` | 614 | unknown | unknown |
| D08 | effect_summary | `ecmascript/compiler/new_object_stub_builder.h` | `f411d72cbca7915e56b9d851beeb57b788e438ac` / `4b2d3586c0df13bdc25a2b029cc6a445c6f6bc1b95349968ca2b221df6779bb4` | `ecdf871b20e884e013ce0f26877ef404e4950cb0` / `d84a72bb1a252fb9ea2b8ff01e702c3a0c952681e211d8f1a850f1880217778b` | 33 | unknown | unknown |
| D09 | effect_summary | `ecmascript/compiler/builtins/builtins_stubs.cpp` | `715c5d65164369bc93a82aa4a6cc1d19b7970143` / `64263f8d75dae7f7f924d9e34fb7a41e2180ae4e6f73e16f1c139e79987e4e76` | `f9c026f6b732cf090aca9df620c4d79bf7597f3b` / `58f8c8b2183735dd41ef96ceb47d9cd7de0e9e13b76b4a4338f48493d9502e82` | 211 | unknown | unknown |
| D10 | effect_summary | `ecmascript/compiler/builtins/builtins_array_stub_builder.h` | `88e131561f756db9bd9e57b3078df22ac3c34c6a` / `c665d4e13208dc00e809331e13a0135b5ae4c63f9c47f4e99e85dc51eb491ee2` | `c9b5a66c12c657533047286ec79406a639fb8232` / `1804426bca64803a2a7b70c63004eb5236718daa075c67d74c68fd5f21ef151c` | 26 | unknown | unknown |
| D11 | effect_summary | `ecmascript/compiler/call_stub_builder.h` | `f1f44f44679a9a6d648c8dd0182864d4af7c24f7` / `3bcb06509efea7261bdaef4c108e31281275c8eff4cbbda24632d710edc98d21` | `d1fb1b9ef28ff8c928a6e8dfdd9aed67e42ef6aa` / `18af6653e22c36dc1fce30d9b7b7eda9d616084add2b1c6d1faa6d89c6c895ae` | 52 | unknown | unknown |
| D12 | effect_summary | `ecmascript/compiler/profiler_operation.h` | `e68a2db48f222945629adb637cd50be8a0f93651` / `ae79f4a797260bcc5f0be6a89737c17321b8e9f0c656c4859416619331e13398` | `e68a2db48f222945629adb637cd50be8a0f93651` / `ae79f4a797260bcc5f0be6a89737c17321b8e9f0c656c4859416619331e13398` | 0 | unknown | unknown |
| D13 | effect_summary | `ecmascript/base/typed_array_helper-inl.h` | `3adadba4324927a18ff715efa99b2aa9cd15bc41` / `ed9bc1df7a3c1a4c30046710a9a28c5d74e2fc0e56e21da1de1d752006635fc4` | `172fa188b64ed23d0714c4f4cd0ef66bcbb8e1cf` / `ecad66a6acb1a19f4eed9b84ce9f86f565348ad0be8c3411643ebace7a8ee559` | 8 | unknown | unknown |
| D14 | effect_summary | `ecmascript/base/typed_array_helper.cpp` | `17f4b8f50ea126eb646ef011e9b7fa7e461394dc` / `0704698674d39389525de7ccca0941138fc0bb4a84d3acdf0f14544a119558a3` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` / `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` | 172 | unknown | unknown |
| D15 | effect_summary | `ecmascript/stubs/runtime_stubs.cpp` | `c7ce18a76e25289ee7274354fd85950fa9b17af8` / `0a11c3832d2d4a0b1adf0879a01e1cbde40a62885f2702dff316985838c135a3` | `14dc06350881b1fa0fdabeeb8465ae9063224d6c` / `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46` | 1629 | unknown | unknown |
| D16 | effect_summary | `ecmascript/js_typed_array.cpp` | `892e376de57c08c768831936503a8e4dac4b39bb` / `e0fa7cb24aae9e3da6ac0bf6ea06972c9419dda83a6647cf3e62d9595997342f` | `098c2a22cae3152af3a59063dda25e145f03bbd7` / `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe` | 205 | unknown | unknown |
| D17 | type_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `757b8d050d306d349822600deacb295c7a54245e` / `3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` / `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | 1218 | unknown | unknown |
| D18 | exception_guard_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` / `c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` / `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | 974 | unknown | unknown |
| D19 | exception_guard_dependency | `ecmascript/compiler/new_object_stub_builder.cpp` | `05dda56de74949f07a241942be6465beaf94b52a` / `c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` / `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | 974 | unknown | unknown |

## Per-item change evidence

### D01 — `ecmascript/compiler/stub_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 65907 → 93596.

Change cues:

Changed diff-line count: 1014; hunk count: 149.
Identifier cues (textual only, not semantic findings): ASM_ASAN_ASSERT, ASM_ASSERT_WITH_LINE, ASSERT, Advance, Apply, Assert, AtomicCmpXchgI32, AtomicLoadAcquireI32, Bind, BothAreString, Branch, BranchOptions::From, BranchOptions::Likely, BranchOptions::NoWeight, BranchOptions::Unlikely, Break, CMCArrayCopyWriteBarrier, CMCArrayCopyWriteBarrierSameArray, CMCIsInYoungSpace, CMCSetValueWithBarrier, CalcHashcodeForDouble, CalcHashcodeForObject, CallCommonStub, CallGetterIfAccessor, CallRuntimeWithCurrentEnv, CallRuntimeWithGlobalEnv, CallSetterHelper, CanDoubleRepresentInt, CanNotConvertNotValidObject, CheckHClassForRep, CheckIsResolvedIndexBinding, CheckPolyHClass, CheckSafePointAtLoopEnd, CheckStackOverflow, CheckSuspendForCMCGC, Circuit::NullGate, ComputeElementCapacityHighGrowth, ComputeElementCapacityWithHint, ComputeTaggedArrayElementKind, ConcurrentApiScopeCanRead, ConcurrentApiScopeCanWrite, ConcurrentApiScopeReadDone, ConcurrentApiScopeWriteDone, Continue, Copyright, EXITENTRY, EmitLoopEnd, EndTraceCall, EndTraceDefineFunc, EndTraceLoadValue, EndTraceStore, EnsureBackEdge, EnsureMergeLabel, FastLoadExternalmodulevar, FastReadBarrier, FastReadBarrierForCompressed, FastToBoolean, FastToBooleanBaseline, FastToBooleanWithProfile, FastToBooleanWithProfileBaseline, FindEntryFromHashTable, FindEntryFromNameDictionary, Finish, From, GateRef, GetAccGetter, GetAccSetter, GetArrayBufferData, GetArrayElementsGuardians, GetArrayIteratorDetector, GetAttr, GetAttributesFromDictionary, GetBindingName, GetBitFieldFromSourceTextModule, GetBoxFromGlobalDictionary, GetBranchOptions, GetCMCRegionRSet, GetCMCRegionType, GetCacheKindFromForInIterator, GetCachedHClassFromForInIterator, GetCachedHclassFromForInIterator, GetCallBackForLazyGetGlobalEnv, GetCallSignature, GetCircuit, GetCjsModuleFunction, GetConstPoolFromFunction, GetCtorPrototype, GetCurrentGlobalEnv, GetCurrentModuleEnv, GetElementsArray, GetEnumCacheAllFromEnumCache, GetEnumCacheFromHClass, GetEnumCacheKind, GetEnumCacheKindFromEnumCache, GetEnumCacheOwnFromEnumCache, GetEnvironment, GetFirstFromTreeString, GetFunctionLexicalEnv, GetGCPhase, GetGCReason, GetGlobalEnv, GetGlobalEnvValue, GetGlobalObject, GetGlue, GetHandlerFromJSProxy, GetHasChanged, GetHash, GetHomeObjectFromFunction, GetHomeObjectFromJSFunction, GetICLength, GetICSlot, GetIdxOfResolvedIndexBinding, GetIdxOfResolvedRecordIndexBinding, GetIhcFromAOTLiteralInfo, GetIsArkSteedCode, GetKey, GetKeyFromDictionary, GetKeyFromLayoutInfo, GetKeyFromLexivalEnv, GetKeysFromForInIterator.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D02 — `ecmascript/compiler/stub_builder-inl.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 140690 → 176499.

Change cues:

Changed diff-line count: 1914; hunk count: 486.
Identifier cues (textual only, not semantic findings): ASM_ASAN_ASSERT, ASM_ASSERT, ASM_ASSERT_WITH_GLUE, ASM_ASSERT_WITH_LINE, ASSERT, And, AsmInterpretedFrame::GetFunctionOffset, AsmInterpretedFrame::GetSize, AtomicCmpXchg, AtomicCmpXchgI32, AtomicLoadAcquire, AtomicLoadAcquireI32, BRANCH, BRANCH_UNLIKELY, Bind, BitAnd, BitOr, BoolNot, BothAreString, CallCommonStub, CallNGCRuntime, CallRuntime, CallRuntimeVarargs, ChangeIntPtrToInt32, ChangeTaggedPointerToInt64, CheckHClassFieldInvalidAccess, Circuit::NullGate, ConcurrentApiScope::CanRead, ConcurrentApiScope::CanWrite, ConcurrentApiScope::ReadDone, ConcurrentApiScope::WriteDone, Copyright, DEFVARIABLE, Done, EXITENTRY, EcmaContext::EcmaData::GetLoadMegaICCacheOffset, EcmaContext::EcmaData::GetMegaHitCountOffset, EcmaContext::EcmaData::GetMegaProbesCountOffset, EcmaContext::EcmaData::GetPropertiesCacheOffset, EcmaContext::EcmaData::GetStoreMegaICCacheOffset, Equal, False, FetchOr, GET_MESSAGE_STRING_ID, GetArrayIteratorDetector, GetAttr, GetBitFieldFromSourceTextModule, GetBoxFromGlobalDictionary, GetBuilder, GetCacheKindFromForInIterator, GetCachedHClassFromForInIterator, GetCachedHclassFromForInIterator, GetControl, GetCurrentGlobalEnv, GetCurrentLabel, GetDepend, GetElementsArray, GetEnumCacheFromHClass, GetEnvironment, GetExtendElementFromConstPool, GetFirstFromTreeString, GetFunctionLexicalEnv, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvValue, GetGlobalObject, GetHomeObjectFromFunction, GetInt32OfTInt, GetInt64OfTInt, GetKey, GetKeyFromLexivalEnv, GetKeysFromForInIterator, GetLengthFromString, GetLengthOfTaggedArray, GetMapIteratorDetector, GetMethodFromFunction, GetModuleFromFunction, GetModuleType, GetNotFoundHasChanged, GetObjectFromForInIterator, GetObjectType, GetParentEnv, GetPropertiesFromLexicalEnv, GetPropertiesFromSendableEnv, GetProtoChangeMarkerFromHClass, GetPrototypeFromHClass, GetRawHashFromString, GetSecondFromTreeString, GetSendableEnvFromModule, GetSendableParentEnv, GetSetIteratorDetector, GetSharedType, GetSortedIndex, GetStageOfHotReload, GetStringWrapperToPrimitiveDetector, GetTypedArraySpeciesProtectDetector, GetUnsharedConstpoolIndex, GetValueFromTaggedArray, HasArkSteedEntry, HasConstructor, IR_IF, InSharedHeap, Int32, Int32Add, Int32And, Int32Equal, Int32GreaterThan, Int32GreaterThanOrEqual, Int32LSL, Int32LSR, Int32LessThan, Int32LessThanOrEqual, Int32Mul, Int32Not, Int32NotEqual, Int32Or, Int32Sub, Int32Xor, Int64, Int64Add.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D03 — `ecmascript/compiler/stub_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 436814 → 542236.

Change cues:

Changed diff-line count: 5566; hunk count: 761.
Identifier cues (textual only, not semantic findings): ASM_ASSERT, ASM_ASSERT_WITH_GLUE, ASSERT, And, AppendPredecessor, BRANCH, BRANCH_LIKELY, BRANCH_NO_WEIGHT, BRANCH_UNLIKELY, BinarySearch, Bind, BitAnd, BitOr, BoolNot, Boolean, BooleanToTaggedBooleanPtr, BothAreString, Branch, CMCArrayCopyWriteBarrier, CMCArrayCopyWriteBarrierSameArray, CMCIsInYoungSpace, CMCSetValueWithBarrier, CMSmarking, CalIteratorKey, CalcHashcodeForInt, CallCommonStub, CallGetterHelper, CallGetterIfAccessor, CallNGCRuntime, CallRuntime, CallRuntimeWithGlobalEnv, CallSetterHelper, CanDoubleRepresentInt, CanNotConvertNotValidObject, CastInt64ToFloat64, ChangeFloat64ToInt32, ChangeInt32ToFloat64, ChangeIntPtrToInt32, ChangeTaggedPointerToInt64, CheckHClassForRep, CheckIsResolvedIndexBinding, CheckSafePointAtLoopEnd, CheckSuspendForCMCGC, Circuit::NullGate, ConvertTemporaryTaggedObjectToTaggedValue, CopyArray, Copyright, DEFVARIABLE, Done, DoubleEqual, DoubleIsNAN, EmitLoopEnd, EnsureBackEdge, EnsureMergeLabel, Equal, Exception, False, FastGetPropertyByName, FastReadBarrier, FastReadBarrierForCompressed, FastStringEqual, FastToBoolean, FatalPrint, FinalizeOperatorResults, FindElementWithCache, FindEntry, FindEntryFromNameDictionary, FlattenString, GET_MESSAGE_STRING_ID, GateAccessor, GetArrayBufferData, GetArrayElementsGuardians, GetArrayIteratorDetector, GetAttr, GetAttributes, GetBaselineJitHotnessThreshold, GetBindingName, GetBitFieldFromHClass, GetBoxFromGlobalDictionary, GetBranchOptions, GetBuilder, GetCMCRegionRSet, GetCMCRegionType, GetCacheKindFromForInIterator, GetCachedHClassFromForInIterator, GetCachedHclassFromForInIterator, GetCallSignature, GetCircuit, GetCjsModuleFunction, GetConstPoolFromFunction, GetConstantPool, GetConstantValue, GetControl, GetCtorPrototype, GetCurrentGlobalEnv, GetCurrentLabel, GetCurrentModuleEnv, GetDoubleOfTDouble, GetElementsArray, GetElementsKindFromHClass, GetEnumCacheAllFromEnumCache, GetEnumCacheFromHClass, GetEnumCacheKind, GetEnumCacheKindFromEnumCache, GetEnumCacheOwnFromEnumCache, GetEnvironment, GetExtraLengthOfTaggedArray, GetGCPhase, GetGCReason, GetGateType, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvValue, GetGlue, GetHasChanged, GetHash, GetHolder, GetICSlot, GetIdxOfResolvedIndexBinding, GetIdxOfResolvedRecordIndexBinding.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D04 — `ecmascript/compiler/hcr_circuit_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 16622 → 21419.

Change cues:

Changed diff-line count: 272; hunk count: 82.
Identifier cues (textual only, not semantic findings): ChangeTaggedPointerToInt64, CheckHClassAddrInvalid, CheckHClassFieldInvalidAccess, CircuitBuilder::GetBuiltinsId, CircuitBuilder::GetEnumCacheAllFromEnumCache, CircuitBuilder::GetEnumCacheKindFromEnumCache, CircuitBuilder::GetEnumCacheOwnFromEnumCache, CircuitBuilder::GetMethodId, CircuitBuilder::GetProtoChainInfoEnumCacheFromEnumCache, CircuitBuilder::HasConstructor, CircuitBuilder::IsAOTLiteralInfo, CircuitBuilder::IsBase, CircuitBuilder::IsCachedExternalString, CircuitBuilder::IsCallable, CircuitBuilder::IsClassConstructor, CircuitBuilder::IsClassPrototype, CircuitBuilder::IsConstantString, CircuitBuilder::IsConstructor, CircuitBuilder::IsDerived, CircuitBuilder::IsDictionaryMode, CircuitBuilder::IsExtensible, CircuitBuilder::IsJSFunction, CircuitBuilder::IsJSHClass, CircuitBuilder::IsJSObject, CircuitBuilder::IsJsProxy, CircuitBuilder::IsJsType, CircuitBuilder::IsLineString, CircuitBuilder::IsSlicedString, CircuitBuilder::IsStableElements, CircuitBuilder::IsTreeString, CircuitBuilder::LoadHClass, CircuitBuilder::LoadHClassByConstOffset, CircuitBuilder::LoadHclassImpl, CircuitBuilder::LoadProtoChangeMarker, CircuitBuilder::LoadPrototype, CircuitBuilder::LoadPrototypeHClass, CircuitBuilder::LoadPrototypeOfPrototypeHClass, CircuitBuilder::StoreHClass, CircuitBuilder::StoreHClassWithoutBarrier, CircuitBuilder::TransitionHClass, CircuitBuilder::TransitionHClassByConstOffset, GateType::NJSValue, GetCircuit, GetCurrentLabel, GetDepend, GetGateType, GetMachineType, GetMethodFromFunction, GetObjectType, Int32, Int32And, Int32Equal, Int32LSR, Int64, Int64And, Int64LSR, Int64Or, IntPtr, IsConstant, IsStableElements, IsStableElementsIntrinsic, LOG_ECMA, Load, LoadConstOffset, LoadHClass, LoadHClassByConstOffset, LoadHClassOpcode, LoadPrototype, LoadStoreAccessor::ToValue, LoadWithoutBarrier, MemoryAttribute::NeedBarrier, MemoryAttribute::NoBarrier, NewGate, PtrAdd, PtrMul, SetDepend, Store, StoreHClass, StoreHClassConstOffset, SupportIntrinsic, TaggedPointerToInt64, TruncInt64ToInt32, UNREACHABLE, VariableType::INT32, VariableType::INT64, VariableType::JS_ANY, VariableType::JS_POINTER.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D05 — `ecmascript/compiler/mcr_circuit_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 26077 → 36875.

Change cues:

Changed diff-line count: 408; hunk count: 97.
Identifier cues (textual only, not semantic findings): ASSERT_ASM, And, AppendFrameArgs, AppendFrameState, BRANCH, Bind, BitAnd, BoolNot, CallNewBuiltin, ChangeTaggedPointerToInt64, CheckTaggedObjectIsString, CircuitBuilder::BothAreString, CircuitBuilder::CallNewBuiltin, CircuitBuilder::ConvertTemporaryTaggedObjectToTaggedValue, CircuitBuilder::GetArrayElementsGuardians, CircuitBuilder::GetArrayIteratorDetector, CircuitBuilder::GetFirstFromTreeString, CircuitBuilder::GetMapIteratorDetector, CircuitBuilder::GetSecondFromTreeString, CircuitBuilder::GetSetIteratorDetector, CircuitBuilder::GetStringIteratorDetector, CircuitBuilder::GetStringWrapperToPrimitiveDetector, CircuitBuilder::GetTypedArrayIteratorDetector, CircuitBuilder::GetTypedArraySpeciesProtectDetector, CircuitBuilder::GetValueFromTaggedArray, CircuitBuilder::IsSpecialSlicedString, CircuitBuilder::LoadFromTaggedArray, CircuitBuilder::StoreToTaggedArray, CircuitBuilder::TaggedIsArrayIterator, CircuitBuilder::TaggedIsAsyncGeneratorObject, CircuitBuilder::TaggedIsBigInt, CircuitBuilder::TaggedIsBoundFunction, CircuitBuilder::TaggedIsEnumCache, CircuitBuilder::TaggedIsGeneratorObject, CircuitBuilder::TaggedIsHeapObject, CircuitBuilder::TaggedIsJSArray, CircuitBuilder::TaggedIsJSFunction, CircuitBuilder::TaggedIsJSGlobalObject, CircuitBuilder::TaggedIsJSProxy, CircuitBuilder::TaggedIsLineUtf8String, CircuitBuilder::TaggedIsNativePointer, CircuitBuilder::TaggedIsNumeric, CircuitBuilder::TaggedIsPropertyBox, CircuitBuilder::TaggedIsProtoChangeMarker, CircuitBuilder::TaggedIsPrototypeHandler, CircuitBuilder::TaggedIsSharedObj, CircuitBuilder::TaggedIsStoreAOTHandler, CircuitBuilder::TaggedIsString, CircuitBuilder::TaggedIsStringIterator, CircuitBuilder::TaggedIsStringOrSymbol, CircuitBuilder::TaggedIsSymbol, CircuitBuilder::TaggedIsTransWithProtoHandler, CircuitBuilder::TaggedIsTransitionHandler, CircuitBuilder::TaggedObjectIsByteArray, CircuitBuilder::TaggedObjectIsDataView, CircuitBuilder::TaggedObjectIsEcmaObject, CircuitBuilder::TaggedObjectIsJSArray, CircuitBuilder::TaggedObjectIsJSDate, CircuitBuilder::TaggedObjectIsJSMap, CircuitBuilder::TaggedObjectIsJSSet, CircuitBuilder::TaggedObjectIsMap, CircuitBuilder::TaggedObjectIsShared, CircuitBuilder::TaggedObjectIsString, CircuitBuilder::TaggedObjectIsTypedArray, CircuitBuilder::TemporaryTaggedIsHeapObject, CircuitBuilder::TemporaryTaggedIsInt, CircuitBuilder::TemporaryTaggedIsNullPtr, CircuitBuilder::TreeStringIsFlat, CircuitBuilder::WipeHighBitOfTemporaryTagged, Copyright, DEFVALUE, Done, Equal, False, GET_MESSAGE_STRING_ID, GateType::AnyType, GateType::Empty, GateType::NJSValue, GetArrayElementsGuardians, GetCircuit, GetControl, GetCurrentLabel, GetDepend, GetGlobalEnvCache, GetObjectType, GetSecondFromTreeString, Int32, Int32And, Int32Equal, Int32GreaterThanOrEqual, Int32LSR, Int32LessThanOrEqual, Int64, Int64And, IntPtr, IsConstant, IsConstantPool, IsJsType, IsLineString, IsUtf8String, JSTaggedValue::TaggedTypeSize, JSThread::GlueData::GetArrayElementsGuardiansOffset, Jump, LOG_ECMA, Load, LoadConstOffset, LoadHClass, LoadWithoutBarrier, LogicAndBuilder, LogicOrBuilder, NewGate, NullPtrConstant, Or, PtrAdd, PtrMul, SetControl, SetDepend, SubCfgEntry, SubCfgExit, SupportIntrinsic.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D06 — `ecmascript/compiler/lcr_circuit_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 12359 → 17240.

Change cues:

Changed diff-line count: 129; hunk count: 11.
Identifier cues (textual only, not semantic findings): ASSERT, AtomicCmpXchg, AtomicLoadAcquire, BoolNot, Boolean, CallNGCRuntime, Circuit::NullGate, CircuitBuilder::AtomicCmpXchg, CircuitBuilder::AtomicLoadAcquire, CircuitBuilder::DoubleTrunc, CircuitBuilder::FetchOr, CircuitBuilder::Load, CircuitBuilder::LoadFromAddressWithoutBarrier, CircuitBuilder::LoadFromCompressedTaggedValue, CircuitBuilder::LoadWithoutBarrier, CircuitBuilder::NeedSkipReadBarrier, CircuitBuilder::NotSwitchToStwStub, CircuitBuilder::ReadReserveRegister, CircuitBuilder::StoreHClass, FetchOr, GateType::NJSValue, GetCircuit, GetConstantValue, GetCurrentLabel, GetDepend, GetGateType, GetGlueFromArgList, GetMachineType, Int64, Int64And, Int64Equal, IntPtr, IsConstant, JSThread::GlueData::GetHasSwitchedToStwStubOffset, JSThread::GlueData::GetSharedGCStateBitFieldOffset, LOG_ECMA, Load, LoadFromCompressed, LoadStoreAccessor::ToValue, LoadWithoutBarrier, MemoryAttribute::NeedBarrier, NewGate, PtrAdd, RTSTUB_ID, ReadReserveRegister, ReservedReg, SetDepend, Store, VariableType::BOOL, VariableType::INT64, VariableType::JS_ANY, VariableType::JS_POINTER, ordering.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D07 — `ecmascript/compiler/circuit_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 59182 → 73531.

Change cues:

Changed diff-line count: 614; hunk count: 155.
Identifier cues (textual only, not semantic findings): ASSERT_ASM, And, BRANCH, BRANCH_LIKELY, BRANCH_UNLIKELY, Bind, BitAnd, BitOr, BoolNot, CallNGCRuntime, CallRuntime, CheckHClassFieldInvalidAccess, Circuit::NullGate, CircuitBuilder::AppendFrameArgs, CircuitBuilder::AppendFrameState, CircuitBuilder::Assert, CircuitBuilder::CheckHClassAddrInvalid, CircuitBuilder::CheckHClassFieldInvalidAccess, CircuitBuilder::CheckJSType, CircuitBuilder::FastToBoolean, CircuitBuilder::FloatArrayElementConvert, CircuitBuilder::GetCacheKindFromForInIterator, CircuitBuilder::GetCachedHClassFromForInIterator, CircuitBuilder::GetCachedHclassFromForInIterator, CircuitBuilder::GetConstPoolFromFunction, CircuitBuilder::GetElementsArray, CircuitBuilder::GetEnumCacheFromHClass, CircuitBuilder::GetExtendElementFromConstPool, CircuitBuilder::GetFromCompressedTaggedValueFromConstPoolUnsafe, CircuitBuilder::GetFunctionLexicalEnv, CircuitBuilder::GetGlobalEnv, CircuitBuilder::GetGlobalEnvValue, CircuitBuilder::GetGlobalObject, CircuitBuilder::GetHomeObjectFromFunction, CircuitBuilder::GetICSlot, CircuitBuilder::GetKeyFromLexivalEnv, CircuitBuilder::GetKeysFromForInIterator, CircuitBuilder::GetLengthOfConstPoolCacheElement, CircuitBuilder::GetMethodFromFunction, CircuitBuilder::GetModuleFromFunction, CircuitBuilder::GetNotFoundHasChanged, CircuitBuilder::GetNumOfConstPoolCacheElement, CircuitBuilder::GetObjectFromConstPoolCacheUnsafe, CircuitBuilder::GetObjectFromForInIterator, CircuitBuilder::GetParentEnv, CircuitBuilder::GetProfileTypeInfo, CircuitBuilder::GetPropertiesFromLexicalEnv, CircuitBuilder::GetPropertiesFromSendableEnv, CircuitBuilder::GetProtoChangeMarkerFromHClass, CircuitBuilder::GetPrototypeFromHClass, CircuitBuilder::GetSendableEnvFromModule, CircuitBuilder::GetSendableParentEnv, CircuitBuilder::GetSharedConstpoolFromMethod, CircuitBuilder::GetStageOfHotReload, CircuitBuilder::GetUnsharedConstpool, CircuitBuilder::GetUnsharedConstpoolIndex, CircuitBuilder::HasArkSteedEntry, CircuitBuilder::HasPendingException, CircuitBuilder::HeapConstant, CircuitBuilder::IndexOfConstPoolCacheElementValid, CircuitBuilder::IsAccessorInternal, CircuitBuilder::IsCompositeHClass, CircuitBuilder::IsConstantPool, CircuitBuilder::IsEcmaObject, CircuitBuilder::IsJsCOWArray, CircuitBuilder::IsNotLdEndExecPatchMain, CircuitBuilder::IsSharedTypedArray, CircuitBuilder::IsStableArrayLengthWriteable, CircuitBuilder::IsTaggedArray, CircuitBuilder::IsTypedArray, CircuitBuilder::LoadObjectFromConstPool, CircuitBuilder::NewJSPrimitiveRef, CircuitBuilder::OffsetOfConstPoolValid, CircuitBuilder::SetCacheKindForInIterator, CircuitBuilder::SetCachedHClassOfForInIterator, CircuitBuilder::SetCachedHclassOfForInIterator, CircuitBuilder::SetICSlot, CircuitBuilder::TemporaryHoleConstant, CircuitBuilder::ToObject, CompressedJSTaggedValue::CompressedTaggedTypeSize, ConvertTemporaryTaggedObjectToTaggedValue, DEFVALUE, Deoptimizier::DisplayItems, Done, Double, DoubleIsNAN, Equal, ExtFloat32ToDouble, GET_MESSAGE_STRING_ID, GateType::NJSValue, GateType::TaggedValue, GetArgumentAccessor, GetCircuit, GetConstantGate, GetCurrentLabel, GetDepend, GetElementsArray, GetExtendElementFromConstPool, GetFrameArgs, GetFrameArgsIn, GetFrameState, GetFromCompressedTaggedValueFromConstPoolUnsafe, GetGlobalEnvValue, GetHeapConstantGate, GetICSlot, GetInt64OfTInt, GetLengthOfConstPoolCacheElement, GetLengthOfTaggedArray, GetMethodFromFunction, GetModuleFromFunction, GetNumOfConstPoolCacheElement, GetObjectFromConstPoolCacheUnsafe, GetObjectType, GetParentEnv, GetPropertiesFromLexicalEnv, GetPrototypeFromHClass, GetRawDataUnsafe, GetSharedConstpoolFromMethod, GetStageOfHotReload, GetUnsharedConstpool.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D08 — `ecmascript/compiler/new_object_stub_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 10540 → 12540.

Change cues:

Changed diff-line count: 33; hunk count: 17.
Identifier cues (textual only, not semantic findings): AllocateInSOldPrologueImpl, AllocateInSOldPrologueImplForCMCGC, AllocateInYoungPrologueImpl, AllocateInYoungPrologueImplForCMCGC, AllocateInYoungPrologueImplForCMSGC, CreateJSSharedMapIterator, DefineFuncForJit, DefineMethod, InitializeObject, LoadHClassFromMethodForDefineMethod, NewEnumCache, NewFloat32ArrayObj, NewJSApiFunctionByHClass, NewJSForinIterator, NewJSFunctionForDefineMethod, NewJSFunctionForJit, NewJSObject, NewObjectStubBuilder, NewSTaggedArray, NewTaggedArrayChecked, StubBuilder.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D09 — `ecmascript/compiler/builtins/builtins_stubs.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 33980 → 35101.

Change cues:

Changed diff-line count: 211; hunk count: 46.
Identifier cues (textual only, not semantic findings): ASM_ASSERT, And, BRANCH, BRANCH_UNLIKELY, BUILTINS_STUB_ID, Bind, BitOr, BuiltinsStubBuilder::CallSlowPath, BuiltinsStubBuilder::GetArgFromArgv, BuiltinsStubBuilder::GetGlobalEnvFromFunction, BuiltinsStubCSigns::GetName, CallBuiltinRuntime, CallBuiltinRuntimeWithNewTarget, CallNGCRuntime, CallSlowPath, D, DECLARE_BUILTINS, DECLARE_BUILTINS_DATAVIEW_STUB_BUILDER, DEFVARIABLE, Done, Double, DoubleToTaggedDoublePtr, FastToBoolean, GET_MESSAGE_STRING_ID, GenSharedArrayConstructor, GenSharedMapSetConstructor, GetArgFromArgv, GetArgv, GetEnvironment, GetFunctionLexicalEnv, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvFromFunction, IntPtr, IsGlobalEnv, IsJSFunction, IsJSHClass, JSTaggedValue::TaggedTypeSize, Jump, Load, LogicAndBuilder, NEXT_AOT_AND_BUILTINS_STUB_LIST_WITH_METHOD, NewJSObject, PtrMul, RTSTUB_ID, Return, SetGlueGlobalEnv, Store, SubCfgEntry, SubCfgExit, TaggedIsHeapObject, TaggedIsUndefined, Undefined, V, VariableType::INT64, VariableType::JS_ANY, VariableType::JS_NOT_POINTER, VariableType::JS_POINTER, builder, builtinsTypedArrayStubBuilder, exit, hashTableBuilder, isUndefined, slowPath, slowPath1, subentry.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D10 — `ecmascript/compiler/builtins/builtins_array_stub_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 11828 → 12190.

Change cues:

Changed diff-line count: 26; hunk count: 10.
Identifier cues (textual only, not semantic findings): BuiltinsArrayStubBuilder, BuiltinsStubBuilder, CalEleKindForNewArrayNoHole, FlatInnerArray, IndexOfElements.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D11 — `ecmascript/compiler/call_stub_builder.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 8168 → 9597.

Change cues:

Changed diff-line count: 52; hunk count: 12.
Identifier cues (textual only, not semantic findings): CallArkSteedConstructorBridge, CallNGCRuntimeWithCallTimer, CallStubDispatch, Circuit::NullGate, Copyright, FastCallSelector, JSCallArkSteed, JSCallAsmInterpreter, JSCallNativeInner, LowerCallNGCRuntime, LowerFastSuperCall, PrepareArgsForArkSteedPushArgv, PrepareArgsForArkSteedWithArgV, ProfileOperation.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D12 — `ecmascript/compiler/profiler_operation.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 4176 → 4176.

Change cues:

Changed diff-line count: 0; hunk count: 0.
Identifier cues (textual only, not semantic findings): none.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D13 — `ecmascript/base/typed_array_helper-inl.h`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 22732 → 22772.

Change cues:

Changed diff-line count: 8; hunk count: 3.
Identifier cues (textual only, not semantic findings): GetClass, GetProtoChangeMarker, GetTaggedObject, TypedArrayHelper::IsAccessorHasChanged.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D14 — `ecmascript/base/typed_array_helper.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 67342 → 65211.

Change cues:

Changed diff-line count: 172; hunk count: 61.
Identifier cues (textual only, not semantic findings): ASSERT, BuiltinsArrayBuffer::IsDetachedBuffer, BuiltinsSendableArrayBuffer::IsDetachedBuffer, Cast, ContentTypeIsBigInt, ElementAccessor::GetElementsLength, GetArrayProtoValuesFunction, GetCallArg, GetConstructorNameFromType, GetContentType, GetHandledIteratorSymbol, GetIteratorSymbol, GetJSHClass, GetPrototype, GetSharedConstructorNameFromType, GetTaggedValue, GetTypedArrayName, GetTypedArrayProtoValuesFunction, GetTypedArraySpeciesProtectDetector, GetViewedArrayBufferOrByteArray, GlobalConstants, IsSendableArrayBuffer, JSSharedTypedArray::Cast, JSTaggedValue, JSTaggedValue::SameValue, JSTaggedValue::ToString, JSTaggedValue::ToUint32, JSTypedArray::Cast, JSTypedArray::GetTypeFromName, PropertyDetector::IsTypedArraySpeciesProtectDetectorValid, SetContentType, SetTypedArrayName, SynchronizedSetClass, SynchronizedTransitionClass, TaggedObject::Cast, ToStdString, TypedArrayHelper::AllocateSharedTypedArray, TypedArrayHelper::AllocateTypedArray, TypedArrayHelper::FastCopyElementFromArray, TypedArrayHelper::FastCopyElementFromArrayForCtor, TypedArrayHelper::IsAccessorHasChanged, proto, singleNumber, srcName.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D15 — `ecmascript/stubs/runtime_stubs.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 199944 → 243885.

Change cues:

Changed diff-line count: 1629; hunk count: 209.
Identifier cues (textual only, not semantic findings): ASSERT, AccessorData::Cast, AddDepth, AddType, AllocObjectWithSpaceType, ArrayHelper::FlatMapFromIndexAfterCall, Barriers::CMCWriteBarrier, Barriers::CheckObjectForCMS, Barriers::CheckValueForCMS, Barriers::ReadBarrierForCompressedForObject, Barriers::ReadBarrierForObject, Barriers::Update, Barriers::UpdateShared, Barriers::UpdateSlot, BigInt::Equal, BigInt::SameValueZero, CallInternalSet, Cast, CheckAndThrowModuleError, CheckElementsNumber, CollectGarbage, ComputeHashcode, ConstructAsmInterpretFrame, ConvertToString, Copyright, CountBranch, CreateUnsharedConstpool, DEF_RUNTIME_STUBS, DFXHiSysEvent::SendRuntimeIncompatibleEvent, Deoptimizier::GetInlineDepth, Deoptimizier::PrepareForExceptionLazyDeopt, Dump, DumpHeapObjAddress, DumpInfoForLdObjByValue, DumpInfoForMoreLdInfo, ECMAObject::Cast, ECMA_BYTRACE_FINISH_TRACE, ECMA_BYTRACE_NAME, ECMA_BYTRACE_START_TRACE, EcmaInterpreter::NewRuntimeCallInfo, EcmaString::Cast, EcmaStringAccessor, EcmaStringAccessor::StringsAreEqualDiffUtfEncoding, Empty, FatalPrint, FindCatchBlock, FindOrCreateUnsharedConstpool, FindPatchModule, FindProtoTransitions, FindTraceBundleName, FindUnsharedConstpool, GET_ASM_FRAME, Get, GetAbcFileNameString, GetArg, GetArgv, GetBoundArguments, GetBoundTarget, GetBundleName, GetByteOffset, GetCallTarget, GetClass, GetCodeEntry, GetCodeSize, GetCurrentEcmaContext, GetCurrentFrame, GetCurrentInterpretedFrame, GetCurrentStackPosition, GetDataUtf16, GetDataUtf8, GetEcmaModuleFilenameString, GetEcmaModuleRecordNameString, GetEcmaStringTable, GetEcmaVM, GetElements, GetException, GetFactory, GetGlobalEnv, GetGlueAddr, GetHandlerInfo, GetHeap, GetHmsModuleList, GetICSlot, GetIcSlot, GetIcuCollator, GetInt, GetJSError, GetJSOptions, GetKey, GetLastLeaveFrame, GetLayout, GetLeft, GetLength, GetLexicalEnv, GetMachineCode, GetMethod, GetMethodId, GetMethodName, GetModuleManager, GetModuleRecordName, GetMutator, GetNotificationManager, GetObjectType, GetOffset, GetOptCodeProfiler, GetOrInternString, GetParent, GetProfileTypeInfo, GetProperties, GetProto, GetRawData, GetRecordNameStr, GetRight, GetSModule, GetSlotSize, GetSlotSpace, GetStackLimit, GetStartIndex, GetStringToListResultCache, GetSymbolFunction.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D16 — `ecmascript/js_typed_array.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 43951 → 41859.

Change cues:

Changed diff-line count: 205; hunk count: 43.
Identifier cues (textual only, not semantic findings): ASSERT, BuiltinsArrayBuffer::IsDetachedBuffer, BuiltinsSendableArrayBuffer::IsDetachedBuffer, ByteArray::Cast, CanonicalNumericIndexString, Cast, ContentTypeIsBigInt, Get, GetArrayBufferData, GetArrayLength, GetContentType, GetData, GetHandledBigInt64ArrayString, GetHandledFloat32ArrayString, GetHandledFloat64ArrayString, GetHandledInt16ArrayString, GetHandledInt32ArrayString, GetHandledInt8ArrayString, GetHandledSharedBigInt64ArrayString, GetHandledSharedFloat32ArrayString, GetHandledSharedFloat64ArrayString, GetHandledSharedInt16ArrayString, GetHandledSharedInt32ArrayString, GetHandledSharedInt8ArrayString, GetHandledSharedUint16ArrayString, GetHandledSharedUint32ArrayString, GetHandledSharedUint8ArrayString, GetHandledSharedUint8ClampedArrayString, GetHandledUint16ArrayString, GetHandledUint32ArrayString, GetHandledUint8ArrayString, GetHandledUint8ClampedArrayString, GetJSHClass, GetTaggedObject, GetTaggedValue, GetTypedArrayName, GetViewedArrayBufferOrByteArray, GlobalConstants, IntegerIndexedElementGet, IntegerIndexedElementGetForNum, IsArrayBufferDetached, IsDetachedBuffer, IsECMAObject, IsNumber, IsSendableArrayBuffer, IsSharedTypedArray, IsString, IsTypedArray, IsUndefined, IsValidIntegerIndex, JSHClass::NotifyHclassChanged, JSTaggedNumber::SameValue, JSTaggedValue::CanonicalNumericIndexString, JSTaggedValue::Exception, JSTaggedValue::SameValue, JSTaggedValue::StringToDouble, JSTaggedValue::Undefined, JSTypedArray::GetTypeFromName, JSTypedArray::IntegerIndexedElementGet, JSTypedArray::IsArrayBufferDetached, JSTypedArray::IsValidIntegerIndex, OperationResult, PropertyMetaData, RETURN_VALUE_IF_ABRUPT_COMPLETION, SynchronizedSetClass, SynchronizedTransitionClass, TaggedObject::Cast, UNLIKELY, constexpr, oldHClass, typeName, typedarrayObj.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D17 — `ecmascript/compiler/new_object_stub_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 126036 → 151323.

Change cues:

Changed diff-line count: 1218; hunk count: 227.
Identifier cues (textual only, not semantic findings): ASM_ASSERT, ASSERT, AlignUp, AllocateInSOld, AllocateInSOldPrologueImpl, AllocateInSOldPrologueImplForCMCGC, AllocateInYoung, AllocateInYoungPrologueImpl, AllocateInYoungPrologueImplForCMCGC, AllocateInYoungPrologueImplForCMSGC, BRANCH, BRANCH_LIKELY, BRANCH_UNLIKELY, Bind, BoolNot, Boolean, CallNGCRuntime, CallRuntime, Copyright, CreateWeakRef, DEFVARIABLE, DefineFuncForJit, Equal, Exception, False, GET_MESSAGE_STRING_ID, GetBuilder, GetConstPoolFromFunction, GetCtorPrototype, GetCurrentGlobalEnv, GetElementsArray, GetElementsKindHClass, GetEnumCacheFromHClass, GetEnumCacheKindFromEnumCache, GetEnvironment, GetFlatString, GetFuncKind, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvValue, GetHomeObjectFromFunction, GetICSlot, GetLayoutFromHClass, GetLengthFromFunction, GetMethodFromFunction, GetModuleFromFunction, GetObjectSizeFromHClass, GetObjectType, GetProfileTypeInfo, GetPropAttrFromLayoutInfo, GetPropertiesArray, GetPropertyInlinedProps, GetProtoChangeMarkerFromHClass, GetProtoOrHClass, GetPrototypeFromHClass, GetSendableEnvFromModule, GetStartIndex, GetTypedArraySpeciesProtectDetector, GetValueFromTaggedArray, HasConstructor, HasFunctionPrototype, HasPendingException, HeapAlloc, Hole, InitStringLengthAndFlags, InitializeFunctionWithMethod, InitializeJSFunction, InitializeObject, Int32, Int32Add, Int32And, Int32Equal, Int32LessThan, Int32Mul, Int64ToTaggedPtr, Int8, IntPtr, IntPtrAnd, IntPtrDiv, IntPtrEqual, IntPtrGreaterThan, IntPtrLessThan, IntPtrNot, IntPtrSize, IntToTaggedInt, Is32Bit, IsBase, IsCallable, IsClassConstructor, IsConstructor, IsDictionaryModeByHClass, IsEcmaObject, IsFastTypeArray, IsFastTypedArray, IsJSApiFunction, IsJSFunction, IsJSHClass, IsJSShared, IsMarkerCellValid, IsMutantTaggedArray, IsNativePointer, IsSendableFunction, IsTypedArray, JSFunction::GetInlinedPropertyOffset, JSTaggedValue::TaggedTypeSize, JSThread::GlueData::GetAllocBufferOffset, JSThread::GlueData::GetGlobalConstOffset, JSThread::GlueData::GetGlueGlobalEnvOffset, JSThread::GlueData::GetIsEnableCMCGCOffset, JSThread::GlueData::GetIsStartHeapSamplingOffset, JSThread::GlueData::GetSlotSpaceAllocatorsAddressOffset, Jump, Label, Load, LoadHCIndexFromConstPool, LoadHCIndexInfosFromConstPool, LoadHClass, LoadHClassFromMethodForDefineMethod, LoadPfHeaderFromConstPool, LoadPrimitive.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D18 — `ecmascript/compiler/new_object_stub_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 129325 → 151323.

Change cues:

Changed diff-line count: 974; hunk count: 159.
Identifier cues (textual only, not semantic findings): ASM_ASSERT, ASSERT, AlignUp, AllocateInSOld, AllocateInSOldPrologueImpl, AllocateInSOldPrologueImplForCMCGC, AllocateInYoung, AllocateInYoungPrologueImpl, AllocateInYoungPrologueImplForCMCGC, AllocateInYoungPrologueImplForCMSGC, BRANCH, BRANCH_LIKELY, BRANCH_UNLIKELY, Bind, BoolNot, Boolean, CallNGCRuntime, CallRuntime, Copyright, CreateWeakRef, DEFVARIABLE, DefineFuncForJit, Equal, Exception, False, GET_MESSAGE_STRING_ID, GetBuilder, GetCurrentGlobalEnv, GetElementsKindHClass, GetEnumCacheFromHClass, GetEnumCacheKindFromEnumCache, GetEnvironment, GetFlatString, GetFuncKind, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvValue, GetHomeObjectFromFunction, GetICSlot, GetLengthFromFunction, GetModuleFromFunction, GetObjectSizeFromHClass, GetObjectType, GetProfileTypeInfo, GetPropertyInlinedProps, GetPrototypeFromHClass, GetStartIndex, GetTypedArraySpeciesProtectDetector, GetValueFromTaggedArray, HasPendingException, Hole, InitStringLengthAndFlags, InitializeFunctionWithMethod, InitializeJSFunction, InitializeObject, Int32, Int32Add, Int32And, Int32Equal, Int32LessThan, Int32Mul, Int64ToTaggedPtr, Int8, IntPtr, IntPtrAnd, IntPtrDiv, IntPtrEqual, IntPtrGreaterThan, IntPtrLessThan, IntPtrNot, IntPtrSize, IntToTaggedInt, Is32Bit, IsClassConstructor, IsDictionaryModeByHClass, IsEcmaObject, IsFastTypeArray, IsFastTypedArray, IsJSApiFunction, IsTypedArray, JSFunction::GetInlinedPropertyOffset, JSTaggedValue::TaggedTypeSize, JSThread::GlueData::GetAllocBufferOffset, JSThread::GlueData::GetGlobalConstOffset, JSThread::GlueData::GetGlueGlobalEnvOffset, JSThread::GlueData::GetIsEnableCMCGCOffset, JSThread::GlueData::GetIsStartHeapSamplingOffset, JSThread::GlueData::GetSlotSpaceAllocatorsAddressOffset, Jump, Label, Load, LoadHClass, LoadHClassFromMethodForDefineMethod, LoadPrimitive, MemoryAttribute::NoBarrier, MemoryAttribute::UnknownBarrier, NewFloat32ArrayObj, NewJSApiFunctionByHClass, NewJSForinIterator, NewJSFunctionByHClass, NewJSFunctionForDefineMethod, NewJSObject, NewObjectStubBuilder::AllocateInSOldPrologueImpl, NewObjectStubBuilder::AllocateInSOldPrologueImplForCMCGC, NewObjectStubBuilder::AllocateInYoungPrologue, NewObjectStubBuilder::AllocateInYoungPrologueImpl, NewObjectStubBuilder::AllocateInYoungPrologueImplForCMCGC, NewObjectStubBuilder::AllocateInYoungPrologueImplForCMSGC, NewObjectStubBuilder::CreateJSSharedMapIterator, NewObjectStubBuilder::DefineFuncForJit, NewObjectStubBuilder::DefineMethod, NewObjectStubBuilder::LoadHClassFromMethodForDefineMethod, NewObjectStubBuilder::NewFloat32ArrayObj, NewObjectStubBuilder::NewJSApiFunctionByHClass, NewObjectStubBuilder::NewJSFunctionForDefineMethod, NewObjectStubBuilder::NewJSFunctionForJit, NewObjectStubBuilder::NewJSObject, NewObjectStubBuilder::NewSTaggedArray, NewObjectStubBuilder::NewTaggedArrayChecked, NewProfileTypeInfoCell.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

### D19 — `ecmascript/compiler/new_object_stub_builder.cpp`

Model expected/current blobs match bound revisions: `true`. Raw byte lengths: 129325 → 151323.

Change cues:

Changed diff-line count: 974; hunk count: 159.
Identifier cues (textual only, not semantic findings): ASM_ASSERT, ASSERT, AlignUp, AllocateInSOld, AllocateInSOldPrologueImpl, AllocateInSOldPrologueImplForCMCGC, AllocateInYoung, AllocateInYoungPrologueImpl, AllocateInYoungPrologueImplForCMCGC, AllocateInYoungPrologueImplForCMSGC, BRANCH, BRANCH_LIKELY, BRANCH_UNLIKELY, Bind, BoolNot, Boolean, CallNGCRuntime, CallRuntime, Copyright, CreateWeakRef, DEFVARIABLE, DefineFuncForJit, Equal, Exception, False, GET_MESSAGE_STRING_ID, GetBuilder, GetCurrentGlobalEnv, GetElementsKindHClass, GetEnumCacheFromHClass, GetEnumCacheKindFromEnumCache, GetEnvironment, GetFlatString, GetFuncKind, GetGlobalConstantValue, GetGlobalEnv, GetGlobalEnvValue, GetHomeObjectFromFunction, GetICSlot, GetLengthFromFunction, GetModuleFromFunction, GetObjectSizeFromHClass, GetObjectType, GetProfileTypeInfo, GetPropertyInlinedProps, GetPrototypeFromHClass, GetStartIndex, GetTypedArraySpeciesProtectDetector, GetValueFromTaggedArray, HasPendingException, Hole, InitStringLengthAndFlags, InitializeFunctionWithMethod, InitializeJSFunction, InitializeObject, Int32, Int32Add, Int32And, Int32Equal, Int32LessThan, Int32Mul, Int64ToTaggedPtr, Int8, IntPtr, IntPtrAnd, IntPtrDiv, IntPtrEqual, IntPtrGreaterThan, IntPtrLessThan, IntPtrNot, IntPtrSize, IntToTaggedInt, Is32Bit, IsClassConstructor, IsDictionaryModeByHClass, IsEcmaObject, IsFastTypeArray, IsFastTypedArray, IsJSApiFunction, IsTypedArray, JSFunction::GetInlinedPropertyOffset, JSTaggedValue::TaggedTypeSize, JSThread::GlueData::GetAllocBufferOffset, JSThread::GlueData::GetGlobalConstOffset, JSThread::GlueData::GetGlueGlobalEnvOffset, JSThread::GlueData::GetIsEnableCMCGCOffset, JSThread::GlueData::GetIsStartHeapSamplingOffset, JSThread::GlueData::GetSlotSpaceAllocatorsAddressOffset, Jump, Label, Load, LoadHClass, LoadHClassFromMethodForDefineMethod, LoadPrimitive, MemoryAttribute::NoBarrier, MemoryAttribute::UnknownBarrier, NewFloat32ArrayObj, NewJSApiFunctionByHClass, NewJSForinIterator, NewJSFunctionByHClass, NewJSFunctionForDefineMethod, NewJSObject, NewObjectStubBuilder::AllocateInSOldPrologueImpl, NewObjectStubBuilder::AllocateInSOldPrologueImplForCMCGC, NewObjectStubBuilder::AllocateInYoungPrologue, NewObjectStubBuilder::AllocateInYoungPrologueImpl, NewObjectStubBuilder::AllocateInYoungPrologueImplForCMCGC, NewObjectStubBuilder::AllocateInYoungPrologueImplForCMSGC, NewObjectStubBuilder::CreateJSSharedMapIterator, NewObjectStubBuilder::DefineFuncForJit, NewObjectStubBuilder::DefineMethod, NewObjectStubBuilder::LoadHClassFromMethodForDefineMethod, NewObjectStubBuilder::NewFloat32ArrayObj, NewObjectStubBuilder::NewJSApiFunctionByHClass, NewObjectStubBuilder::NewJSFunctionForDefineMethod, NewObjectStubBuilder::NewJSFunctionForJit, NewObjectStubBuilder::NewJSObject, NewObjectStubBuilder::NewSTaggedArray, NewObjectStubBuilder::NewTaggedArrayChecked, NewProfileTypeInfoCell.

**Function/type/macro/call semantic interpretation:** unknown pending review of the exact hunk in its preprocessing/build context. **Effect on rule applicability:** unknown; do not treat as no impact.

## Parent/fix and control replay

Parent/fix, safe, and unrelated controls were not replayed as part of this dependency inventory. Keep their prior exact-bound replay evidence separate; missing objects or partial parsing remain unknown. See `README.md` for reproducible source identity and Runner commands.
