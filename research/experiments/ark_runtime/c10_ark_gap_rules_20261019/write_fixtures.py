from pathlib import Path
base = Path("tests/detectors/ark_runtime/fixtures/c10_gap_rules")
files = {
"ia_positive.cpp": r'''
class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), {target, fn, argv});
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef state = builder_.GetState();
    GateRef exceptionVal = builder_.ExceptionConstant();
    GateRef equal = builder_.Equal(value, exceptionVal);
    auto ifBranch = builder_.Branch(state, equal, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
''',
"ia_fixed.cpp": r'''
class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), {target, fn, argv});
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef state = builder_.GetState();
    GateRef condition = builder_.HasPendingException(glue_);
    auto ifBranch = builder_.Branch(state, condition, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
''',
"ia_safe.cpp": r'''
class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    if (builder_.HasPendingException(glue_)) {
        builder_.ReturnException();
        return;
    }
    builder_.ReturnValue(value);
}
};
''',
"ia_unrelated.cpp": r'''
class Decoder {
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef exceptionVal = builder_.ExceptionConstant();
    GateRef equal = builder_.Equal(value, exceptionVal);
    builder_.Branch(builder_.GetState(), equal, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
''',
"ia_unknown.cpp": r'''
class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    ReplaceGateWithPendingException(gate, ret);
}
};
''',
"length_positive.cpp": r'''
JSTaggedValue TypedArrayHelper::TypedArrayConstructor(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);
    int32_t elementLength = 0;
    elementLength = static_cast<int32_t>(index.GetNumber());
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
''',
"length_fixed.cpp": r'''
JSTaggedValue TypedArrayHelper::TypedArrayConstructor(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);
    uint32_t elementLength = 0;
    elementLength = static_cast<uint32_t>(index.GetNumber());
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
''',
"length_safe.cpp": r'''
JSTaggedValue TypedArrayHelper::MakeEmpty(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);
    uint32_t elementLength = 0;
    if (index.GetNumber() != 0) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "length", JSTaggedValue::Exception());
    }
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
''',
"length_unrelated.cpp": r'''
int ConvertMetric() {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    int32_t metric = 0;
    metric = static_cast<int32_t>(index.GetNumber());
    print(metric);
    return metric;
}
''',
"length_unknown.cpp": r'''
JSTaggedValue TypedArrayHelper::TypedArrayConstructor(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    int32_t elementLength = 0;
    elementLength = ConvertLength(index.GetNumber());
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
''',
"index_positive.cpp": r'''
JSTaggedValue DataViewGet(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    int32_t indexInt = base::NumberHelper::DoubleInRangeInt32(numberIndex.GetNumber());
    uint32_t index = static_cast<uint32_t>(indexInt);
    uint32_t elementSize = 4;
    if (static_cast<uint32_t>(index) + elementSize > size) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    return GetValueFromBuffer(thread, buffer, index, type, littleEndian);
}
''',
"index_fixed.cpp": r'''
JSTaggedValue DataViewGet(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = base::NumberHelper::DoubleToUInt64(numberIndex.GetNumber());
    uint64_t elementSize = 4;
    if (index + elementSize > size) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    uint32_t bufferIndex = static_cast<uint32_t>(index + offset);
    return GetValueFromBuffer(thread, buffer, bufferIndex, type, littleEndian);
}
''',
"index_safe.cpp": r'''
JSTaggedValue DataViewGetSafe(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = base::NumberHelper::DoubleToUInt64(numberIndex.GetNumber());
    uint64_t elementSize = 4;
    if (index > size || elementSize > size - index) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    return GetValueFromBuffer(thread, buffer, static_cast<uint32_t>(index + offset), type, littleEndian);
}
''',
"index_unrelated.cpp": r'''
int32_t SumIndices(int32_t index, int32_t elementSize) {
    return Int32Add(index, elementSize);
}
''',
"index_unknown.cpp": r'''
JSTaggedValue DataViewUnknown(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = UnknownIndexConversion(numberIndex.GetNumber());
    if (CheckIndexBounds(index, size, elementSize)) {
        return GetValueFromBuffer(thread, buffer, index, type, littleEndian);
    }
    return JSTaggedValue::Undefined();
}
''',
}
for name, text in files.items():
    (base / name).write_text(text.lstrip(), encoding="utf-8")
print(f"wrote {len(files)} fixtures")
