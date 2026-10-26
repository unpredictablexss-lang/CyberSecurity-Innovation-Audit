/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "ecmascript/compiler/native_inline_lowering.h"
#include "ecmascript/builtins/builtins_number.h"
#include "ecmascript/builtins/builtins_string.h"
#include "ecmascript/base/number_helper.h"
#include "ecmascript/compiler/circuit.h"
#include "ecmascript/compiler/circuit_builder-inl.h"
#include "ecmascript/compiler/circuit_builder_helper.h"
#include "ecmascript/compiler/share_gate_meta_data.h"
#include "ecmascript/js_dataview.h"
#include "ecmascript/compiler/circuit.h"
#include "ecmascript/compiler/new_object_stub_builder.h"
#include "ecmascript/global_env.h"
#include "ecmascript/js_iterator.h"
#include "ecmascript/js_thread.h"
#include "ecmascript/message_string.h"

namespace panda::ecmascript::kungfu {

std::optional<std::pair<size_t, bool>> NativeInlineLowering::GetCallInfo(GateRef gate)
{
    EcmaOpcode ecmaOpcode = acc_.GetByteCodeOpcode(gate);
    switch (ecmaOpcode) {
        case EcmaOpcode::CALLARG0_IMM8:
            return {{0U, false}};
        case EcmaOpcode::CALLTHIS0_IMM8_V8:
            return {{0U, true}};
        case EcmaOpcode::CALLARG1_IMM8_V8:
            return {{1U, false}};
        case EcmaOpcode::CALLTHIS1_IMM8_V8_V8:
            return {{1U, true}};
        case EcmaOpcode::CALLARGS2_IMM8_V8_V8:
            return {{2U, false}};
        case EcmaOpcode::CALLTHIS2_IMM8_V8_V8_V8:
            return {{2U, true}};
        case EcmaOpcode::CALLARGS3_IMM8_V8_V8_V8:
            return {{3U, false}};
        case EcmaOpcode::CALLTHIS3_IMM8_V8_V8_V8_V8:
            return {{3U, true}};
        case EcmaOpcode::CALLRANGE_IMM8_IMM8_V8: {
            CallRangeTypeInfoAccessor tia(compilationEnv_, circuit_, gate);
            return {{tia.GetArgc(), false}};
        }
        case EcmaOpcode::CALLTHISRANGE_IMM8_IMM8_V8: {
            CallThisRangeTypeInfoAccessor tia(compilationEnv_, circuit_, gate);
            return {{tia.GetArgc(), true}};
        }
        default:
            return std::nullopt;
    }
}

void NativeInlineLowering::RunNativeInlineLowering()
{
    std::vector<GateRef> gateList;
    circuit_->GetAllGates(gateList);
    for (const auto &gate : gateList) {
        auto op = acc_.GetOpCode(gate);
        if (op != OpCode::JS_BYTECODE) {
            continue;
        }
        auto optCallInfo = GetCallInfo(gate);
        if (!optCallInfo) {
            continue;
        }
        auto [argc, skipThis] = optCallInfo.value();
        CallTypeInfoAccessor ctia(compilationEnv_, circuit_, gate);
        BuiltinsStubCSigns::ID id = ctia.TryGetPGOBuiltinMethodId();
        if (IS_INVALID_ID(id) && id != BuiltinsStubCSigns::ID::BigIntConstructor) {
            continue;
        }
        switch (id) {
            case BuiltinsStubCSigns::ID::StringFromCharCode:
                TryInlineStringFromCharCode(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::StringSubstring:
                TryInlineStringSubstring(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::StringSubStr:
                TryInlineStringSubStr(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::StringSlice:
                TryInlineStringSlice(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberIsFinite:
                TryInlineNumberIsFinite(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberIsInteger:
                TryInlineNumberIsInteger(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberIsNaN:
                TryInlineNumberIsNaN(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberParseFloat:
                TryInlineNumberParseFloat(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberParseInt:
                TryInlineNumberParseInt(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::NumberIsSafeInteger:
                TryInlineNumberIsSafeInteger(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::TypedArrayEntries:
                TryInlineTypedArrayIteratorBuiltin(gate, id, circuit_->TypedArrayEntries(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::TypedArrayKeys:
                TryInlineTypedArrayIteratorBuiltin(gate, id, circuit_->TypedArrayKeys(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::TypedArrayValues:
                TryInlineTypedArrayIteratorBuiltin(gate, id, circuit_->TypedArrayValues(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayValues:
                TryInlineArrayIterator(gate, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayKeys:
                TryInlineArrayIterator(gate, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayEntries:
                TryInlineArrayIterator(gate, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAcos:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAcos(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAcosh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAcosh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAsin:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAsin(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAsinh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAsinh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAtan:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAtan(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAtan2:
                TryInlineMathBinaryBuiltin(gate, argc, id, circuit_->MathAtan2(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAtanh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathAtanh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathCos:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathCos(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathCosh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathCosh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathSign:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathSign(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathSin:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathSin(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathSinh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathSinh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathSqrt:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathSqrt(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathTan:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathTan(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathTanh:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathTanh(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathTrunc:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathTrunc(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathAbs:
                TryInlineMathAbsBuiltin(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathLog:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathLog(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathLog2:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathLog2(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathLog10:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathLog10(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathLog1p:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathLog1p(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathExp:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathExp(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathExpm1:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathExpm1(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathClz32:
                TryInlineMathClz32Builtin(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathPow:
                TryInlineMathBinaryBuiltin(gate, argc, id, circuit_->MathPow(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathCbrt:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathCbrt(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathImul:
                TryInlineMathImulBuiltin(gate, argc, id, circuit_->MathImul(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::GlobalIsFinite:
                TryInlineGlobalFiniteBuiltin(gate, argc, id, circuit_->GlobalIsFinite(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::GlobalIsNan:
                TryInlineGlobalNanBuiltin(gate, argc, id, circuit_->GlobalIsNan(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::DateGetTime:
                TryInlineDateGetTime(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathMin:
                TryInlineMathMinMaxBuiltin(gate, argc, id, circuit_->MathMin(), base::POSITIVE_INFINITY, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathMax:
                TryInlineMathMinMaxBuiltin(gate, argc, id, circuit_->MathMax(), -base::POSITIVE_INFINITY, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathRound:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathRound(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathFRound:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathFRound(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathCeil:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathCeil(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MathFloor:
                TryInlineMathUnaryBuiltin(gate, argc, id, circuit_->MathFloor(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayBufferIsView:
                TryInlineArrayBufferIsView(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::DataViewGetFloat32:
            case BuiltinsStubCSigns::ID::DataViewGetFloat64:
            case BuiltinsStubCSigns::ID::DataViewGetInt8:
            case BuiltinsStubCSigns::ID::DataViewGetInt16:
            case BuiltinsStubCSigns::ID::DataViewGetInt32:
            case BuiltinsStubCSigns::ID::DataViewGetUint16:
            case BuiltinsStubCSigns::ID::DataViewGetUint32:
            case BuiltinsStubCSigns::ID::DataViewGetUint8:
                TryInlineDataViewGet(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::DataViewSetFloat32:
            case BuiltinsStubCSigns::ID::DataViewSetFloat64:
            case BuiltinsStubCSigns::ID::DataViewSetInt8:
            case BuiltinsStubCSigns::ID::DataViewSetInt16:
            case BuiltinsStubCSigns::ID::DataViewSetInt32:
            case BuiltinsStubCSigns::ID::DataViewSetUint8:
            case BuiltinsStubCSigns::ID::DataViewSetUint16:
            case BuiltinsStubCSigns::ID::DataViewSetUint32:
                TryInlineDataViewSet(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::BigIntAsIntN:
            case BuiltinsStubCSigns::ID::BigIntAsUintN:
                TryInlineBigIntAsIntN(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapGet:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->MapGet(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapHas:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->MapHas(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapKeys:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->MapKeys(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapValues:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->MapValues(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapEntries:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->MapEntries(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetHas:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->SetHas(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetAdd:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->SetAdd(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::DateNow:
                TryInlineWhitoutParamBuiltin(gate, argc, id, circuit_->DateNow(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapDelete:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->MapDelete(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetDelete:
                InlineStubBuiltin(gate, 1U, argc, id, circuit_->SetDelete(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetValues:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->SetValues(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetEntries:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->SetEntries(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::BigIntConstructor:
                TryInlineBigIntConstructor(gate, argc, skipThis);
                break;
            case BuiltinsStubCSigns::ID::MapClear:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->MapClear(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::SetClear:
                InlineStubBuiltin(gate, 0U, argc, id, circuit_->SetClear(), skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArraySort:
                TryInlineArraySort(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectIs:
                TryInlineObjectIs(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectGetPrototypeOf:
                TryInlineObjectGetPrototypeOf(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectGetProto:
                TryInlineObjectGetProto(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectCreate:
                TryInlineObjectCreate(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectIsPrototypeOf:
                TryInlineObjectIsPrototypeOf(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ObjectHasOwnProperty:
                TryInlineObjectHasOwnProperty(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ReflectGetPrototypeOf:
                TryInlineReflectGetPrototypeOf(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ReflectGet:
                TryInlineReflectGet(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ReflectHas:
                TryInlineReflectHas(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ReflectConstruct:
                TryInlineReflectConstruct(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ReflectApply:
                TryInlineReflectApply(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::FunctionPrototypeHasInstance:
                TryInlineFunctionPrototypeHasInstance(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayIndexOf:
                TryInlineIndexOfIncludes(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayIncludes:
                TryInlineIndexOfIncludes(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayForEach:
                TryInlineArrayForEach(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayFind:
                TryInlineArrayFindOrFindIndex(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayFindIndex:
                TryInlineArrayFindOrFindIndex(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayFilter:
                TryInlineArrayFilter(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayMap:
                TryInlineArrayMap(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArraySome:
                TryInlineArraySome(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayEvery:
                TryInlineArrayEvery(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArrayPop:
                TryInlineArrayPop(gate, argc, id, skipThis);
                break;
            case BuiltinsStubCSigns::ID::ArraySlice:
                TryInlineArraySlice(gate, argc, id, skipThis);
                break;
            default:
                break;
        }
    }

    if (EnableLog()) {
        LOG_COMPILER(INFO) << " ";
        LOG_COMPILER(INFO) << "\033[34m" << "================="
                           << " After Native Inline Lowering "
                           << "[" << GetMethodName() << "] "
                           << "=================" << "\033[0m";
        circuit_->PrintAllGatesWithBytecode();
        LOG_COMPILER(INFO) << "\033[34m" << "=========================== End ===========================" << "\033[0m";
    }
}

void NativeInlineLowering::AddTraceLogs(GateRef gate, BuiltinsStubCSigns::ID id)
{
    size_t index = RTSTUB_ID(AotInlineBuiltinTrace);

    GateRef frameState = acc_.GetFrameState(gate);
    GateRef frameArgs = acc_.GetValueIn(frameState);
    GateRef callerFunc = acc_.GetValueIn(frameArgs, 0);
    std::vector<GateRef> args{callerFunc, builder_.Int32(id)};

    builder_.CallRuntime(glue_, index, Gate::InvalidGateRef, args, gate);
}

void NativeInlineLowering::TryInlineStringFromCharCode(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringFromCharCode)),
                                 {tacc.GetArg0()});
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, BuiltinsStubCSigns::ID::StringFromCharCode);
    }

    GateRef ret = builder_.StringFromSingleCharCode(tacc.GetArg0());
    acc_.ReplaceGate(gate, builder_.GetState(), builder_.GetDepend(), ret);
}

void NativeInlineLowering::TryInlineStringSubstring(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1 && argc != 2) { // only optimize one or two parameters scene
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef startTag = tacc.GetArg0();
        GateRef endTag = builder_.GetLengthFromString(thisValue);
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSubstring)),
                                     {tacc.GetArg0()});
            builder_.EcmaStringCheck(thisValue);
            auto param_check = builder_.TaggedIsNumber(startTag);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSubstring(thisValue, startTag, endTag);
    } else {
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef startTag = acc_.GetValueIn(gate, 1);
        GateRef endTag = acc_.GetValueIn(gate, 2);
        GateRef func = acc_.GetValueIn(gate, 3);
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, func,
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSubstring)));
            builder_.EcmaStringCheck(thisValue);
            auto start_param_check = builder_.TaggedIsNumber(startTag);
            auto end_param_check = builder_.TaggedIsNumber(endTag);
            auto param_check = builder_.BoolAnd(start_param_check, end_param_check);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSubstring(thisValue, startTag, endTag);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineStringSubStr(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1 && argc != 2) { // only optimize one or two parameters scene
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef intStart = tacc.GetArg0();
        GateRef lengthTag = builder_.Int32(INT_MAX);
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSubStr)),
                                     {tacc.GetArg0()});
            builder_.EcmaStringCheck(thisValue);
            auto param_check = builder_.TaggedIsNumber(intStart);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSubStr(thisValue, intStart, lengthTag);
    } else {
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef intStart = acc_.GetValueIn(gate, 1);
        GateRef lengthTag = acc_.GetValueIn(gate, 2);
        GateRef func = acc_.GetValueIn(gate, 3);  //acc
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, func,
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSubStr)));
            builder_.EcmaStringCheck(thisValue);
            auto start_param_check = builder_.TaggedIsNumber(intStart);
            auto end_param_check = builder_.TaggedIsNumber(lengthTag);
            auto param_check = builder_.BoolAnd(start_param_check, end_param_check);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSubStr(thisValue, intStart, lengthTag);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineStringSlice(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1 && argc != 2) { // only optimize one or two parameters scene
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef startTag = tacc.GetArg0();
        GateRef endTag = builder_.GetLengthFromString(thisValue);
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSlice)),
                                     {tacc.GetArg0()});
            builder_.EcmaStringCheck(thisValue);
            auto param_check = builder_.TaggedIsNumber(startTag);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSlice(thisValue, startTag, endTag);
    } else {
        GateRef thisValue = acc_.GetValueIn(gate, 0);
        GateRef startTag = acc_.GetValueIn(gate, 1);
        GateRef endTag = acc_.GetValueIn(gate, 2);
        GateRef func = acc_.GetValueIn(gate, 3);
        if (!Uncheck()) {
            builder_.CallTargetCheck(gate, func,
                                     builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::StringSlice)));
            builder_.EcmaStringCheck(thisValue);
            auto start_param_check = builder_.TaggedIsNumber(startTag);
            auto end_param_check = builder_.TaggedIsNumber(endTag);
            auto param_check = builder_.BoolAnd(start_param_check, end_param_check);
            builder_.DeoptCheck(param_check, acc_.GetFrameState(gate), DeoptType::BUILTIN_INLINING_TYPE_GUARD);
        }
        ret = builder_.StringSlice(thisValue, startTag, endTag);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberIsFinite(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::NumberIsFinite)));
    }
    GateRef ret = builder_.NumberIsFinite(tacc.GetArg0());
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberIsInteger(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    auto id = BuiltinsStubCSigns::ID::NumberIsInteger;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef ret = builder_.NumberIsInteger(tacc.GetArg0());
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberIsNaN(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::NumberIsNaN)));
    }
    GateRef ret = builder_.NumberIsNaN(tacc.GetArg0());
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberParseFloat(GateRef gate, size_t argc, bool skipThis)
{
    auto firstParam = skipThis ? 1 : 0;
    auto func = acc_.GetValueIn(gate, argc + firstParam);
    auto arg = acc_.GetValueIn(gate, firstParam);

    Environment env(gate, circuit_, &builder_);
    auto id = BuiltinsStubCSigns::ID::NumberParseFloat;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, func, builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef ret = builder_.NumberParseFloat(arg, acc_.GetFrameState(gate));
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberParseInt(GateRef gate, size_t argc, bool skipThis)
{
    auto firstParam = skipThis ? 1 : 0;
    auto func = acc_.GetValueIn(gate, argc + firstParam);
    auto arg = acc_.GetValueIn(gate, firstParam);
    auto radix = builder_.Undefined();
    if (argc > 1) {
        radix = acc_.GetValueIn(gate, firstParam + 1);
    }

    Environment env(gate, circuit_, &builder_);
    auto id = BuiltinsStubCSigns::ID::NumberParseInt;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, func, builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef ret = builder_.NumberParseInt(arg, radix);
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineNumberIsSafeInteger(GateRef gate, size_t argc, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    auto id = BuiltinsStubCSigns::ID::NumberIsSafeInteger;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef ret = builder_.NumberIsSafeInteger(tacc.GetArg0());
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineBigIntAsIntN(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                 bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (argc < 2U) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef bits = acc_.GetValueIn(gate, firstParam);
    GateRef bigint = acc_.GetValueIn(gate, firstParam + 1);
    GateRef frameState = acc_.GetFrameState(gate);
    bool isUnsigned = (id == BuiltinsStubCSigns::ID::BigIntAsUintN);
    const auto* op = isUnsigned ? circuit_->BigIntAsUintN() : circuit_->BigIntAsIntN();
    GateRef ret = builder_.BuildBigIntAsIntN(op, {bits, bigint, frameState});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineTypedArrayIteratorBuiltin(GateRef gate,
                                                              BuiltinsStubCSigns::ID id,
                                                              const GateMetaData* op, bool skipThis)
{
    if (!skipThis) {
        return;
    }

    CallThis0TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(), builder_.IntPtr(static_cast<int64_t>(id)), {tacc.GetThisObj()});
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef ret = builder_.BuildTypedArrayIterator(acc_.GetValueIn(gate, 0), op);
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineMathUnaryBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                     const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    if (argc == 0) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.NanValue());
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(op, {acc_.GetValueIn(gate, firstParam)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineWhitoutParamBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                        const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef ret = builder_.BuildControlDependOp(op, {});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineMathAbsBuiltin(GateRef gate, size_t argc, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::MathAbs)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, BuiltinsStubCSigns::ID::MathAbs);
    }

    if (argc == 0) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.NanValue());
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(circuit_->MathAbs(), {acc_.GetValueIn(gate, firstParam)},
                                                {acc_.GetFrameState(gate)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineMathClz32Builtin(GateRef gate, size_t argc, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::MathClz32)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, BuiltinsStubCSigns::ID::MathClz32);
    }
    if (argc == 0) {
        const int32_t defaultValue = 32;
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.Int32(defaultValue));
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(circuit_->MathClz32(), {acc_.GetValueIn(gate, firstParam)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineGlobalFiniteBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                        const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc == 0) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.Boolean(false));
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(op, {acc_.GetValueIn(gate, firstParam)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineGlobalNanBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                     const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc == 0) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.Boolean(true));
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(op, {acc_.GetValueIn(gate, firstParam)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineMathImulBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                    const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc < 2U) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.Int32(0));
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(op, {acc_.GetValueIn(gate, firstParam),
                                              acc_.GetValueIn(gate, firstParam + 1)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
    return;
}

void NativeInlineLowering::TryInlineMathBinaryBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                      const GateMetaData* op, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc < 2U) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.NanValue());
        return;
    }
    GateRef ret = builder_.BuildControlDependOp(op, {acc_.GetValueIn(gate, firstParam),
                                              acc_.GetValueIn(gate, firstParam + 1)});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
    return;
}

void NativeInlineLowering::TryInlineMathMinMaxBuiltin(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                      const GateMetaData* op, double defaultValue, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc == 0) {
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), builder_.Double(defaultValue));
        return;
    }
    GateRef ret = acc_.GetValueIn(gate, firstParam);
    if (argc == 1) {
        builder_.TypeOfCheck(ret, ParamType::NumberType());
        acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
        return;
    }
    for (size_t i = 1; i < argc; i++) {
        auto param = acc_.GetValueIn(gate, i + firstParam);
        ret = builder_.BuildControlDependOp(op, {ret, param});
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayBufferIsView(GateRef gate,
                                                      size_t argc,
                                                      BuiltinsStubCSigns::ID id,
                                                      bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1) {
        return;
    }
    CallThis1TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(), builder_.IntPtr(static_cast<int64_t>(id)), {tacc.GetArg0()});
    }
    GateRef arg0 = tacc.GetArg0();
    GateRef ret = builder_.ArrayBufferIsView(arg0);
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineDataViewGet(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1 && argc != 2) { // number of args must be 1/2
        return;
    }
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    GateRef thisObj = acc_.GetValueIn(gate, 0); // 0: this
    builder_.EcmaObjectCheck(thisObj);
    builder_.IsDataViewCheck(thisObj);
    GateRef dataViewCallID = builder_.Int32(id);
    GateRef index = acc_.GetValueIn(gate, 1); // 1: index of dataView
    GateRef ret = Circuit::NullGate();
    GateRef frameState = acc_.GetFrameState(gate);
    builder_.DeoptCheck(builder_.TaggedIsInt(index), frameState, DeoptType::INDEXNOTINT);
    GateRef indexInt = builder_.TaggedGetInt(index);
    if (argc == 1) { // if not provide isLittleEndian, default use big endian
        ret = builder_.DataViewGet(thisObj, indexInt, dataViewCallID, builder_.False(), frameState);
    } else if (argc == 2) { // 2: provide isLittleEndian
        GateRef isLittleEndian = acc_.GetValueIn(gate, 2); // 2: is little endian mode
        ret = builder_.DataViewGet(thisObj, indexInt, dataViewCallID, isLittleEndian, frameState);
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineDataViewSet(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc != 1 && argc != 2 && argc != 3) { // number of args must be 1/2/3
        return;
    }
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    GateRef thisObj = acc_.GetValueIn(gate, 0); // 0: this
    builder_.EcmaObjectCheck(thisObj);
    builder_.IsDataViewCheck(thisObj);
    GateRef dataViewCallID = builder_.Int32(id);
    GateRef index = acc_.GetValueIn(gate, 1); // 1: index
    GateRef frameState = acc_.GetFrameState(gate);
    builder_.DeoptCheck(builder_.TaggedIsInt(index), frameState, DeoptType::INDEXNOTINT);
    GateRef indexInt = builder_.TaggedGetInt(index);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) { // arg counts is 1
        ret = builder_.DataViewSet(
            thisObj, indexInt, builder_.Double(base::NAN_VALUE), dataViewCallID, builder_.False(), frameState);
    } else if (argc == 2) { // arg counts is 2
        GateRef value = acc_.GetValueIn(gate, 2); // 2: value
        ret = builder_.DataViewSet(thisObj, indexInt, value, dataViewCallID, builder_.False(), frameState);
    } else if (argc == 3) { // arg counts is 3
        GateRef value = acc_.GetValueIn(gate, 2); // 2: value
        GateRef isLittleEndian = acc_.GetValueIn(gate, 3); // 3: is little endian mode
        ret = builder_.DataViewSet(thisObj, indexInt, value, dataViewCallID, isLittleEndian, frameState);
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::InlineStubBuiltin(GateRef gate, size_t builtinArgc, size_t realArgc,
    BuiltinsStubCSigns::ID id, const GateMetaData* op, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        GateRef obj = acc_.GetValueIn(gate, 0);
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, realArgc + 1U),
                                 builder_.IntPtr(static_cast<int64_t>(id)), {obj});
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    std::vector<GateRef> args {};
    for (size_t i = 0; i <= builtinArgc; i++) {
        args.push_back(i <= realArgc ? acc_.GetValueIn(gate, i) : builder_.Undefined());
    }
    GateRef ret = builder_.BuildControlDependOp(op, args);
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::ReplaceGateWithPendingException(GateRef hirGate, GateRef value)
{
    GateRef state = builder_.GetState();
    // copy depend-wire of hirGate to value
    GateRef depend = builder_.GetDepend();
    // exception value
    GateRef exceptionVal = builder_.ExceptionConstant();
    // compare with trampolines result
    GateRef equal = builder_.Equal(value, exceptionVal);
    auto ifBranch = builder_.Branch(state, equal, 1, BranchWeight::DEOPT_WEIGHT, "checkException");

    GateRef ifTrue = builder_.IfTrue(ifBranch);
    GateRef ifFalse = builder_.IfFalse(ifBranch);
    GateRef eDepend = builder_.DependRelay(ifTrue, depend);
    GateRef sDepend = builder_.DependRelay(ifFalse, depend);
    StateDepend success(ifFalse, sDepend);
    StateDepend exception(ifTrue, eDepend);
    acc_.ReplaceHirWithIfBranch(hirGate, success, exception, value);
}

void NativeInlineLowering::TryInlineBigIntConstructor(GateRef gate, size_t argc, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    bool firstParam = skipThis ? 1 : 0;
    auto id = BuiltinsStubCSigns::ID::BigIntConstructor;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    auto param = builder_.Undefined();
    if (argc > 0) {
        param = acc_.GetValueIn(gate, firstParam);
    }

    GateRef ret = builder_.BuildControlDependOp(circuit_->BigIntConstructor(), {param});
    ReplaceGateWithPendingException(gate, ret);
    return;
}

void NativeInlineLowering::TryInlineDateGetTime(GateRef gate, size_t argc, bool skipThis)
{
    // Always shout be "this", we can't inline this function without instance of object
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    // We are sure, that "this" is passed to this function, so always need to do +1
    bool firstParam = 1;
    if (!Uncheck()) {
        GateRef obj = acc_.GetValueIn(gate, 0);
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(BuiltinsStubCSigns::ID::DateGetTime)), {obj});
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, BuiltinsStubCSigns::ID::DateGetTime);
    }
    // Take object using "this"
    GateRef obj = acc_.GetValueIn(gate, 0);
    GateRef ret = builder_.BuildControlDependOp(circuit_->DateGetTime(), {obj});
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineObjectIs(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 2) {  // 2: left and right
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef left = acc_.GetValueIn(gate, firstParam);
    GateRef right = acc_.GetValueIn(gate, firstParam + 1);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectIs(), { left, right });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineObjectGetPrototypeOf(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                         bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 1) {
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef value = acc_.GetValueIn(gate, firstParam);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectGetPrototypeOf(), { value });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineObjectGetProto(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis || argc != 0) {
        return;
    }

    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, 1), builder_.IntPtr(static_cast<int64_t>(id)));  // 1: func
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef thisValue = acc_.GetValueIn(gate, 0);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectGetPrototypeOf(), { thisValue });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineObjectCreate(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 1) {
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef proto = acc_.GetValueIn(gate, firstParam);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectCreate(), { proto });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineObjectIsPrototypeOf(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                        bool skipThis)
{
    if (!skipThis || argc != 1) {
        return;
    }

    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, 2), builder_.IntPtr(static_cast<int64_t>(id)));  // 2: func
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef thisValue = acc_.GetValueIn(gate, 0);
    GateRef value = acc_.GetValueIn(gate, 1);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectIsPrototypeOf(), {thisValue, value});
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineObjectHasOwnProperty(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                         bool skipThis)
{
    if (!skipThis || argc != 1) {
        return;
    }

    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, 2), builder_.IntPtr(static_cast<int64_t>(id)));  // 2: func
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef thisValue = acc_.GetValueIn(gate, 0);
    GateRef key = acc_.GetValueIn(gate, 1);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ObjectHasOwnProperty(), { thisValue, key });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineReflectGetPrototypeOf(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                          bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 1) {
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef value = acc_.GetValueIn(gate, firstParam);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectGetPrototypeOf(), { value });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineReflectGet(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 2) {  // 2: target and key, do not handle receiver argument scene
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    GateRef key = acc_.GetValueIn(gate, firstParam + 1);
    if (!TypeInfoAccessor::IsTrustedStringType(compilationEnv_, circuit_, chunk_, acc_, key)) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef target = acc_.GetValueIn(gate, firstParam);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectGet(), { target, key });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineReflectHas(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 2) {  // 2: target and key
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef target = acc_.GetValueIn(gate, firstParam);
    GateRef key = acc_.GetValueIn(gate, firstParam + 1);
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectHas(), { target, key });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineReflectConstruct(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                     bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 2) {  // 2: optimize newtarget equal target
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    GateRef target = acc_.GetValueIn(gate, firstParam);
    GateRef argumentsList = acc_.GetValueIn(gate, firstParam + 1);

    OpCode op = acc_.GetOpCode(argumentsList);
    if (op != OpCode::JS_BYTECODE) {
        return;
    }

    EcmaOpcode ecmaOpcode = acc_.GetByteCodeOpcode(argumentsList);
    // optimize empty array literal argumentsList
    if ((ecmaOpcode != EcmaOpcode::CREATEEMPTYARRAY_IMM8) && (ecmaOpcode != EcmaOpcode::CREATEEMPTYARRAY_IMM16)) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectConstruct(), { target });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineReflectApply(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                 bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (argc != 3) {  // 3: target key and  argumentsList
        return;
    }

    size_t firstParam = skipThis ? 1 : 0;
    GateRef target = acc_.GetValueIn(gate, firstParam);
    GateRef thisValue = acc_.GetValueIn(gate, firstParam + 1);
    GateRef argumentsList = acc_.GetValueIn(gate, firstParam + 2);

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + firstParam),
                                 builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), { target, thisValue, argumentsList });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineFunctionPrototypeApply(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                           bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (!skipThis || argc == 0) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef thisFunc = acc_.GetValueIn(gate, 0);
    GateRef thisArg = acc_.GetValueIn(gate, 1);
    GateRef argArray = (argc == 2) ? (acc_.GetValueIn(gate, 2)) : (builder_.UndefineConstant());
    GateRef ret = builder_.BuildControlDependOp(circuit_->FunctionPrototypeApply(), { thisFunc, thisArg, argArray });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineFunctionPrototypeBind(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                          bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (!skipThis || argc != 1) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, 2), builder_.IntPtr(static_cast<int64_t>(id)));  // 2: func
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef target = acc_.GetValueIn(gate, 0);
    GateRef thisArg = acc_.GetValueIn(gate, 1);
    GateRef ret = builder_.BuildControlDependOp(circuit_->FunctionPrototypeBind(), { target, thisArg });
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineFunctionPrototypeCall(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                          bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (!skipThis || argc == 0) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    std::vector<GateRef> args(argc + 1);  // 1: thisFunc
    for (size_t i = 0; i <= argc; ++i) {
        args[i] = acc_.GetValueIn(gate, i);
    }
    GateRef ret = builder_.BuildControlDependOp(circuit_->FunctionPrototypeCall(argc + 1), args);
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineFunctionPrototypeHasInstance(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id,
                                                                 bool skipThis)
{
    Environment env(gate, circuit_, &builder_);
    if (!skipThis || argc != 1) {
        return;
    }

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, 2), builder_.IntPtr(static_cast<int64_t>(id)));  // 2: func
    }

    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }

    GateRef function = acc_.GetValueIn(gate, 0);
    GateRef value = acc_.GetValueIn(gate, 1);
    GateRef ret = builder_.OrdinaryHasInstance(value, function);
    ReplaceGateWithPendingException(gate, ret);
}

void NativeInlineLowering::TryInlineIndexOfIncludes(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc == 0) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisArray = acc_.GetValueIn(gate, 0);
    GateRef targetElement = acc_.GetValueIn(gate, 1);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisArray);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisArray, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisArray, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef ret = Circuit::NullGate();
    GateRef callID = builder_.Int32(static_cast<int32_t>(id));
    GateRef arrayKind = builder_.Int32(static_cast<int32_t>(kind));
    if (argc == 1) {
        ret = builder_.ArrayIncludesIndexOf(thisArray, builder_.Int32(0), targetElement, callID, arrayKind);
    } else {
        GateRef fromIndexHandler = acc_.GetValueIn(gate, 2);
        builder_.DeoptCheck(builder_.TaggedIsInt(fromIndexHandler), acc_.GetFrameState(gate), DeoptType::INDEXNOTINT);
        GateRef fromIndex = builder_.TaggedGetInt(fromIndexHandler);
        ret = builder_.ArrayIncludesIndexOf(thisArray, fromIndex, targetElement, callID, arrayKind);
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayIterator(GateRef gate, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    CallThis0TypeInfoAccessor tacc(compilationEnv_, circuit_, gate);
    Environment env(gate, circuit_, &builder_);

    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, tacc.GetFunc(), builder_.IntPtr(static_cast<int64_t>(id)), {tacc.GetThisObj()});
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef thisObj = acc_.GetValueIn(gate, 0);
    builder_.EcmaObjectCheck(thisObj);
    GateRef CallIDRef = builder_.Int32(static_cast<int32_t>(id));
    GateRef ret = builder_.ArrayIteratorBuiltin(thisObj, CallIDRef);
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayForEach(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (argc == 0) { // 0: Must have a callBackFn
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    auto pcOffset = acc_.TryGetPcOffset(gate);
    GateRef ret = Circuit::NullGate();
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    if (argc == 1) {
        ret = builder_.ArrayForEach(thisValue, callBackFn, builder_.UndefineConstant(), pcOffset);
    } else {
        ret = builder_.ArrayForEach(thisValue, callBackFn, acc_.GetValueIn(gate, 2), pcOffset); // 2:provide using This
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayFindOrFindIndex(GateRef gate,
                                                         size_t argc,
                                                         BuiltinsStubCSigns::ID id,
                                                         bool skipThis)
{
    if (argc == 0) { // 0: Must have a callBackFn
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    uint32_t pcOffset = acc_.TryGetPcOffset(gate);
    GateRef ret = Circuit::NullGate();

    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef callIDRef = builder_.Int32(static_cast<int32_t>(id));

    if (argc == 1) {
        ret = builder_.ArrayFindOrFindIndex(thisValue, callBackFn, builder_.UndefineConstant(), callIDRef, pcOffset);
    } else {
        ret = builder_.ArrayFindOrFindIndex(
            thisValue, callBackFn, acc_.GetValueIn(gate, 2), callIDRef, pcOffset); // 2:provide using This
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayFilter(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (argc == 0) {
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    uint32_t pcOffset = acc_.TryGetPcOffset(gate);
    GateRef frameState = acc_.GetFrameState(gate);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        ret = builder_.ArrayFilter(thisValue, callBackFn, builder_.UndefineConstant(), frameState, pcOffset);
    } else {
        ret = builder_.ArrayFilter(
            thisValue, callBackFn, acc_.GetValueIn(gate, 2), frameState, pcOffset); //2: provide usingThis
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayMap(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (argc == 0) {
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    uint32_t pcOffset = acc_.TryGetPcOffset(gate);
    GateRef frameState = acc_.GetFrameState(gate);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        ret = builder_.ArrayMap(thisValue, callBackFn, builder_.UndefineConstant(), frameState, pcOffset);
    } else {
        ret = builder_.ArrayMap(
            thisValue, callBackFn, acc_.GetValueIn(gate, 2), frameState, pcOffset); //2: provide usingThis
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArraySome(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (argc == 0) {
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    uint32_t pcOffset = acc_.TryGetPcOffset(gate);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        ret = builder_.ArraySome(thisValue, callBackFn, builder_.UndefineConstant(), pcOffset);
    } else {
        ret = builder_.ArraySome(thisValue, callBackFn, acc_.GetValueIn(gate, 2), pcOffset); //2: provide usingThis
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayEvery(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (argc == 0) {
        return;
    }
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef callBackFn = acc_.GetValueIn(gate, 1);
    builder_.IsCallableCheck(callBackFn);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    uint32_t pcOffset = acc_.TryGetPcOffset(gate);
    GateRef ret = Circuit::NullGate();
    if (argc == 1) {
        ret = builder_.ArrayEvery(thisValue, callBackFn, builder_.UndefineConstant(), pcOffset);
    } else {
        ret = builder_.ArrayEvery(thisValue, callBackFn, acc_.GetValueIn(gate, 2), pcOffset); //2: provide usingThis
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArrayPop(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    GateRef ret = builder_.ArrayPop(thisValue, acc_.GetFrameState(gate));
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArraySlice(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    GateRef frameState = acc_.GetFrameState(gate);
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    GateRef ret = Circuit::NullGate();
    if (argc == 0) {
        ret = builder_.ArraySlice(thisValue, builder_.UndefineConstant(), builder_.UndefineConstant(), frameState);
    } else if (argc == 1) {
        GateRef startIndex = acc_.GetValueIn(gate, 1);
        builder_.DeoptCheck(builder_.TaggedIsInt(startIndex), acc_.GetFrameState(gate), DeoptType::INDEXNOTINT);
        ret = builder_.ArraySlice(thisValue, startIndex, builder_.UndefineConstant(), frameState);
    } else {
        GateRef startIndex = acc_.GetValueIn(gate, 1);
        GateRef endIndex = acc_.GetValueIn(gate, 2);
        builder_.DeoptCheck(builder_.TaggedIsInt(startIndex), acc_.GetFrameState(gate), DeoptType::INDEXNOTINT);
        builder_.DeoptCheck(builder_.TaggedIsInt(endIndex), acc_.GetFrameState(gate), DeoptType::INDEXNOTINT);
        ret = builder_.ArraySlice(thisValue, startIndex, endIndex, frameState);
    }
    if (EnableTrace()) {
        AddTraceLogs(gate, id);
    }
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

void NativeInlineLowering::TryInlineArraySort(GateRef gate, size_t argc, BuiltinsStubCSigns::ID id, bool skipThis)
{
    if (!skipThis) {
        return;
    }
    if (argc > 1) {
        return;
    }
    Environment env(gate, circuit_, &builder_);
    if (argc == 1) {
        GateRef callBackFn = acc_.GetValueIn(gate, 1);
        auto fnType = acc_.GetGateType(callBackFn);
        if (!fnType.IsUndefinedType()) {
            return;
        }
    }
    GateRef thisValue = acc_.GetValueIn(gate, 0);
    ElementsKind kind = acc_.TryGetArrayElementsKind(thisValue);
    if (Elements::IsHole(kind)) {
        return;
    }
    if (!Uncheck()) {
        builder_.CallTargetCheck(gate, acc_.GetValueIn(gate, argc + 1), builder_.IntPtr(static_cast<int64_t>(id)));
    }
    GateRef ret = Circuit::NullGate();

    builder_.BuiltinPrototypeHClassCheck(thisValue, BuiltinTypeId::ARRAY, kind, false);
    builder_.StableArrayCheck(thisValue, kind, ArrayMetaDataAccessor::Mode::LOAD_ELEMENT);
    ret = builder_.ArraySort(thisValue, builder_.UndefineConstant());
    acc_.ReplaceHirAndDeleteIfException(gate, builder_.GetStateDepend(), ret);
}

}  // namespace panda::ecmascript
