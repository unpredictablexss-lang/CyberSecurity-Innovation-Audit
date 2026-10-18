/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h"

#include "ecmascript/base/typed_array_helper-inl.h"
#include "ecmascript/compiler/builtins/builtins_array_stub_builder.h"
#include "ecmascript/compiler/call_stub_builder.h"
#include "ecmascript/compiler/new_object_stub_builder.h"

namespace panda::ecmascript::kungfu {
GateRef BuiltinsTypedArrayStubBuilder::GetDataPointFromBuffer(GateRef arrBuf)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    Label isNull(env);
    Label exit(env);
    Label isByteArray(env);
    Label notByteArray(env);
    DEFVARIABLE(result, VariableType::NATIVE_POINTER(), IntPtr(0));
    BRANCH(IsByteArray(arrBuf), &isByteArray, &notByteArray);
    Bind(&isByteArray);
    {
        result = ChangeByteArrayTaggedPointerToInt64(PtrAdd(arrBuf, IntPtr(ByteArray::DATA_OFFSET)));
        Jump(&exit);
    }
    Bind(&notByteArray);
    {
        GateRef data = GetArrayBufferData(arrBuf);
        result = GetExternalPointer(data);
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::CheckTypedArrayIndexInRange(GateRef array, GateRef index)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::BOOL(), False());
    Label exit(env);
    Label indexIsvalid(env);
    Label indexNotLessZero(env);
    BRANCH(Int64LessThan(index, Int64(0)), &exit, &indexNotLessZero);
    Bind(&indexNotLessZero);
    {
        GateRef arrLen = GetArrayLength(array);
        BRANCH(Int64GreaterThanOrEqual(index, ZExtInt32ToInt64(arrLen)), &exit, &indexIsvalid);
        Bind(&indexIsvalid);
        {
            result = True();
            Jump(&exit);
        }
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::LoadTypedArrayElement(GateRef glue, GateRef array, GateRef key, GateRef jsType)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::JS_ANY(), Hole());
    Label exit(env);
    Label notDetached(env);
    Label indexIsvalid(env);
    Label slowPath(env);
    GateRef buffer = GetViewedArrayBuffer(array);
    BRANCH(IsDetachedBuffer(buffer), &exit, &notDetached);
    Bind(&notDetached);
    {
        GateRef index = TryToElementsIndex(glue, key);
        BRANCH(CheckTypedArrayIndexInRange(array, index), &indexIsvalid, &exit);
        Bind(&indexIsvalid);
        {
            GateRef offset = GetByteOffset(array);
            result = GetValueFromBuffer(buffer, TruncInt64ToInt32(index), offset, jsType);
            BRANCH(TaggedIsNumber(*result), &exit, &slowPath);
        }
        Bind(&slowPath);
        {
            result = CallRuntime(glue, RTSTUB_ID(GetTypeArrayPropertyByIndex),
                { array, IntToTaggedInt(index), IntToTaggedInt(jsType) });
            Jump(&exit);
        }
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::StoreTypedArrayElement(GateRef glue, GateRef array, GateRef index, GateRef value,
                                                              GateRef jsType)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::JS_ANY(), Hole());
    Label exit(env);
    Label notDetached(env);
    Label indexIsvalid(env);
    GateRef buffer = GetViewedArrayBuffer(array);
    BRANCH(IsDetachedBuffer(buffer), &exit, &notDetached);
    Bind(&notDetached);
    {
        BRANCH(CheckTypedArrayIndexInRange(array, index), &indexIsvalid, &exit);
        Bind(&indexIsvalid);
        {
            result = CallRuntime(glue, RTSTUB_ID(SetTypeArrayPropertyByIndex),
                { array, IntToTaggedInt(index), value, IntToTaggedInt(jsType) });
            Jump(&exit);
        }
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::FastGetPropertyByIndex(GateRef glue, GateRef array,
                                                              GateRef index, GateRef jsType)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::JS_ANY(), Undefined());
    Label exit(env);
    Label isDetached(env);
    Label notDetached(env);
    Label slowPath(env);
    Label indexIsvalid(env);

    GateRef buffer = GetViewedArrayBuffer(array);
    BRANCH(IsDetachedBuffer(buffer), &isDetached, &notDetached);
    Bind(&isDetached);
    {
        Jump(&slowPath);
    }
    Bind(&notDetached);
    {
        GateRef arrLen = GetArrayLength(array);
        BRANCH(Int32GreaterThanOrEqual(index, arrLen), &exit, &indexIsvalid);
        Bind(&indexIsvalid);
        {
            GateRef offset = GetByteOffset(array);
            result = GetValueFromBuffer(buffer, index, offset, jsType);
            BRANCH(TaggedIsNumber(*result), &exit, &slowPath);
        }
    }
    Bind(&slowPath);
    {
        result = CallRuntime(glue, RTSTUB_ID(GetTypeArrayPropertyByIndex),
            { array, IntToTaggedInt(index), IntToTaggedInt(jsType)});
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::FastCopyElementToArray(GateRef glue, GateRef typedArray, GateRef array)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::BOOL(), True());
    DEFVARIABLE(start, VariableType::INT32(), Int32(0));
    Label exit(env);
    Label isDetached(env);
    Label notDetached(env);
    Label slowPath(env);
    Label begin(env);
    Label storeValue(env);
    Label endLoop(env);

    GateRef buffer = GetViewedArrayBuffer(typedArray);
    BRANCH(IsDetachedBuffer(buffer), &isDetached, &notDetached);
    Bind(&isDetached);
    {
        result = False();
        Jump(&slowPath);
    }
    Bind(&notDetached);
    {
        GateRef arrLen = GetArrayLength(typedArray);
        GateRef offset = GetByteOffset(typedArray);
        GateRef hclass = LoadHClass(typedArray);
        GateRef jsType = GetObjectType(hclass);

        Jump(&begin);
        LoopBegin(&begin);
        {
            BRANCH(Int32UnsignedLessThan(*start, arrLen), &storeValue, &exit);
            Bind(&storeValue);
            {
                GateRef value = GetValueFromBuffer(buffer, *start, offset, jsType);
                SetValueToTaggedArray(VariableType::JS_ANY(), glue, array, *start, value);
                start = Int32Add(*start, Int32(1));
                Jump(&endLoop);
            }
            Bind(&endLoop);
            LoopEnd(&begin);
        }
    }
    Bind(&slowPath);
    {
        CallRuntime(glue, RTSTUB_ID(FastCopyElementToArray), { typedArray, array});
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::GetValueFromBuffer(GateRef buffer, GateRef index, GateRef offset, GateRef jsType)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    DEFVARIABLE(result, VariableType::JS_ANY(), Undefined());
    Label exit(env);
    Label defaultLabel(env);
    Label isInt8(env);
    Label notInt8(env);
    Label isInt16(env);
    Label notInt16(env);

    Label labelBuffer[3] = { Label(env), Label(env), Label(env) };
    Label labelBuffer1[3] = { Label(env), Label(env), Label(env) };
    Label labelBuffer2[3] = { Label(env), Label(env), Label(env) };
    int64_t valueBuffer[3] = {
        static_cast<int64_t>(JSType::JS_INT8_ARRAY), static_cast<int64_t>(JSType::JS_UINT8_ARRAY),
        static_cast<int64_t>(JSType::JS_UINT8_CLAMPED_ARRAY) };
    int64_t valueBuffer1[3] = {
        static_cast<int64_t>(JSType::JS_INT16_ARRAY), static_cast<int64_t>(JSType::JS_UINT16_ARRAY),
        static_cast<int64_t>(JSType::JS_INT32_ARRAY) };
    int64_t valueBuffer2[3] = {
        static_cast<int64_t>(JSType::JS_UINT32_ARRAY), static_cast<int64_t>(JSType::JS_FLOAT32_ARRAY),
        static_cast<int64_t>(JSType::JS_FLOAT64_ARRAY) };

    BRANCH(Int32LessThanOrEqual(jsType, Int32(static_cast<int32_t>(JSType::JS_UINT8_CLAMPED_ARRAY))),
        &isInt8, &notInt8);
    Bind(&isInt8);
    {
        // 3 : this switch has 3 case
        Switch(jsType, &defaultLabel, valueBuffer, labelBuffer, 3);
        Bind(&labelBuffer[0]);
        {
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            GateRef re = Load(VariableType::INT8(), block, byteIndex);
            result = IntToTaggedPtr(SExtInt8ToInt32(re));
            Jump(&exit);
        }

        Bind(&labelBuffer[1]);
        {
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            GateRef re = Load(VariableType::INT8(), block, byteIndex);
            result = IntToTaggedPtr(ZExtInt8ToInt32(re));
            Jump(&exit);
        }
        // 2 : index of this buffer
        Bind(&labelBuffer[2]);
        {
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            GateRef re = Load(VariableType::INT8(), block, byteIndex);
            result = IntToTaggedPtr(ZExtInt8ToInt32(re));
            Jump(&exit);
        }
    }

    Bind(&notInt8);
    {
        BRANCH(Int32LessThanOrEqual(jsType, Int32(static_cast<int32_t>(JSType::JS_INT32_ARRAY))),
            &isInt16, &notInt16);
        Bind(&isInt16);
        {
            // 3 : this switch has 3 case
            Switch(jsType, &defaultLabel, valueBuffer1, labelBuffer1, 3);
            Bind(&labelBuffer1[0]);
            {
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::TWO)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef re = Load(VariableType::INT16(), block, byteIndex);
                result = IntToTaggedPtr(SExtInt16ToInt32(re));
                Jump(&exit);
            }

            Bind(&labelBuffer1[1]);
            {
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::TWO)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef re = Load(VariableType::INT16(), block, byteIndex);
                result = IntToTaggedPtr(ZExtInt16ToInt32(re));
                Jump(&exit);
            }
            // 2 : index of this buffer
            Bind(&labelBuffer1[2]);
            {
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef re = Load(VariableType::INT32(), block, byteIndex);
                result = IntToTaggedPtr(re);
                Jump(&exit);
            }
        }
        Bind(&notInt16);
        {
            // 3 : this switch has 3 case
            Switch(jsType, &defaultLabel, valueBuffer2, labelBuffer2, 3);
            Bind(&labelBuffer2[0]);
            {
                Label overflow(env);
                Label notOverflow(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef re = Load(VariableType::INT32(), block, byteIndex);

                auto condition = Int32UnsignedGreaterThan(re, Int32(INT32_MAX));
                BRANCH(condition, &overflow, &notOverflow);
                Bind(&overflow);
                {
                    result = DoubleToTaggedDoublePtr(ChangeUInt32ToFloat64(re));
                    Jump(&exit);
                }
                Bind(&notOverflow);
                {
                    result = IntToTaggedPtr(re);
                    Jump(&exit);
                }
            }
            Bind(&labelBuffer2[1]);
            {
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef re = Load(VariableType::INT32(), block, byteIndex);
                result = DoubleToTaggedDoublePtr(ExtFloat32ToDouble(CastInt32ToFloat32(re)));
                Jump(&exit);
            }
            // 2 : index of this buffer
            Bind(&labelBuffer2[2]);
            {
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::EIGHT)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                GateRef tmpResult = CastInt64ToFloat64(Load(VariableType::INT64(), block, byteIndex));

                Label tmpResultIsNumber(env);
                Label tmpResultIsNan(env);
                BRANCH(env->GetBuilder()->DoubleIsImpureNaN(tmpResult), &tmpResultIsNan, &tmpResultIsNumber);
                Bind(&tmpResultIsNan);
                result = DoubleToTaggedDoublePtr(Double(base::NAN_VALUE));
                Jump(&exit);
                Bind(&tmpResultIsNumber);
                result = DoubleToTaggedDoublePtr(tmpResult);
                Jump(&exit);
            }
        }
    }

    Bind(&defaultLabel);
    {
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::CalculatePositionWithLength(GateRef position, GateRef length)
{
    auto env = GetEnvironment();
    Label entry(env);
    env->SubCfgEntry(&entry);
    DEFVARIABLE(result, VariableType::INT64(), Int64(0));
    Label positionLessThanZero(env);
    Label positionNotLessThanZero(env);
    Label resultNotGreaterThanZero(env);
    Label positionLessThanLength(env);
    Label positionNotLessThanLength(env);
    Label afterCalculatePosition(env);

    BRANCH(Int64LessThan(position, Int64(0)), &positionLessThanZero, &positionNotLessThanZero);
    Bind(&positionLessThanZero);
    {
        result = Int64Add(position, length);
        BRANCH(Int64GreaterThan(*result, Int64(0)), &afterCalculatePosition, &resultNotGreaterThanZero);
        Bind(&resultNotGreaterThanZero);
        {
            result = Int64(0);
            Jump(&afterCalculatePosition);
        }
    }
    Bind(&positionNotLessThanZero);
    {
        BRANCH(Int64LessThan(position, length), &positionLessThanLength, &positionNotLessThanLength);
        Bind(&positionLessThanLength);
        {
            result = position;
            Jump(&afterCalculatePosition);
        }
        Bind(&positionNotLessThanLength);
        {
            result = length;
            Jump(&afterCalculatePosition);
        }
    }
    Bind(&afterCalculatePosition);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

void BuiltinsTypedArrayStubBuilder::Reverse(GateRef glue, GateRef thisValue, [[maybe_unused]] GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label isFastTypedArray(env);
    Label defaultConstr(env);
    Label notDetached(env);
    Label notEmpty(env);
    Label writeResult(env);

    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    GateRef arrayType = GetObjectType(LoadHClass(thisValue));
    BRANCH(IsFastTypeArray(arrayType), &isFastTypedArray, slowPath);
    Bind(&isFastTypedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    GateRef arrLen = GetArrayLength(thisValue);
    BRANCH(Int32Equal(arrLen, Int32(0)), &writeResult, &notEmpty);
    Bind(&notEmpty);
    CallNGCRuntime(glue, RTSTUB_ID(ReverseTypedArray), {thisValue});
    Jump(&writeResult);
    Bind(&writeResult);
    result->WriteVariable(thisValue);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::LastIndexOf(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label isHeapObject(env);
    Label typedArray(env);
    Label notDetached(env);

    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);

    GateRef len = ZExtInt32ToInt64(GetArrayLength(thisValue));
    Label isEmptyArray(env);
    Label notEmptyArray(env);
    BRANCH(Int64Equal(len, Int64(0)), &isEmptyArray, &notEmptyArray);
    Bind(&isEmptyArray);
    {
        result->WriteVariable(IntToTaggedPtr(Int32(-1)));
        Jump(exit);
    }
    Bind(&notEmptyArray);

    GateRef value = GetCallArg0(numArgs);
    DEFVARIABLE(relativeFromIndex, VariableType::INT64(), Int64(0));
    Label findIndex(env);
    Label isOneArg(env);
    Label isTwoArg(env);
    // 2:Indicates the number of parameters passed in.
    BRANCH(Int64Equal(TruncPtrToInt32(numArgs), Int32(2)), &isTwoArg, &isOneArg);
    Bind(&isOneArg);
    {
        relativeFromIndex = Int64Sub(len, Int64(1));
        Jump(&findIndex);
    }
    Bind(&isTwoArg);
    {
        GateRef fromIndex = GetCallArg1(numArgs);
        Label taggedIsInt(env);
        BRANCH(TaggedIsInt(fromIndex), &taggedIsInt, slowPath);
        Bind(&taggedIsInt);
        GateRef fromIndexInt = SExtInt32ToInt64(TaggedGetInt(fromIndex));
        Label isFromIndexLessZero(env);
        Label isFromIndexNotLessZero(env);
        BRANCH(Int64LessThan(fromIndexInt, Int64(0)), &isFromIndexLessZero, &isFromIndexNotLessZero);
        Bind(&isFromIndexLessZero);
        {
            relativeFromIndex = Int64Add(len, fromIndexInt);
            Jump(&findIndex);
        }
        Bind(&isFromIndexNotLessZero);
        {
            Label isFromIndexGreatLen(env);
            Label isFromIndexNotGreatLen(env);
            BRANCH(Int64GreaterThan(fromIndexInt, Int64Sub(len, Int64(1))),
                &isFromIndexGreatLen, &isFromIndexNotGreatLen);
            Bind(&isFromIndexGreatLen);
            {
                relativeFromIndex = Int64Sub(len, Int64(1));
                Jump(&findIndex);
            }
            Bind(&isFromIndexNotGreatLen);
            {
                relativeFromIndex = fromIndexInt;
                Jump(&findIndex);
            }
        }
    }

    Bind(&findIndex);
    {
        Label loopHead(env);
        Label loopEnd(env);
        Label loopExit(env);
        Label loopNext(env);
        Label isFound(env);
        Jump(&loopHead);
        LoopBegin(&loopHead);
        {
            BRANCH(Int64LessThan(*relativeFromIndex, Int64(0)), &loopExit, &loopNext);
            Bind(&loopNext);
            {
                GateRef hclass = LoadHClass(thisValue);
                GateRef jsType = GetObjectType(hclass);
                GateRef ele = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*relativeFromIndex), jsType);
                BRANCH(FastStrictEqual(glue, value, ele, ProfileOperation()), &isFound, &loopEnd);
                Bind(&isFound);
                {
                    result->WriteVariable(IntToTaggedPtr(*relativeFromIndex));
                    Jump(exit);
                }
            }
        }
        Bind(&loopEnd);
        relativeFromIndex = Int64Sub(*relativeFromIndex, Int64(1));
        LoopEnd(&loopHead);
        Bind(&loopExit);
        result->WriteVariable(IntToTaggedPtr(Int32(-1)));
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::IndexOf(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label defaultConstr(env);
    Label notDetached(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);

    DEFVARIABLE(fromIndex, VariableType::INT64(), Int64(0));
    DEFVARIABLE(thisArrLen, VariableType::INT64(), ZExtInt32ToInt64(GetArrayLength(thisValue)));
    Label thisIsEmpty(env);
    Label thisIsNotEmpty(env);
    Label getFromIndex(env);
    Label next(env);
    result->WriteVariable(IntToTaggedPtr(Int32(-1)));
    BRANCH(Int64Equal(*thisArrLen, Int64(0)), &thisIsEmpty, &thisIsNotEmpty);
    Bind(&thisIsEmpty);
    Jump(exit);
    Bind(&thisIsNotEmpty);
    // 2 : index of the param
    BRANCH(Int64Equal(numArgs, IntPtr(2)), &getFromIndex, &next);
    Bind(&getFromIndex);
    {
        GateRef index = GetCallArg1(numArgs);
        Label taggedIsInt(env);
        Label lessThanZero(env);
        Label stillLessThanZero(env);
        BRANCH(TaggedIsInt(index), &taggedIsInt, slowPath);
        Bind(&taggedIsInt);
        fromIndex = SExtInt32ToInt64(TaggedGetInt(index));
        BRANCH(Int64LessThan(*fromIndex, Int64(0)), &lessThanZero, &next);
        Bind(&lessThanZero);
        {
            fromIndex = Int64Add(*fromIndex, *thisArrLen);
            BRANCH(Int64LessThan(*fromIndex, Int64(0)), &stillLessThanZero, &next);
            Bind(&stillLessThanZero);
            fromIndex = Int64(0);
            Jump(&next);
        }
    }
    Bind(&next);
    {
        GateRef target = GetCallArg0(numArgs);
        DEFVARIABLE(curIndex, VariableType::INT64(), *fromIndex);
        Label lessThanLength(env);
        BRANCH(Int64GreaterThanOrEqual(*curIndex, *thisArrLen), exit, &lessThanLength);
        Bind(&lessThanLength);
        {
            Label loopHead(env);
            Label loopEnd(env);
            Label loopNext(env);
            Label loopExit(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                BRANCH(Int64LessThan(*curIndex, *thisArrLen), &loopNext, &loopExit);
                Bind(&loopNext);
                {
                    GateRef kValue = FastGetPropertyByIndex(glue, thisValue,
                        TruncInt64ToInt32(*curIndex), GetObjectType(LoadHClass(thisValue)));
                    Label hasException0(env);
                    Label notHasException0(env);
                    BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
                    Bind(&hasException0);
                    {
                        result->WriteVariable(Exception());
                        Jump(exit);
                    }
                    Bind(&notHasException0);
                    {
                        Label find(env);
                        BRANCH(FastStrictEqual(glue, target, kValue, ProfileOperation()), &find, &loopEnd);
                        Bind(&find);
                        {
                            result->WriteVariable(IntToTaggedPtr(*curIndex));
                            Jump(exit);
                        }
                    }
                }
            }
            Bind(&loopEnd);
            curIndex = Int64Add(*curIndex, Int64(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::Find(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label isHeapObject(env);
    Label defaultConstr(env);
    Label typedArray(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    Label arg0HeapObject(env);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    Label callable(env);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);
    GateRef argHandle = GetCallArg1(numArgs);
    GateRef thisArrLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    DEFVARIABLE(i, VariableType::INT64(), Int64(0));
    Label loopHead(env);
    Label loopEnd(env);
    Label next(env);
    Label loopExit(env);
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        Label hasException0(env);
        Label notHasException0(env);
        BRANCH(Int64LessThan(*i, thisArrLen), &next, &loopExit);
        Bind(&next);
        GateRef kValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*i),
            GetObjectType(LoadHClass(thisValue)));
        BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
        Bind(&hasException0);
        {
            result->WriteVariable(Exception());
            Jump(exit);
        }
        Bind(&notHasException0);
        {
            GateRef key = Int64ToTaggedInt(*i);
            Label hasException1(env);
            Label notHasException1(env);
            JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
            callArgs.callThisArg3WithReturnArgs = { argHandle, kValue, key, thisValue };
            CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
                Circuit::NullGate(), callArgs);
            GateRef retValue = callBuilder.JSCallDispatch();
            BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
            Bind(&hasException1);
            {
                result->WriteVariable(retValue);
                Jump(exit);
            }
            Bind(&notHasException1);
            {
                Label find(env);
                BRANCH(TaggedIsTrue(FastToBoolean(retValue)), &find, &loopEnd);
                Bind(&find);
                {
                    result->WriteVariable(kValue);
                    Jump(exit);
                }
            }
        }
    }
    Bind(&loopEnd);
    i = Int64Add(*i, Int64(1));
    LoopEnd(&loopHead);
    Bind(&loopExit);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::Includes(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label typedArray(env);
    Label isHeapObject(env);
    Label notFound(env);
    Label thisLenNotZero(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    GateRef thisLen = GetArrayLength(thisValue);
    BRANCH(Int32Equal(thisLen, Int32(0)), &notFound, &thisLenNotZero);
    Bind(&thisLenNotZero);
    {
        DEFVARIABLE(fromIndex, VariableType::INT32(), Int32(0));
        Label getArgTwo(env);
        Label nextProcess(env);
        BRANCH(Int64Equal(numArgs, IntPtr(2)), &getArgTwo, &nextProcess); // 2: 2 parameters
        Bind(&getArgTwo);
        {
            Label secondArgIsInt(env);
            GateRef fromIndexTemp = GetCallArg1(numArgs);
            BRANCH(TaggedIsInt(fromIndexTemp), &secondArgIsInt, slowPath);
            Bind(&secondArgIsInt);
            fromIndex = GetInt32OfTInt(fromIndexTemp);
            BRANCH(Int32GreaterThanOrEqual(*fromIndex, thisLen), &notFound, &nextProcess);
        }
        Bind(&nextProcess);
        {
            Label setBackZero(env);
            Label calculateFrom(env);
            Label nextCheck(env);
            BRANCH(Int64GreaterThanOrEqual(numArgs, IntPtr(1)), &nextCheck, slowPath);
            Bind(&nextCheck);
            {
                Label startLoop(env);
                BRANCH(Int32LessThan(Int32Add(*fromIndex, thisLen), Int32(0)), &setBackZero, &calculateFrom);
                Bind(&setBackZero);
                {
                    fromIndex = Int32(0);
                    Jump(&startLoop);
                }
                Bind(&calculateFrom);
                Label fromIndexLessThanZero(env);
                BRANCH(Int32GreaterThanOrEqual(*fromIndex, Int32(0)), &startLoop, &fromIndexLessThanZero);
                Bind(&fromIndexLessThanZero);
                {
                    fromIndex = Int32Add(*fromIndex, thisLen);
                    Jump(&startLoop);
                }
                Bind(&startLoop);
                GateRef searchElement = GetCallArg0(numArgs);
                Label loopHead(env);
                Label loopEnd(env);
                Label next(env);
                Label loopExit(env);
                Jump(&loopHead);
                LoopBegin(&loopHead);
                {
                    BRANCH(Int32LessThan(*fromIndex, thisLen), &next, &loopExit);
                    Bind(&next);
                    {
                        Label valueFound(env);
                        GateRef value = FastGetPropertyByIndex(glue, thisValue, *fromIndex,
                            GetObjectType(LoadHClass(thisValue)));
                        GateRef valueEqual = StubBuilder::SameValueZero(glue, searchElement, value);
                        BRANCH(valueEqual, &valueFound, &loopEnd);
                        Bind(&valueFound);
                        {
                            result->WriteVariable(TaggedTrue());
                            Jump(exit);
                        }
                    }
                }
                Bind(&loopEnd);
                fromIndex = Int32Add(*fromIndex, Int32(1));
                LoopEnd(&loopHead);
                Bind(&loopExit);
                Jump(&notFound);
            }
        }
    }
    Bind(&notFound);
    {
        result->WriteVariable(TaggedFalse());
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::CopyWithin(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label isHeapObject(env);
    Label defaultConstr(env);
    Label typedArray(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    GateRef jsType = GetObjectType(LoadHClass(thisValue));
    BRANCH(IsFastTypeArray(jsType), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);

    DEFVARIABLE(startPos, VariableType::INT64(), Int64(0));
    DEFVARIABLE(endPos, VariableType::INT64(), Int64(0));
    Label targetTagExists(env);
    Label targetTagIsInt(env);
    Label startTagExists(env);
    Label startTagIsInt(env);
    Label afterCallArg1(env);
    Label endTagExists(env);
    Label endTagIsInt(env);
    Label afterCallArg2(env);
    GateRef thisLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    // 0 : index of the param
    BRANCH(Int64GreaterThanOrEqual(IntPtr(0), numArgs), slowPath, &targetTagExists);
    Bind(&targetTagExists);
    GateRef targetTag = GetCallArg0(numArgs);
    BRANCH(TaggedIsInt(targetTag), &targetTagIsInt, slowPath);
    Bind(&targetTagIsInt);
    GateRef argTarget = SExtInt32ToInt64(TaggedGetInt(targetTag));
    // 1 : index of the param
    BRANCH(Int64GreaterThanOrEqual(IntPtr(1), numArgs), &afterCallArg1, &startTagExists);
    Bind(&startTagExists);
    GateRef startTag = GetCallArg1(numArgs);
    BRANCH(TaggedIsInt(startTag), &startTagIsInt, slowPath);
    Bind(&startTagIsInt);
    startPos = SExtInt32ToInt64(TaggedGetInt(startTag));
    Jump(&afterCallArg1);
    Bind(&afterCallArg1);
    endPos = thisLen;
    // 2 : index of the param
    BRANCH(Int64GreaterThanOrEqual(IntPtr(2), numArgs), &afterCallArg2, &endTagExists);
    Bind(&endTagExists);
    GateRef endTag = GetCallArg2(numArgs);
    BRANCH(TaggedIsInt(endTag), &endTagIsInt, slowPath);
    Bind(&endTagIsInt);
    endPos = SExtInt32ToInt64(TaggedGetInt(endTag));
    Jump(&afterCallArg2);
    Bind(&afterCallArg2);

    DEFVARIABLE(copyTo, VariableType::INT64(), Int64(0));
    DEFVARIABLE(copyFrom, VariableType::INT64(), Int64(0));
    DEFVARIABLE(copyEnd, VariableType::INT64(), Int64(0));
    DEFVARIABLE(count, VariableType::INT64(), Int64(0));
    DEFVARIABLE(direction, VariableType::INT64(), Int64(0));
    Label calculateCountBranch1(env);
    Label calculateCountBranch2(env);
    Label afterCalculateCount(env);
    Label needToAdjustParam(env);
    Label afterAdjustParam(env);
    copyTo = CalculatePositionWithLength(argTarget, thisLen);
    copyFrom = CalculatePositionWithLength(*startPos, thisLen);
    copyEnd = CalculatePositionWithLength(*endPos, thisLen);
    BRANCH(Int64LessThan(Int64Sub(*copyEnd, *copyFrom), Int64Sub(thisLen, *copyTo)),
        &calculateCountBranch1, &calculateCountBranch2);
    Bind(&calculateCountBranch1);
    {
        count = Int64Sub(*copyEnd, *copyFrom);
        Jump(&afterCalculateCount);
    }
    Bind(&calculateCountBranch2);
    {
        count = Int64Sub(thisLen, *copyTo);
        Jump(&afterCalculateCount);
    }
    Bind(&afterCalculateCount);
    {
        direction = Int64(1);
        GateRef copyFromVal = *copyFrom;
        GateRef copyToVal = *copyTo;
        GateRef countVal = *count;
        BRANCH(LogicAndBuilder(env).And(Int64LessThan(copyFromVal, copyToVal))
            .And(Int64LessThan(copyToVal, Int64Add(copyFromVal, countVal))).Done(),
            &needToAdjustParam, &afterAdjustParam);
        Bind(&needToAdjustParam);
        {
            direction = Int64(-1);
            copyFrom = Int64Sub(Int64Add(*copyFrom, *count), Int64(1));
            copyTo = Int64Sub(Int64Add(*copyTo, *count), Int64(1));
            Jump(&afterAdjustParam);
        }
        Bind(&afterAdjustParam);
        {
            DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
            Label loopHead(env);
            Label loopEnd(env);
            Label next(env);
            Label loopExit(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                Label hasException0(env);
                Label notHasException0(env);
                BRANCH(Int64GreaterThan(*count, Int64(0)), &next, &loopExit);
                Bind(&next);
                kValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*copyFrom), jsType);
                BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
                Bind(&hasException0);
                {
                    result->WriteVariable(Exception());
                    Jump(exit);
                }
                Bind(&notHasException0);
                {
                    StoreTypedArrayElement(glue, thisValue, *copyTo, *kValue, jsType);
                    Jump(&loopEnd);
                }
            }
            Bind(&loopEnd);
            copyFrom = Int64Add(*copyFrom, *direction);
            copyTo = Int64Add(*copyTo, *direction);
            count = Int64Sub(*count, Int64(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            result->WriteVariable(thisValue);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::ReduceRight(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label defaultConstr(env);
    Label atLeastOneArg(env);
    Label callbackFnHandleHeapObject(env);
    Label callbackFnHandleCallable(env);
    Label noTypeError(env);
    Label typedArray(env);
    Label notDetached(env);

    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    GateRef thisLen = GetArrayLength(thisValue);
    BRANCH(Int64GreaterThanOrEqual(numArgs, IntPtr(1)), &atLeastOneArg, slowPath);
    Bind(&atLeastOneArg);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &callbackFnHandleHeapObject, slowPath);
    Bind(&callbackFnHandleHeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callbackFnHandleCallable, slowPath);
    Bind(&callbackFnHandleCallable);
    GateRef thisLenIsZero = Int32Equal(thisLen, Int32(0));
    GateRef numArgsLessThanTwo = Int64LessThan(numArgs, IntPtr(2));
    BRANCH(BitAnd(thisLenIsZero, numArgsLessThanTwo), slowPath, &noTypeError);
    Bind(&noTypeError);
    {
        DEFVARIABLE(accumulator, VariableType::JS_ANY(), Undefined());
        DEFVARIABLE(k, VariableType::INT32(), Int32Sub(thisLen, Int32(1)));
        Label updateAccumulator(env);
        Label accumulateBegin(env);
        Label defaultValue(env);
        BRANCH(numArgsLessThanTwo, &defaultValue, &updateAccumulator);
        Bind(&updateAccumulator);
        {
            accumulator = GetCallArg1(numArgs);
            Jump(&accumulateBegin);
        }
        Bind(&defaultValue);
        {
            accumulator = FastGetPropertyByIndex(glue, thisValue, *k, GetObjectType(LoadHClass(thisValue)));
            k = Int32Sub(*k, Int32(1));
            Jump(&accumulateBegin);
        }
        Bind(&accumulateBegin);
        {
            // 4 : max value of the param amount
            GateRef argsLength = Int32(4);
            NewObjectStubBuilder newBuilder(this);
            GateRef argList = newBuilder.NewTaggedArray(glue, argsLength);
            Label loopHead(env);
            Label next(env);
            Label loopEnd(env);
            Label loopExit(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                BRANCH(Int32GreaterThanOrEqual(*k, Int32(0)), &next, &loopExit);
                Bind(&next);
                {
                    GateRef kValue = FastGetPropertyByIndex(glue, thisValue, *k, GetObjectType(LoadHClass(thisValue)));
                    // 0 : the first position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(0), *accumulator);
                    // 1 : the second position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(1), kValue);
                    // 2 : the third position
                    SetValueToTaggedArray(VariableType::INT32(), glue, argList, Int32(2), IntToTaggedInt(*k));
                    // 3 : the fourth position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(3), thisValue);
                    GateRef argv = PtrAdd(argList, IntPtr(TaggedArray::DATA_OFFSET));
                    JSCallArgs callArgs(JSCallMode::CALL_THIS_ARGV_WITH_RETURN);
                    callArgs.callThisArgvWithReturnArgs = { argsLength, argv, Undefined() };
                    CallStubBuilder callBuilder(this, glue, callbackFnHandle, argsLength, 0, nullptr,
                        Circuit::NullGate(), callArgs);
                    GateRef callResult = callBuilder.JSCallDispatch();
                    Label hasException1(env);
                    Label notHasException1(env);
                    BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
                    Bind(&hasException1);
                    {
                        result->WriteVariable(Exception());
                        Jump(exit);
                    }
                    Bind(&notHasException1);
                    {
                        accumulator = callResult;
                        Jump(&loopEnd);
                    }
                }
            }
            Bind(&loopEnd);
            k = Int32Sub(*k, Int32(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            result->WriteVariable(*accumulator);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::Reduce(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label defaultConstr(env);
    Label atLeastOneArg(env);
    Label callbackFnHandleHeapObject(env);
    Label callbackFnHandleCallable(env);
    Label noTypeError(env);
    Label typedArray(env);
    Label notDetached(env);

    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    GateRef thisLen = GetArrayLength(thisValue);
    BRANCH(Int64GreaterThanOrEqual(numArgs, IntPtr(1)), &atLeastOneArg, slowPath);
    Bind(&atLeastOneArg);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &callbackFnHandleHeapObject, slowPath);
    Bind(&callbackFnHandleHeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callbackFnHandleCallable, slowPath);
    Bind(&callbackFnHandleCallable);
    GateRef thisLenIsZero = Int32Equal(thisLen, Int32(0));
    GateRef numArgsLessThanTwo = Int64LessThan(numArgs, IntPtr(2));
    BRANCH(BitAnd(thisLenIsZero, numArgsLessThanTwo), slowPath, &noTypeError);
    Bind(&noTypeError);
    {
        DEFVARIABLE(accumulator, VariableType::JS_ANY(), Undefined());
        DEFVARIABLE(k, VariableType::INT32(), Int32(0));
        Label updateAccumulator(env);
        Label accumulateBegin(env);
        Label defaultValue(env);
        // 2 : index of the param
        BRANCH(numArgsLessThanTwo, &defaultValue, &updateAccumulator);
        Bind(&updateAccumulator);
        {
            accumulator = GetCallArg1(numArgs);
            Jump(&accumulateBegin);
        }
        Bind(&defaultValue);
        {
            accumulator = FastGetPropertyByIndex(glue, thisValue, Int32(0), GetObjectType(LoadHClass(thisValue)));
            k = Int32Add(*k, Int32(1));
            Jump(&accumulateBegin);
        }
        Bind(&accumulateBegin);
        {
            // 4 : max value of the param amount
            GateRef argsLength = Int32(4);
            NewObjectStubBuilder newBuilder(this);
            GateRef argList = newBuilder.NewTaggedArray(glue, argsLength);
            Label loopHead(env);
            Label next(env);
            Label loopEnd(env);
            Label loopExit(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                BRANCH(Int32LessThan(*k, thisLen), &next, &loopExit);
                Bind(&next);
                {
                    GateRef kValue = FastGetPropertyByIndex(glue, thisValue, *k, GetObjectType(LoadHClass(thisValue)));
                    // 0 : the first position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(0), *accumulator);
                    // 1 : the second position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(1), kValue);
                    // 2 : the third position
                    SetValueToTaggedArray(VariableType::INT32(), glue, argList, Int32(2), IntToTaggedInt(*k));
                    // 3 : the fourth position
                    SetValueToTaggedArray(VariableType::JS_ANY(), glue, argList, Int32(3), thisValue);
                    GateRef argv = PtrAdd(argList, IntPtr(TaggedArray::DATA_OFFSET));
                    JSCallArgs callArgs(JSCallMode::CALL_THIS_ARGV_WITH_RETURN);
                    callArgs.callThisArgvWithReturnArgs = { argsLength, argv, Undefined() };
                    CallStubBuilder callBuilder(this, glue, callbackFnHandle, argsLength, 0, nullptr,
                        Circuit::NullGate(), callArgs);
                    GateRef callResult = callBuilder.JSCallDispatch();
                    Label hasException1(env);
                    Label notHasException1(env);
                    BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
                    Bind(&hasException1);
                    {
                        result->WriteVariable(Exception());
                        Jump(exit);
                    }
                    Bind(&notHasException1);
                    {
                        accumulator = callResult;
                        Jump(&loopEnd);
                    }
                }
            }
            Bind(&loopEnd);
            k = Int32Add(*k, Int32(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            result->WriteVariable(*accumulator);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::Every(GateRef glue, GateRef thisValue,  GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label isHeapObject(env);
    Label typedArray(env);
    Label defaultConstr(env);
    Label notDetached(env);

    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);

    Label arg0HeapObject(env);
    Label callable(env);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);
    GateRef argHandle = GetCallArg1(numArgs);
    DEFVARIABLE(i, VariableType::INT32(), Int32(0));
    DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
    GateRef thisArrlen = GetArrayLength(thisValue);
    Label loopHead(env);
    Label loopEnd(env);
    Label next(env);
    Label loopExit(env);
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        Label hasException0(env);
        Label notHasException0(env);
        Label hasException1(env);
        Label notHasException1(env);
        Label retValueIsFalse(env);
        BRANCH(Int32LessThan(*i, thisArrlen), &next, &loopExit);
        Bind(&next);
        kValue = FastGetPropertyByIndex(glue, thisValue, *i, GetObjectType(LoadHClass(thisValue)));
        BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
        Bind(&hasException0);
        {
            result->WriteVariable(Exception());
            Jump(exit);
        }
        Bind(&notHasException0);
        {
            GateRef key = IntToTaggedInt(*i);
            JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
            callArgs.callThisArg3WithReturnArgs = { argHandle, *kValue, key, thisValue };
            CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
                Circuit::NullGate(), callArgs);
            GateRef retValue = callBuilder.JSCallDispatch();
            BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
            Bind(&hasException1);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException1);
            {
                BRANCH(TaggedIsFalse(FastToBoolean(retValue)), &retValueIsFalse, &loopEnd);
                Bind(&retValueIsFalse);
                {
                    result->WriteVariable(TaggedFalse());
                    Jump(exit);
                }
            }
        }
    }
    Bind(&loopEnd);
    i = Int32Add(*i, Int32(1));
    LoopEnd(&loopHead);
    Bind(&loopExit);
    result->WriteVariable(TaggedTrue());
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::Some(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label thisExists(env);
    Label notDetached(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);

    Label arg0HeapObject(env);
    Label callable(env);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);
    {
        GateRef argHandle = GetCallArg1(numArgs);
        DEFVARIABLE(i, VariableType::INT64(), Int64(0));
        DEFVARIABLE(thisArrLen, VariableType::INT64(), ZExtInt32ToInt64(GetArrayLength(thisValue)));
        DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
        Label loopHead(env);
        Label loopEnd(env);
        Label next(env);
        Label loopExit(env);
        Jump(&loopHead);
        LoopBegin(&loopHead);
        {
            Label hasException0(env);
            Label notHasException0(env);
            Label callDispatch(env);
            Label hasException1(env);
            Label notHasException1(env);
            BRANCH(Int64LessThan(*i, *thisArrLen), &next, &loopExit);
            Bind(&next);
            kValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*i),
                GetObjectType(LoadHClass(thisValue)));
            BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
            Bind(&hasException0);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException0);
            {
                BRANCH(TaggedIsHole(*kValue), &loopEnd, &callDispatch);
            }
            Bind(&callDispatch);
            {
                GateRef key = Int64ToTaggedInt(*i);
                JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
                callArgs.callThisArg3WithReturnArgs = { argHandle, *kValue, key, thisValue };
                CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
                    Circuit::NullGate(), callArgs);
                GateRef retValue = callBuilder.JSCallDispatch();
                BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
                Bind(&hasException1);
                {
                    result->WriteVariable(Exception());
                    Jump(exit);
                }
                Bind(&notHasException1);
                {
                    Label retValueIsTrue(env);
                    BRANCH(TaggedIsTrue(FastToBoolean(retValue)), &retValueIsTrue, &loopEnd);
                    Bind(&retValueIsTrue);
                    {
                        result->WriteVariable(TaggedTrue());
                        Jump(exit);
                    }
                }
            }
        }
        Bind(&loopEnd);
        i = Int64Add(*i, Int64(1));
        LoopEnd(&loopHead);
        Bind(&loopExit);
        result->WriteVariable(TaggedFalse());
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label notDetached(env);
    Label isEcmaObject(env);
    Label isFastTypedArray(env);
    Label defaultConstr(env);
    Label prototypeIsEcmaObj(env);
    Label isProtoChangeMarker(env);
    Label accessorNotChanged(env);
    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(IsEcmaObject(thisValue), &isEcmaObject, slowPath);
    Bind(&isEcmaObject);
    GateRef arrayType = GetObjectType(LoadHClass(thisValue));
    BRANCH(IsFastTypeArray(arrayType), &isFastTypedArray, slowPath);
    Bind(&isFastTypedArray);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef prototype = GetPrototypeFromHClass(LoadHClass(thisValue));
    BRANCH(IsEcmaObject(prototype), &prototypeIsEcmaObj, slowPath);
    Bind(&prototypeIsEcmaObj);
    GateRef marker = GetProtoChangeMarkerFromHClass(LoadHClass(prototype));
    BRANCH(TaggedIsProtoChangeMarker(marker), &isProtoChangeMarker, slowPath);
    Bind(&isProtoChangeMarker);
    BRANCH(GetAccessorHasChanged(marker), slowPath, &accessorNotChanged);
    Bind(&accessorNotChanged);

    Label arg0HeapObject(env);
    Label callable(env);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    {
        BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
        Bind(&callable);
        {
            GateRef argHandle = GetCallArg1(numArgs);
            GateRef thisLen = GetArrayLength(thisValue);
            BuiltinsArrayStubBuilder arrayStubBuilder(this);
            GateRef kept = arrayStubBuilder.NewArray(glue, ZExtInt32ToInt64(thisLen));
            DEFVARIABLE(i, VariableType::INT32(), Int32(0));
            DEFVARIABLE(newArrayLen, VariableType::INT32(), Int32(0));
            Label loopHead(env);
            Label loopEnd(env);
            Label next(env);
            Label loopExit(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                Label hasException0(env);
                Label notHasException0(env);
                Label hasException1(env);
                Label notHasException1(env);
                Label retValueIsTrue(env);
                BRANCH(Int32LessThan(*i, thisLen), &next, &loopExit);
                Bind(&next);
                {
                    GateRef kValue = FastGetPropertyByIndex(glue, thisValue, *i, arrayType);
                    BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
                    Bind(&hasException0);
                    {
                        result->WriteVariable(Exception());
                        Jump(exit);
                    }
                    Bind(&notHasException0);
                    {
                        GateRef key = IntToTaggedInt(*i);
                        JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
                        callArgs.callThisArg3WithReturnArgs = { argHandle, kValue, key, thisValue };
                        CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0,
                            nullptr, Circuit::NullGate(), callArgs);
                        GateRef retValue = callBuilder.JSCallDispatch();
                        BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
                        Bind(&hasException1);
                        {
                            result->WriteVariable(Exception());
                            Jump(exit);
                        }
                        Bind(&notHasException1);
                        {
                            BRANCH(TaggedIsTrue(FastToBoolean(retValue)), &retValueIsTrue, &loopEnd);
                            Bind(&retValueIsTrue);
                            {
                                arrayStubBuilder.SetValueWithElementsKind(glue, kept, kValue, *newArrayLen,
                                    Boolean(true), Int32(Elements::ToUint(ElementsKind::NONE)));
                                newArrayLen = Int32Add(*newArrayLen, Int32(1));
                                Jump(&loopEnd);
                            }
                        }
                    }
                }
            }
            Bind(&loopEnd);
            i = Int32Add(*i, Int32(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            Label hasException2(env);
            Label notHasException2(env);
            NewObjectStubBuilder newBuilder(this);
            newBuilder.SetParameters(glue, 0);
            GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen));
            BRANCH(HasPendingException(glue), &hasException2, &notHasException2);
            Bind(&hasException2);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException2);
            i = Int32(0);
            Label loopHead2(env);
            Label loopEnd2(env);
            Label next2(env);
            Label loopExit2(env);
            Jump(&loopHead2);
            LoopBegin(&loopHead2);
            {
                BRANCH(Int32LessThan(*i, *newArrayLen), &next2, &loopExit2);
                Bind(&next2);
                {
                    GateRef kValue = arrayStubBuilder.GetTaggedValueWithElementsKind(glue, kept, *i);
                    StoreTypedArrayElement(glue, newArray, ZExtInt32ToInt64(*i), kValue, arrayType);
                    Jump(&loopEnd2);
                }
            }
            Bind(&loopEnd2);
            i = Int32Add(*i, Int32(1));
            LoopEnd(&loopHead2);
            Bind(&loopExit2);

            result->WriteVariable(newArray);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::Slice(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label isEcmaObject(env);
    Label isFastTypedArray(env);
    Label defaultConstr(env);
    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(IsEcmaObject(thisValue), &isEcmaObject, slowPath);
    Bind(&isEcmaObject);
    GateRef arrayType = GetObjectType(LoadHClass(thisValue));
    BRANCH(IsFastTypeArray(arrayType), &isFastTypedArray, slowPath);
    Bind(&isFastTypedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);

    DEFVARIABLE(startPos, VariableType::INT64(), Int64(0));
    DEFVARIABLE(endPos, VariableType::INT64(), Int64(0));
    DEFVARIABLE(newArrayLen, VariableType::INT64(), Int64(0));
    Label startTagExists(env);
    Label startTagIsInt(env);
    Label afterCallArg(env);
    Label endTagExists(env);
    Label endTagIsInt(env);
    Label adjustArrLen(env);
    Label newTypedArray(env);
    Label writeVariable(env);
    Label copyBuffer(env);
    Label hasException0(env);
    Label notHasException0(env);
    GateRef thisLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    BRANCH(Int64GreaterThanOrEqual(IntPtr(0), numArgs), slowPath, &startTagExists);
    Bind(&startTagExists);
    {
        GateRef startTag = GetCallArg0(numArgs);
        BRANCH(TaggedIsInt(startTag), &startTagIsInt, slowPath);
        Bind(&startTagIsInt);
        {
            startPos = SExtInt32ToInt64(TaggedGetInt(startTag));
            endPos = thisLen;
            BRANCH(Int64GreaterThanOrEqual(IntPtr(1), numArgs), &afterCallArg, &endTagExists);
            Bind(&endTagExists);
            {
                GateRef endTag = GetCallArg1(numArgs);
                BRANCH(TaggedIsInt(endTag), &endTagIsInt, slowPath);
                Bind(&endTagIsInt);
                {
                    endPos = SExtInt32ToInt64(TaggedGetInt(endTag));
                    Jump(&afterCallArg);
                }
            }
            Bind(&afterCallArg);
            {
                startPos = CalculatePositionWithLength(*startPos, thisLen);
                endPos = CalculatePositionWithLength(*endPos, thisLen);
                BRANCH(Int64GreaterThan(*endPos, *startPos), &adjustArrLen, &newTypedArray);
                Bind(&adjustArrLen);
                {
                    newArrayLen = Int64Sub(*endPos, *startPos);
                    Jump(&newTypedArray);
                }
            }
        }
    }
    Bind(&newTypedArray);
    {
        NewObjectStubBuilder newBuilder(this);
        newBuilder.SetParameters(glue, 0);
        GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen));
        BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
        Bind(&hasException0);
        {
            result->WriteVariable(Exception());
            Jump(exit);
        }
        Bind(&notHasException0);
        BRANCH(Int32Equal(TruncInt64ToInt32(*newArrayLen), Int32(0)), &writeVariable, &copyBuffer);
        Bind(&copyBuffer);
        {
            CallNGCRuntime(glue, RTSTUB_ID(CopyTypedArrayBuffer),
                           { glue, thisValue, newArray, TruncInt64ToInt32(*startPos), Int32(0),
                             TruncInt64ToInt32(*newArrayLen) });
            Jump(&writeVariable);
        }
        Bind(&writeVariable);
        {
            result->WriteVariable(newArray);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::SubArray(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label isNotZero(env);
    DEFVARIABLE(beginIndex, VariableType::INT32(), Int32(0));
    DEFVARIABLE(endIndex, VariableType::INT32(), Int32(0));
    DEFVARIABLE(newLength, VariableType::INT32(), Int32(0));

    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);

    GateRef objHclass = LoadHClass(thisValue);
    Label defaultConstructor(env);
    BRANCH(HasConstructorByHClass(objHclass), slowPath, &defaultConstructor);
    Bind(&defaultConstructor);
    GateRef arrayLen = GetArrayLength(thisValue);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    Label offHeap(env);
    BRANCH(LogicOrBuilder(env).Or(IsJSObjectType(buffer, JSType::JS_ARRAY_BUFFER))
        .Or(IsJSObjectType(buffer, JSType::JS_SHARED_ARRAY_BUFFER)).Done(),
        &offHeap, slowPath);
    Bind(&offHeap);
    Label notDetached(env);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);

    Label intIndex(env);
    GateRef relativeBegin = GetCallArg0(numArgs);
    GateRef end = GetCallArg1(numArgs);
    BRANCH(TaggedIsInt(relativeBegin), &intIndex, slowPath);
    Bind(&intIndex);
    GateRef relativeBeginInt = GetInt32OfTInt(relativeBegin);
    beginIndex = CalArrayRelativePos(relativeBeginInt, arrayLen);

    Label undefEnd(env);
    Label defEnd(env);
    Label calNewLength(env);
    Label newArray(env);
    BRANCH(TaggedIsUndefined(end), &undefEnd, &defEnd);
    Bind(&undefEnd);
    {
        endIndex = arrayLen;
        Jump(&calNewLength);
    }
    Bind(&defEnd);
    {
        Label intEnd(env);
        BRANCH(TaggedIsInt(end), &intEnd, slowPath);
        Bind(&intEnd);
        {
            GateRef endVal = GetInt32OfTInt(end);
            endIndex = CalArrayRelativePos(endVal, arrayLen);
            Jump(&calNewLength);
        }
    }
    Bind(&calNewLength);
    {
        GateRef diffLen = Int32Sub(*endIndex, *beginIndex);
        Label diffLargeZero(env);
        BRANCH(Int32GreaterThan(diffLen, Int32(0)), &diffLargeZero, &newArray);
        Bind(&diffLargeZero);
        {
            newLength = diffLen;
            Jump(&newArray);
        }
    }
    Bind(&newArray);
    GateRef oldByteLength = Load(VariableType::INT32(), thisValue, IntPtr(JSTypedArray::BYTE_LENGTH_OFFSET));
    BRANCH(Int32Equal(arrayLen, Int32(0)), slowPath, &isNotZero);
    Bind(&isNotZero);
    GateRef elementSize = Int32Div(oldByteLength, arrayLen);
    NewObjectStubBuilder newBuilder(this);
    *result = newBuilder.NewTaggedSubArray(glue, thisValue, elementSize, *newLength, *beginIndex, objHclass, buffer);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::With(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    DEFVARIABLE(relativeIndex, VariableType::INT64(), Int64(0));
    DEFVARIABLE(actualIndex, VariableType::INT64(), Int64(0));
    Label isHeapObject(env);
    Label typedArray(env);
    Label notCOWArray(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(IsJsCOWArray(thisValue), slowPath, &notCOWArray);
    Bind(&notCOWArray);
    GateRef thisLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    GateRef index = GetCallArg0(numArgs);
    Label taggedIsInt(env);
    BRANCH(TaggedIsInt(index), &taggedIsInt, slowPath);
    Bind(&taggedIsInt);
    relativeIndex = GetInt64OfTInt(index);
    DEFVARIABLE(value, VariableType::JS_ANY(), Undefined());
    Label indexGreaterOrEqualZero(env);
    Label indexLessZero(env);
    Label next(env);
    Label notOutOfRange(env);
    value = GetCallArg1(numArgs);
    GateRef hclass = LoadHClass(thisValue);
    GateRef jsType = GetObjectType(hclass);
    NewObjectStubBuilder newBuilder(this);
    newBuilder.SetParameters(glue, 0);
    GateRef newArray = newBuilder.NewTypedArraySameType(glue, thisValue, jsType, TruncInt64ToInt32(thisLen));
    Label hasException0(env);
    Label notHasException0(env);
    BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
    Bind(&hasException0);
    {
        result->WriteVariable(Exception());
        Jump(exit);
    }
    Bind(&notHasException0);
    CallNGCRuntime(glue, RTSTUB_ID(CopyTypedArrayBuffer),
                   { glue, thisValue, newArray, Int32(0), Int32(0), TruncInt64ToInt32(thisLen) });
    BRANCH(Int64GreaterThanOrEqual(*relativeIndex, Int64(0)), &indexGreaterOrEqualZero, &indexLessZero);
    Bind(&indexGreaterOrEqualZero);
    {
        actualIndex = *relativeIndex;
        Jump(&next);
    }
    Bind(&indexLessZero);
    {
        actualIndex = Int64Add(thisLen, *relativeIndex);
        Jump(&next);
    }
    Bind(&next);
    {
        BRANCH(BitOr(Int64GreaterThanOrEqual(*actualIndex, thisLen), Int64LessThan(*actualIndex, Int64(0))),
            slowPath, &notOutOfRange);
        Bind(&notOutOfRange);
        {
            DEFVARIABLE(k, VariableType::INT64(), Int64(0));
            Label loopHead(env);
            Label loopEnd(env);
            Label loopExit(env);
            Label loopNext(env);
            Label replaceIndex(env);
            Jump(&loopHead);
            LoopBegin(&loopHead);
            {
                BRANCH(Int64LessThan(*k, thisLen), &loopNext, &loopExit);
                Bind(&loopNext);
                BRANCH(Int64Equal(*k, *actualIndex), &replaceIndex, &loopEnd);
                Bind(&replaceIndex);
                {
                    StoreTypedArrayElement(glue, newArray, *k, *value, jsType);
                    Jump(&loopEnd);
                }
            }
            Bind(&loopEnd);
            k = Int64Add(*k, Int64(1));
            LoopEnd(&loopHead);
            Bind(&loopExit);
            result->WriteVariable(newArray);
            Jump(exit);
        }
    }
}

void BuiltinsTypedArrayStubBuilder::GetByteLength([[maybe_unused]] GateRef glue, GateRef thisValue,
    [[maybe_unused]] GateRef numArgs, Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label Detached(env);
    Label notDetached(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), &Detached, &notDetached);
    Bind(&Detached);
    {
        *result = IntToTaggedPtr(Int32(0));
        Jump(exit);
    }
    Bind(&notDetached);
    {
        *result = IntToTaggedPtr(GetArrayLength(thisValue));
    }
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::DoSort(
    GateRef glue, GateRef receiver, Variable* result, Label* exit, Label* slowPath)
{
    auto env = GetEnvironment();
    Label entry(env);
    Label lenGreaterZero(env);
    env->SubCfgEntry(&entry);
    GateRef len = ZExtInt32ToInt64(GetArrayLength(receiver));
    DEFVARIABLE(i, VariableType::INT64(), Int64(1));
    DEFVARIABLE(presentValue, VariableType::JS_ANY(), Undefined());
    DEFVARIABLE(middleValue, VariableType::JS_ANY(), Undefined());
    DEFVARIABLE(previousValue, VariableType::JS_ANY(), Undefined());
    Label loopHead(env);
    Label loopEnd(env);
    Label loopNext(env);
    Label loopExit(env);
    Label isNumber(env);
    Label hasException0(env);
    Label notHasException0(env);

    GateRef jsType = GetObjectType(LoadHClass(receiver));
    presentValue = FastGetPropertyByIndex(glue, receiver, Int32(0), jsType);
    BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
    Bind(&hasException0);
    {
        result->WriteVariable(Exception());
        Jump(exit);
    }
    Bind(&notHasException0);
    {
        BRANCH(TaggedIsNumber(*presentValue), &isNumber, slowPath);
        Bind(&isNumber);
        BRANCH(Int64GreaterThan(len, Int64(0)), &lenGreaterZero, slowPath);
        Bind(&lenGreaterZero);

        GateRef isIntOrNot = TaggedIsInt(*presentValue);
        GateRef isUint32 = Int32Equal(jsType, Int32(static_cast<int32_t>(JSType::JS_UINT32_ARRAY)));

        Jump(&loopHead);
        LoopBegin(&loopHead);
        {
            BRANCH(Int64LessThan(*i, len), &loopNext, &loopExit);
            Bind(&loopNext);

            Label hasException1(env);
            Label notHasException1(env);
            DEFVARIABLE(beginIndex, VariableType::INT64(), Int64(0));
            DEFVARIABLE(endIndex, VariableType::INT64(), *i);
            presentValue = FastGetPropertyByIndex(glue, receiver, TruncInt64ToInt32(*i), jsType);
            BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
            Bind(&hasException1);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException1);
            {
                Label loopHead1(env);
                Label loopEnd1(env);
                Label loopNext1(env);
                Label loopExit1(env);

                Jump(&loopHead1);
                LoopBegin(&loopHead1);
                {
                    BRANCH(Int64LessThan(*beginIndex, *endIndex), &loopNext1, &loopExit1);
                    Bind(&loopNext1);
                    Label hasException2(env);
                    Label notHasException2(env);
                    GateRef sum = Int64Add(*beginIndex, *endIndex);
                    GateRef middleIndex = Int64Div(sum, Int64(2));
                    middleValue = FastGetPropertyByIndex(glue, receiver, TruncInt64ToInt32(middleIndex), jsType);
                    BRANCH(HasPendingException(glue), &hasException2, &notHasException2);
                    Bind(&hasException2);
                    {
                        result->WriteVariable(Exception());
                        Jump(exit);
                    }
                    Bind(&notHasException2);
                    {
                        Label goSort(env);
                        Label isFloat(env);
                        Label isInt(env);
                        Label uint32Compare(env);
                        Label notUint32(env);
                        DEFVARIABLE(compareResult, VariableType::INT32(), Int32(0));
                        BRANCH(isUint32, &uint32Compare, &notUint32);
                        Bind(&notUint32);
                        BRANCH(isIntOrNot, &isInt, &isFloat);

                        Bind(&uint32Compare);
                        {
                            DEFVARIABLE(middleValueInt64, VariableType::INT64(), Int64(0));
                            DEFVARIABLE(presentValueInt64, VariableType::INT64(), Int64(0));
                            middleValueInt64 = GetInt64OfTInt(*middleValue);
                            presentValueInt64 = GetInt64OfTInt(*presentValue);

                            Label intGreater(env);
                            Label intEqualOrNot(env);
                            Label intEqual(env);
                            Label intLess(env);

                            BRANCH(
                                Int64GreaterThan(*middleValueInt64, *presentValueInt64), &intGreater, &intEqualOrNot);
                            Bind(&intGreater);
                            {
                                compareResult = Int32(1);
                                Jump(&goSort);
                            }
                            Bind(&intEqualOrNot);
                            {
                                BRANCH(Int64Equal(*middleValueInt64, *presentValueInt64), &intEqual, &intLess);
                                Bind(&intEqual);
                                {
                                    compareResult = Int32(0);
                                    Jump(&goSort);
                                }
                                Bind(&intLess);
                                {
                                    compareResult = Int32(-1);
                                    Jump(&goSort);
                                }
                            }
                        }

                        Bind(&isInt);
                        {
                            DEFVARIABLE(middleValueInt32, VariableType::INT32(), Int32(0));
                            DEFVARIABLE(presentValueInt32, VariableType::INT32(), Int32(0));
                            middleValueInt32 = GetInt32OfTInt(*middleValue);
                            presentValueInt32 = GetInt32OfTInt(*presentValue);

                            Label intGreater(env);
                            Label intEqualOrNot(env);
                            Label intEqual(env);
                            Label intLess(env);

                            BRANCH(
                                Int32GreaterThan(*middleValueInt32, *presentValueInt32), &intGreater, &intEqualOrNot);
                            Bind(&intGreater);
                            {
                                compareResult = Int32(1);
                                Jump(&goSort);
                            }

                            Bind(&intEqualOrNot);
                            {
                                BRANCH(Int32Equal(*middleValueInt32, *presentValueInt32), &intEqual, &intLess);
                                Bind(&intEqual);
                                {
                                    compareResult = Int32(0);
                                    Jump(&goSort);
                                }
                                Bind(&intLess);
                                {
                                    compareResult = Int32(-1);
                                    Jump(&goSort);
                                }
                            }
                        }
                        Bind(&isFloat);
                        {
                            Label floatLess(env);
                            Label floatEqual(env);
                            Label floatGreater(env);
                            Label floatEqualOrNot(env);
                            Label float32EqualOrNot(env);
                            Label midIsNotNAN(env);
                            Label presentIsNotNAN(env);

                            DEFVARIABLE(middleValueFloat64, VariableType::FLOAT64(), Double(0));
                            DEFVARIABLE(presentValueFloat64, VariableType::FLOAT64(), Double(0));

                            middleValueFloat64 = GetDoubleOfTDouble(*middleValue);
                            presentValueFloat64 = GetDoubleOfTDouble(*presentValue);

                            BRANCH(DoubleIsNAN(*presentValueFloat64), &floatLess, &presentIsNotNAN);
                            Bind(&presentIsNotNAN);
                            BRANCH(DoubleIsNAN(*middleValueFloat64), &floatGreater, &midIsNotNAN);
                            Bind(&midIsNotNAN);

                            BRANCH(DoubleLessThan(*middleValueFloat64, *presentValueFloat64), &floatLess,
                                &floatEqualOrNot);
                            Bind(&floatLess);
                            {
                                compareResult = Int32(-1);
                                Jump(&goSort);
                            }

                            Bind(&floatEqualOrNot);
                            {
                                BRANCH(
                                    DoubleEqual(*middleValueFloat64, *presentValueFloat64), &floatEqual, &floatGreater);
                                Bind(&floatEqual);
                                {
                                    Label mIsPositive0(env);
                                    Label mIsNotPositive0(env);
                                    GateRef valueEqual = Equal(*middleValue, DoubleToTaggedDoublePtr(Double(0.0)));
                                    BRANCH(valueEqual, &mIsPositive0, &mIsNotPositive0);
                                    Bind(&mIsPositive0);
                                    {
                                        valueEqual = Equal(*presentValue, DoubleToTaggedDoublePtr(Double(-0.0)));
                                        BRANCH(valueEqual, &floatGreater, &mIsNotPositive0);
                                    }
                                    Bind(&mIsNotPositive0);
                                    {
                                        compareResult = Int32(0);
                                        Jump(&goSort);
                                    }
                                }

                                Bind(&floatGreater);
                                {
                                    compareResult = Int32(1);
                                    Jump(&goSort);
                                }
                            }
                        }
                        Bind(&goSort);
                        {
                            Label less0(env);
                            Label greater0(env);
                            BRANCH(Int32LessThanOrEqual(*compareResult, Int32(0)), &less0, &greater0);
                            Bind(&greater0);
                            {
                                endIndex = middleIndex;
                                Jump(&loopEnd1);
                            }
                            Bind(&less0);
                            {
                                beginIndex = middleIndex;
                                beginIndex = Int64Add(*beginIndex, Int64(1));
                                Jump(&loopEnd1);
                            }
                        }
                    }
                }
                Bind(&loopEnd1);
                LoopEnd(&loopHead1);
                Bind(&loopExit1);

                Label shouldCopy(env);
                GateRef isGreater0 = Int64GreaterThanOrEqual(*endIndex, Int64(0));
                GateRef isLessI = Int64LessThan(*endIndex, *i);
                BRANCH(BitAnd(isGreater0, isLessI), &shouldCopy, &loopEnd);
                Bind(&shouldCopy);
                {
                    DEFVARIABLE(j, VariableType::INT64(), *i);
                    Label loopHead2(env);
                    Label loopEnd2(env);
                    Label loopNext2(env);
                    Label loopExit2(env);
                    Jump(&loopHead2);
                    LoopBegin(&loopHead2);
                    {
                        BRANCH(Int64GreaterThan(*j, *endIndex), &loopNext2, &loopExit2);
                        Bind(&loopNext2);
                        Label hasException3(env);
                        Label notHasException3(env);
                        previousValue = FastGetPropertyByIndex(glue, receiver,
                            TruncInt64ToInt32(Int64Sub(*j, Int64(1))), jsType);
                        BRANCH(HasPendingException(glue), &hasException3, &notHasException3);
                        Bind(&hasException3);
                        {
                            result->WriteVariable(Exception());
                            Jump(exit);
                        }
                        Bind(&notHasException3);
                        {
                            FastSetPropertyByIndex(glue, *previousValue, receiver, TruncInt64ToInt32(*j), jsType);
                            Jump(&loopEnd2);
                        }
                    }
                    Bind(&loopEnd2);
                    j = Int64Sub(*j, Int64(1));
                    LoopEnd(&loopHead2);
                    Bind(&loopExit2);
                    FastSetPropertyByIndex(glue, *presentValue, receiver, TruncInt64ToInt32(*j), jsType);
                    Jump(&loopEnd);
                }
            }
        }
        Bind(&loopEnd);
        i = Int64Add(*i, Int64(1));
        LoopEnd(&loopHead);
        Bind(&loopExit);
        env->SubCfgExit();
    }
}

void BuiltinsTypedArrayStubBuilder::Sort(
    GateRef glue, GateRef thisValue, GateRef numArgs, Variable* result, Label* exit, Label* slowPath)
{
    auto env = GetEnvironment();
    Label isHeapObject(env);
    Label typedArray(env);
    Label defaultConstr(env);
    Label argUndefined(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsFastTypeArray(GetObjectType(LoadHClass(thisValue))), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsUndefined(callbackFnHandle), &argUndefined, slowPath);
    Bind(&argUndefined);
    Label notDetached(env);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    CallNGCRuntime(glue, RTSTUB_ID(SortTypedArray), {thisValue});
    result->WriteVariable(thisValue);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::GetByteOffset([[maybe_unused]] GateRef glue, GateRef thisValue,
    [[maybe_unused]] GateRef numArgs, Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label Detached(env);
    Label notDetached(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), &Detached, &notDetached);
    Bind(&Detached);
    {
        *result = IntToTaggedPtr(Int32(0));
        Jump(exit);
    }
    Bind(&notDetached);
    {
        *result = IntToTaggedPtr(GetByteOffset(thisValue));
    }
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::Set(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label ecmaObj(env);
    Label typedArrayIsFast(env);

    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsFastTypeArray(GetObjectType(LoadHClass(thisValue))), &typedArrayIsFast, slowPath);
    Bind(&typedArrayIsFast);
    GateRef len = ZExtInt32ToInt64(GetArrayLength(thisValue));
    GateRef arrayType = GetObjectType(LoadHClass(thisValue));
    Label notEmptyArray(env);
    BRANCH(Int64Equal(len, Int64(0)), slowPath, &notEmptyArray);
    Bind(&notEmptyArray);
    DEFVARIABLE(realOffset, VariableType::INT64(), Int64(0));
    DEFVARIABLE(startIndex, VariableType::INT64(), Int64(0));
    Label hasOffset(env);
    Label hasNoOffset(env);
    Label numArgsIsInt(env);
    GateRef fromOffset = GetCallArg1(numArgs);
    BRANCH(TaggedIsUndefinedOrNull(fromOffset), &hasNoOffset, &hasOffset);
    Bind(&hasOffset);
    {
        Label taggedIsInt(env);
        BRANCH(TaggedIsInt(fromOffset), &taggedIsInt, slowPath);
        Bind(&taggedIsInt);
        GateRef fromIndexToTagged = SExtInt32ToInt64(TaggedGetInt(fromOffset));
        Label offsetNotLessZero(env);
        BRANCH(Int64LessThan(fromIndexToTagged, Int64(0)), slowPath, &offsetNotLessZero);
        Bind(&offsetNotLessZero);
        {
            realOffset = fromIndexToTagged;
            Jump(&hasNoOffset);
        }
    }
    Bind(&hasNoOffset);

    Label srcArrayIsEcmaObj(env);
    Label srcArrayIsTypedArray(env);
    Label srcArrayIsJsArray(env);
    GateRef srcArray = GetCallArg0(numArgs);
    BRANCH(IsEcmaObject(srcArray), &srcArrayIsEcmaObj, slowPath);
    Bind(&srcArrayIsEcmaObj);
    BRANCH(IsTypedArray(srcArray), &srcArrayIsTypedArray, slowPath);
    Bind(&srcArrayIsTypedArray);
    {
        GateRef srcType = GetObjectType(LoadHClass(srcArray));
        Label isFastTypeArray(env);
        BRANCH(IsFastTypeArray(srcType), &isFastTypeArray, slowPath);
        Bind(&isFastTypeArray);
        Label isNotSameValue(env);
        GateRef targetBuffer = GetViewedArrayBuffer(thisValue);
        GateRef srcBuffer = GetViewedArrayBuffer(srcArray);
        BRANCH(SameValue(glue, targetBuffer, srcBuffer), slowPath, &isNotSameValue);
        Bind(&isNotSameValue);
        Label isNotGreaterThanLen(env);
        GateRef srcLen = ZExtInt32ToInt64(GetArrayLength(srcArray));
        BRANCH(Int64GreaterThan(Int64Add(*realOffset, srcLen), len), slowPath, &isNotGreaterThanLen);
        Bind(&isNotGreaterThanLen);
        {
            Label isSameType(env);
            Label isNotSameType(env);
            BRANCH(Equal(srcType, arrayType), &isSameType, &isNotSameType);
            Bind(&isSameType);
            {
                NewObjectStubBuilder newBuilder(this);
                CallNGCRuntime(glue, RTSTUB_ID(CopyTypedArrayBuffer),
                               { glue, srcArray, thisValue, Int32(0), TruncInt64ToInt32(*realOffset),
                                 TruncInt64ToInt32(srcLen) });
                Jump(exit);
            }
            Bind(&isNotSameType);
            {
                Label loopHead(env);
                Label loopEnd(env);
                Label loopExit(env);
                Label loopNext(env);
                Jump(&loopHead);
                LoopBegin(&loopHead);
                {
                    BRANCH(Int64LessThan(*startIndex, srcLen), &loopNext, &loopExit);
                    Bind(&loopNext);
                    {
                        GateRef srcValue = FastGetPropertyByIndex(glue, srcArray, TruncInt64ToInt32(*startIndex),
                            GetObjectType(LoadHClass(srcArray)));
                        StoreTypedArrayElement(glue, thisValue, *realOffset, srcValue,
                            GetObjectType(LoadHClass(thisValue)));
                        Jump(&loopEnd);
                    }
                }
                Bind(&loopEnd);
                startIndex = Int64Add(*startIndex, Int64(1));
                realOffset = Int64Add(*realOffset, Int64(1));
                LoopEnd(&loopHead);
                Bind(&loopExit);
                result->WriteVariable(Undefined());
                Jump(exit);
            }
        }
    }
}

void BuiltinsTypedArrayStubBuilder::FindIndex(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label typedArray(env);
    Label defaultConstr(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);

    Label arg0HeapObject(env);
    Label callable(env);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);
    result->WriteVariable(IntToTaggedPtr(Int32(-1)));

    GateRef argHandle = GetCallArg1(numArgs);
    DEFVARIABLE(thisArrLen, VariableType::INT64(), ZExtInt32ToInt64(GetArrayLength(thisValue)));
    DEFVARIABLE(j, VariableType::INT32(), Int32(0));
    Label loopHead(env);
    Label loopEnd(env);
    Label next(env);
    Label loopExit(env);
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        thisArrLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
        BRANCH(Int64LessThan(ZExtInt32ToInt64(*j), *thisArrLen), &next, &loopExit);
        Bind(&next);
        {
            Label hasException0(env);
            Label notHasException0(env);
            GateRef kValue = FastGetPropertyByIndex(glue, thisValue, *j, GetObjectType(LoadHClass(thisValue)));
            BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
            Bind(&hasException0);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException0);
            {
                GateRef key = IntToTaggedPtr(*j);
                Label hasException(env);
                Label notHasException(env);
                JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
                callArgs.callThisArg3WithReturnArgs = { argHandle, kValue, key, thisValue };
                CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
                    Circuit::NullGate(), callArgs);
                GateRef retValue = callBuilder.JSCallDispatch();
                BRANCH(TaggedIsException(retValue), &hasException, &notHasException);
                Bind(&hasException);
                {
                    result->WriteVariable(retValue);
                    Jump(exit);
                }
                Bind(&notHasException);
                {
                    Label find(env);
                    BRANCH(TaggedIsTrue(FastToBoolean(retValue)), &find, &loopEnd);
                    Bind(&find);
                    {
                        result->WriteVariable(key);
                        Jump(exit);
                    }
                }
            }
        }
    }
    Bind(&loopEnd);
    thisArrLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    j = Int32Add(*j, Int32(1));
    LoopEnd(&loopHead);
    Bind(&loopExit);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::Entries(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    BuildArrayIterator(glue, thisValue, numArgs, result, exit, slowPath, IterationKind::KEY_AND_VALUE);
}

void BuiltinsTypedArrayStubBuilder::Keys(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    BuildArrayIterator(glue, thisValue, numArgs, result, exit, slowPath, IterationKind::KEY);
}

void BuiltinsTypedArrayStubBuilder::Values(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    BuildArrayIterator(glue, thisValue, numArgs, result, exit, slowPath, IterationKind::VALUE);
}

void BuiltinsTypedArrayStubBuilder::BuildArrayIterator(GateRef glue, GateRef thisValue,
    [[maybe_unused]] GateRef numArgs, Variable *result, Label *exit, Label *slowPath, IterationKind iteratorKind)
{
    auto env = GetEnvironment();

    Label thisExists(env);
    Label isEcmaObject(env);
    Label isTypedArray(env);
    BRANCH(TaggedIsUndefinedOrNullOrHole(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(IsEcmaObject(thisValue), &isEcmaObject, slowPath);
    Bind(&isEcmaObject);
    BRANCH(IsTypedArray(thisValue), &isTypedArray, slowPath);
    Bind(&isTypedArray);

    NewObjectStubBuilder newBuilder(this);
    newBuilder.SetGlue(glue);
    GateRef kind = Int32(static_cast<int32_t>(iteratorKind));
    newBuilder.CreateJSTypedArrayIterator(result, exit, thisValue, kind);
}

void BuiltinsTypedArrayStubBuilder::FindLastIndex(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label isHeapObject(env);
    Label typedArray(env);
    Label arg0HeapObject(env);
    Label callable(env);

    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsTypedArray(thisValue), &typedArray, slowPath);
    Bind(&typedArray);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);

    DEFVARIABLE(i, VariableType::INT64(), Int64Sub(ZExtInt32ToInt64(GetArrayLength(thisValue)), Int64(1)));
    DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
    GateRef argHandle = GetCallArg1(numArgs);
    GateRef hclass = LoadHClass(thisValue);
    GateRef jsType = GetObjectType(hclass);
    Label loopHead(env);
    Label loopEnd(env);
    Label loopNext(env);
    Label loopExit(env);
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        Label hasException(env);
        Label notHasException(env);
        BRANCH(Int64LessThan(*i, Int64(0)), &loopExit, &loopNext);
        Bind(&loopNext);
        kValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*i), jsType);
        GateRef key = Int64ToTaggedInt(*i);
        JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
        callArgs.callThisArg3WithReturnArgs = { argHandle, *kValue, key, thisValue };
        CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
            Circuit::NullGate(), callArgs);
        GateRef retValue = callBuilder.JSCallDispatch();
        BRANCH(HasPendingException(glue), &hasException, &notHasException);
        Bind(&hasException);
        {
            result->WriteVariable(Exception());
            Jump(exit);
        }
        Bind(&notHasException);
        {
            Label find(env);
            BRANCH(TaggedIsTrue(FastToBoolean(retValue)), &find, &loopEnd);
            Bind(&find);
            result->WriteVariable(IntToTaggedPtr(*i));
            Jump(exit);
        }
    }
    Bind(&loopEnd);
    i = Int64Sub(*i, Int64(1));
    LoopEnd(&loopHead);
    Bind(&loopExit);
    result->WriteVariable(IntToTaggedPtr(Int32(-1)));
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::ToSorted(GateRef glue, GateRef thisValue,
    GateRef numArgs, Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label isHeapObject(env);
    Label typedArray(env);
    Label defaultConstr(env);
    Label argUndefined(env);
    Label prototypeIsEcmaObj(env);
    Label isProtoChangeMarker(env);
    Label accessorNotChanged(env);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsFastTypeArray(GetObjectType(LoadHClass(thisValue))), &typedArray, slowPath);
    Bind(&typedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    BRANCH(TaggedIsUndefined(callbackFnHandle), &argUndefined, slowPath);
    Bind(&argUndefined);

    DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
    DEFVARIABLE(i, VariableType::INT64(), Int64(0));
    GateRef jsType = GetObjectType(LoadHClass(thisValue));
    GateRef thisLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    NewObjectStubBuilder newBuilder(this);
    newBuilder.SetParameters(glue, 0);
    GateRef newArray = newBuilder.NewTypedArraySameType(glue, thisValue, jsType, TruncInt64ToInt32(thisLen));
    Label hasException0(env);
    Label notHasException0(env);
    BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
    Bind(&hasException0);
    {
        result->WriteVariable(Exception());
        Jump(exit);
    }
    Bind(&notHasException0);
    CallNGCRuntime(glue, RTSTUB_ID(CopyTypedArrayBuffer),
                   { glue, thisValue, newArray, Int32(0), Int32(0), TruncInt64ToInt32(thisLen) });
    DoSort(glue, newArray, result, exit, slowPath);
    result->WriteVariable(newArray);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::Of(GateRef glue, GateRef thisValue,
    GateRef numArgs, Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label isEcmaObject(env);
    Label isConstructor(env);
    Label notDerived(env);
    Label thisObjIsECmaObject(env);
    Label thisObjIsFastTypedArray(env);
    Label defaultConstr(env);
    Label numArgsInRange(env);
    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(IsEcmaObject(thisValue), &isEcmaObject, slowPath);
    Bind(&isEcmaObject);
    BRANCH(IsConstructor(thisValue), &isConstructor, slowPath);
    Bind(&isConstructor);
    BRANCH(IsDerived(thisValue), slowPath, &notDerived);
    Bind(&notDerived);
    // 3: maximum of numArgs
    BRANCH(Int32LessThanOrEqual(TruncPtrToInt32(numArgs), Int32(3)), &numArgsInRange, slowPath);
    Bind(&numArgsInRange);

    DEFVARIABLE(newArrayLen, VariableType::INT32(), TruncPtrToInt32(numArgs));
    NewObjectStubBuilder newBuilder(this);
    newBuilder.SetParameters(glue, 0);
    GateRef thisObj = newBuilder.NewTypedArrayFromCtor(glue, thisValue, *newArrayLen, slowPath);
    GateRef arrayType = GetObjectType(LoadHClass(thisObj));

    BRANCH(IsEcmaObject(thisObj), &thisObjIsECmaObject, slowPath);
    Bind(&thisObjIsECmaObject);
    BRANCH(IsFastTypeArray(arrayType), &thisObjIsFastTypedArray, slowPath);
    Bind(&thisObjIsFastTypedArray);
    BRANCH(HasConstructor(thisObj), slowPath, &defaultConstr);
    Bind(&defaultConstr);

    DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
    Label firstArg(env);
    Label secondArg(env);
    Label thirdArg(env);
    Label writeResult(env);
    // 1: first element
    BRANCH(Int32LessThanOrEqual(Int32(1), *newArrayLen), &firstArg, &writeResult);
    Bind(&firstArg);
    {
        auto checkValueValid = [this, env](GateRef value) -> GateRef {
            return LogicOrBuilder(env).Or(TaggedIsUndefined(value)).Or(TaggedIsNumber(value))
                .Or(TaggedIsString(value)).Done();
        };
        Label setValue0(env);
        Label hasException0(env);
        Label notHasException0(env);
        kValue = GetCallArg0(numArgs);
        BRANCH(checkValueValid(*kValue), &setValue0, slowPath);
        Bind(&setValue0);
        // 0: first element in newArray
        FastSetPropertyByIndex(glue, *kValue, thisObj, Int32(0), arrayType);
        BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
        Bind(&hasException0);
        {
            result->WriteVariable(Exception());
            Jump(exit);
        }
        Bind(&notHasException0);
        // 2: second element
        BRANCH(Int32LessThanOrEqual(Int32(2), *newArrayLen), &secondArg, &writeResult);
        Bind(&secondArg);
        {
            Label setValue1(env);
            Label hasException1(env);
            Label notHasException1(env);
            kValue = GetCallArg1(numArgs);
            BRANCH(checkValueValid(*kValue), &setValue1, slowPath);
            Bind(&setValue1);
            // 1: second element in newArray
            FastSetPropertyByIndex(glue, *kValue, thisObj, Int32(1), arrayType);
            BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
            Bind(&hasException1);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException1);
            // 3: third element
            BRANCH(Int32LessThanOrEqual(Int32(3), *newArrayLen), &thirdArg, &writeResult);
            Bind(&thirdArg);
            {
                Label setValue2(env);
                Label hasException2(env);
                kValue = GetCallArg2(numArgs);
                BRANCH(checkValueValid(*kValue), &setValue2, slowPath);
                Bind(&setValue2);
                // 2: third element in newArray
                FastSetPropertyByIndex(glue, *kValue, thisObj, Int32(2), arrayType);
                BRANCH(HasPendingException(glue), &hasException2, &writeResult);
                Bind(&hasException2);
                {
                    result->WriteVariable(Exception());
                    Jump(exit);
                }
            }
        }
    }

    Bind(&writeResult);
    {
        result->WriteVariable(thisObj);
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef thisValue, GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label thisExists(env);
    Label isHeapObject(env);
    Label defaultConstr(env);
    Label typedArrayIsFast(env);
    Label prototypeIsEcmaObj(env);
    Label isProtoChangeMarker(env);
    Label accessorNotChanged(env);
    Label notDetached(env);
    BRANCH(TaggedIsUndefinedOrNull(thisValue), slowPath, &thisExists);
    Bind(&thisExists);
    BRANCH(TaggedIsHeapObject(thisValue), &isHeapObject, slowPath);
    Bind(&isHeapObject);
    BRANCH(IsFastTypeArray(GetObjectType(LoadHClass(thisValue))), &typedArrayIsFast, slowPath);
    Bind(&typedArrayIsFast);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);
    GateRef buffer = GetViewedArrayBuffer(thisValue);
    BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetached);
    Bind(&notDetached);
    GateRef prototype = GetPrototypeFromHClass(LoadHClass(thisValue));
    BRANCH(IsEcmaObject(prototype), &prototypeIsEcmaObj, slowPath);
    Bind(&prototypeIsEcmaObj);
    GateRef marker = GetProtoChangeMarkerFromHClass(LoadHClass(prototype));
    BRANCH(TaggedIsProtoChangeMarker(marker), &isProtoChangeMarker, slowPath);
    Bind(&isProtoChangeMarker);
    BRANCH(GetAccessorHasChanged(marker), slowPath, &accessorNotChanged);
    Bind(&accessorNotChanged);
    Label arg0HeapObject(env);
    Label callable(env);
    Label next(env);
    GateRef thisLen = ZExtInt32ToInt64(GetArrayLength(thisValue));
    GateRef callbackFnHandle = GetCallArg0(numArgs);
    GateRef jsType = GetObjectType(LoadHClass(thisValue));
    BRANCH(TaggedIsHeapObject(callbackFnHandle), &arg0HeapObject, slowPath);
    Bind(&arg0HeapObject);
    BRANCH(IsCallable(callbackFnHandle), &callable, slowPath);
    Bind(&callable);
    GateRef argHandle = GetCallArg1(numArgs);
    Jump(&next);
    Bind(&next);
    {
        DEFVARIABLE(kValue, VariableType::JS_ANY(), Hole());
        DEFVARIABLE(i, VariableType::INT64(), Int64(0));
        NewObjectStubBuilder newBuilder(this);
        newBuilder.SetParameters(glue, 0);
        GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, jsType, TruncInt64ToInt32(thisLen));
        GateRef newArrayType = GetObjectType(LoadHClass(newArray));
        Label loopHead(env);
        Label loopEnd(env);
        Label loopNext(env);
        Label loopExit(env);
        Jump(&loopHead);
        LoopBegin(&loopHead);
        {
            Label hasException1(env);
            Label notHasException1(env);
            BRANCH(Int64LessThan(*i, thisLen), &loopNext, &loopExit);
            Bind(&loopNext);
            kValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*i), newArrayType);
            GateRef key = Int64ToTaggedInt(*i);
            JSCallArgs callArgs(JSCallMode::CALL_THIS_ARG3_WITH_RETURN);
            callArgs.callThisArg3WithReturnArgs = { argHandle, *kValue, key, thisValue };
            CallStubBuilder callBuilder(this, glue, callbackFnHandle, Int32(NUM_MANDATORY_JSFUNC_ARGS), 0, nullptr,
                Circuit::NullGate(), callArgs);
            GateRef retValue = callBuilder.JSCallDispatch();
            BRANCH(HasPendingException(glue), &hasException1, &notHasException1);
            Bind(&hasException1);
            result->WriteVariable(Exception());
            Jump(exit);

            Bind(&notHasException1);
            {
                FastSetPropertyByIndex(glue, retValue, newArray, TruncInt64ToInt32(*i), newArrayType);
                Jump(&loopEnd);
            }
        }
        Bind(&loopEnd);
        i = Int64Add(*i, Int64(1));
        LoopEnd(&loopHead);
        Bind(&loopExit);
        result->WriteVariable(newArray);
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::ToReversed(GateRef glue, GateRef thisValue, [[maybe_unused]] GateRef numArgs,
    Variable *result, Label *exit, Label *slowPath)
{
    auto env = GetEnvironment();
    Label ecmaObj(env);
    Label defaultConstr(env);
    Label isFastTypedArray(env);
    BRANCH(IsEcmaObject(thisValue), &ecmaObj, slowPath);
    Bind(&ecmaObj);
    GateRef arrayType = GetObjectType(LoadHClass(thisValue));
    BRANCH(IsFastTypeArray(arrayType), &isFastTypedArray, slowPath);
    Bind(&isFastTypedArray);
    BRANCH(HasConstructor(thisValue), slowPath, &defaultConstr);
    Bind(&defaultConstr);

    DEFVARIABLE(thisArrLen, VariableType::INT64(), ZExtInt32ToInt64(GetArrayLength(thisValue)));
    NewObjectStubBuilder newBuilder(this);
    newBuilder.SetParameters(glue, 0);
    GateRef newArray = newBuilder.NewTypedArraySameType(glue, thisValue, arrayType, TruncInt64ToInt32(*thisArrLen));
    DEFVARIABLE(k, VariableType::INT64(), Int64(0));

    Label loopHead(env);
    Label loopEnd(env);
    Label loopNext(env);
    Label loopExit(env);
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        BRANCH(Int64NotEqual(*k, *thisArrLen), &loopNext, &loopExit);
        Bind(&loopNext);
        {
            DEFVARIABLE(from, VariableType::INT64(), Int64Sub(Int64Sub(*thisArrLen, *k), Int64(1)));
            Label hasException0(env);
            Label hasException1(env);
            Label notHasException0(env);
            GateRef fromValue = FastGetPropertyByIndex(glue, thisValue, TruncInt64ToInt32(*from), arrayType);
            BRANCH(HasPendingException(glue), &hasException0, &notHasException0);
            Bind(&hasException0);
            {
                result->WriteVariable(Exception());
                Jump(exit);
            }
            Bind(&notHasException0);
            {
                FastSetPropertyByIndex(glue, fromValue, newArray, TruncInt64ToInt32(*k), arrayType);
                BRANCH(HasPendingException(glue), &hasException1, &loopEnd);
                Bind(&hasException1);
                {
                    result->WriteVariable(Exception());
                    Jump(exit);
                }
            }
        }
    }
    Bind(&loopEnd);
    k = Int64Add(*k, Int64(1));
    LoopEnd(&loopHead);
    Bind(&loopExit);
    result->WriteVariable(newArray);
    Jump(exit);
}

void BuiltinsTypedArrayStubBuilder::FastSetPropertyByIndex(GateRef glue, GateRef value, GateRef array,
                                                           GateRef index, GateRef jsType)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);
    Label exit(env);
    Label isDetached(env);
    Label notDetached(env);
    Label slowPath(env);
    Label indexIsvalid(env);
    Label notFloatArray(env);
    Label valueIsNumber(env);

    GateRef buffer = GetViewedArrayBuffer(array);
    BRANCH(IsDetachedBuffer(buffer), &isDetached, &notDetached);
    Bind(&isDetached);
    {
        Jump(&slowPath);
    }
    Bind(&notDetached);
    {
        GateRef arrLen = GetArrayLength(array);
        BRANCH(Int32GreaterThanOrEqual(index, arrLen), &exit, &indexIsvalid);
        Bind(&indexIsvalid);
        {
            BRANCH(Int32LessThanOrEqual(jsType, Int32(static_cast<int32_t>(JSType::JS_UINT32_ARRAY))),
                &notFloatArray, &slowPath);
            Bind(&notFloatArray);
            {
                BRANCH(TaggedIsNumber(value), &valueIsNumber, &slowPath);
                Bind(&valueIsNumber);
                {
                    GateRef offset = GetByteOffset(array);
                    SetValueToBuffer(glue, value, buffer, index, offset, jsType, &slowPath);
                    Jump(&exit);
                }
            }
        }
    }
    Bind(&slowPath);
    {
        CallRuntime(glue, RTSTUB_ID(SetTypeArrayPropertyByIndex),
            { array, IntToTaggedInt(index), value, IntToTaggedInt(jsType)});
        Jump(&exit);
    }
    Bind(&exit);
    env->SubCfgExit();
    return;
}

void BuiltinsTypedArrayStubBuilder::SetValueToBuffer(GateRef glue, GateRef value, GateRef buffer, GateRef index,
                                                     GateRef offset, GateRef jsType, Label *slowPath)
{
    auto env = GetEnvironment();
    Label entryPass(env);
    env->SubCfgEntry(&entryPass);

    Label exit(env);
    Label defaultLabel(env);
    Label isInt8(env);
    Label notInt8(env);
    Label isInt16(env);
    Label notInt16(env);
    Label fastPath(env);
    Label valueTypeIsInt(env);
    Label valueTypeIsDouble(env);
    Label labelBuffer[3] = { Label(env), Label(env), Label(env) };
    Label labelBuffer1[3] = { Label(env), Label(env), Label(env) };
    Label labelBuffer2[3] = { Label(env), Label(env), Label(env) };
    int64_t valueBuffer[3] = {
        static_cast<int64_t>(JSType::JS_INT8_ARRAY), static_cast<int64_t>(JSType::JS_UINT8_ARRAY),
        static_cast<int64_t>(JSType::JS_UINT8_CLAMPED_ARRAY) };
    int64_t valueBuffer1[3] = {
        static_cast<int64_t>(JSType::JS_INT16_ARRAY), static_cast<int64_t>(JSType::JS_UINT16_ARRAY),
        static_cast<int64_t>(JSType::JS_INT32_ARRAY) };
    int64_t valueBuffer2[3] = {
        static_cast<int64_t>(JSType::JS_UINT32_ARRAY), static_cast<int64_t>(JSType::JS_FLOAT32_ARRAY),
        static_cast<int64_t>(JSType::JS_FLOAT64_ARRAY) };

    GateRef valueType = TaggedIsInt(value);
    BRANCH(valueType, &valueTypeIsInt, &valueTypeIsDouble);
    Bind(&valueTypeIsInt);
    {
        GateRef intValue = TruncInt64ToInt32(ChangeTaggedPointerToInt64(value));
        GateRef valueLessthanMin = Int32LessThanOrEqual(intValue, Int32(INT32_MIN));
        GateRef valueMorethanMax = Int32GreaterThanOrEqual(intValue, Int32(INT32_MAX));
        BRANCH(BitOr(valueLessthanMin, valueMorethanMax), slowPath, &fastPath);
    }
    Bind(&valueTypeIsDouble);
    {
        GateRef intValue = ChangeFloat64ToInt32(CastInt64ToFloat64(
            ChangeTaggedPointerToInt64(value)));
        GateRef valueLessthanMin = Int32LessThanOrEqual(intValue, Int32(INT32_MIN));
        GateRef valueMorethanMax = Int32GreaterThanOrEqual(intValue, Int32(INT32_MAX));
        BRANCH(BitOr(valueLessthanMin, valueMorethanMax), slowPath, &fastPath);
    }
    Bind(&fastPath);

    BRANCH(Int32LessThanOrEqual(jsType, Int32(static_cast<int32_t>(JSType::JS_UINT8_CLAMPED_ARRAY))),
        &isInt8, &notInt8);
    Bind(&isInt8);
    {
        // 3 : this switch has 3 cases
        Switch(jsType, &defaultLabel, valueBuffer, labelBuffer, 3);
        // 0 : index of this buffer
        Bind(&labelBuffer[0]);
        {
            Label valueIsInt(env);
            Label valueIsDouble(env);
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            BRANCH(valueType, &valueIsInt, &valueIsDouble);
            Bind(&valueIsInt);
            {
                GateRef val = TruncInt32ToInt8(TruncInt64ToInt32(ChangeTaggedPointerToInt64(value)));
                Store(VariableType::INT8(), glue, block, byteIndex, val);
                Jump(&exit);
            }
            Bind(&valueIsDouble);
            {
                GateRef val = TruncInt32ToInt8(ChangeFloat64ToInt32(CastInt64ToFloat64(
                    ChangeTaggedPointerToInt64(value))));
                Store(VariableType::INT8(), glue, block, byteIndex, val);
                Jump(&exit);
            }
        }
        // 1 : index of this buffer
        Bind(&labelBuffer[1]);
        {
            Label valueIsInt(env);
            Label valueIsDouble(env);
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            BRANCH(valueType, &valueIsInt, &valueIsDouble);
            Bind(&valueIsInt);
            {
                GateRef val = TruncInt32ToInt8(TruncInt64ToInt32(ChangeTaggedPointerToInt64(value)));
                Store(VariableType::INT8(), glue, block, byteIndex, val);
                Jump(&exit);
            }
            Bind(&valueIsDouble);
            {
                GateRef val = TruncInt32ToInt8(ChangeFloat64ToInt32(CastInt64ToFloat64(
                    ChangeTaggedPointerToInt64(value))));
                Store(VariableType::INT8(), glue, block, byteIndex, val);
                Jump(&exit);
            }
        }
        // 2 : index of this buffer
        Bind(&labelBuffer[2]);
        {
            Label valueIsInt(env);
            Label valueIsDouble(env);
            GateRef byteIndex = Int32Add(index, offset);
            GateRef block = GetDataPointFromBuffer(buffer);
            Label overFlow(env);
            Label underFlow(env);
            GateRef topValue = Int32(static_cast<uint32_t>(UINT8_MAX));
            GateRef bottomValue = Int32(0U);
            BRANCH(valueType, &valueIsInt, &valueIsDouble);
            Bind(&valueIsInt);
            {
                Label notOverFlow1(env);
                Label notUnderFlow1(env);
                GateRef tmpVal = TruncInt64ToInt32(ChangeTaggedPointerToInt64(value));
                BRANCH(Int32GreaterThan(tmpVal, topValue), &overFlow, &notOverFlow1);
                Bind(&notOverFlow1);
                {
                    BRANCH(Int32LessThan(tmpVal, bottomValue), &underFlow, &notUnderFlow1);
                    Bind(&notUnderFlow1);
                    {
                        GateRef val = TruncInt32ToInt8(tmpVal);
                        Store(VariableType::INT8(), glue, block, byteIndex, val);
                        Jump(&exit);
                    }
                }
            }
            Bind(&valueIsDouble);
            {
                GateRef dVal = GetDoubleOfTDouble(value);
                GateRef integer = ChangeFloat64ToInt32(dVal);
                Label notOverFlow2(env);
                Label notUnderFlow2(env);
                BRANCH(Int32GreaterThan(integer, topValue), &overFlow, &notOverFlow2);
                Bind(&notOverFlow2);
                {
                    BRANCH(BitOr(Int32LessThan(integer, bottomValue), DoubleIsNAN(dVal)), &underFlow, &notUnderFlow2);
                    Bind(&notUnderFlow2);
                    {
                        GateRef val = CallNGCRuntime(glue, RTSTUB_ID(LrInt), { dVal });
                        Store(VariableType::INT8(), glue, block, byteIndex, val);
                        Jump(&exit);
                    }
                }
            }
            Bind(&overFlow);
            {
                Store(VariableType::INT8(), glue, block, byteIndex, Int8(static_cast<uint8_t>(UINT8_MAX)));
                Jump(&exit);
            }
            Bind(&underFlow);
            {
                Store(VariableType::INT8(), glue, block, byteIndex, Int8(0));
                Jump(&exit);
            }
        }
    }

    Bind(&notInt8);
    {
        BRANCH(Int32LessThanOrEqual(jsType, Int32(static_cast<int32_t>(JSType::JS_INT32_ARRAY))),
            &isInt16, &notInt16);
        Bind(&isInt16);
        {
            // 3 : this switch has 3 case
            Switch(jsType, &defaultLabel, valueBuffer1, labelBuffer1, 3);
            // 0 : index of this buffer
            Bind(&labelBuffer1[0]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::TWO)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = TruncInt32ToInt16(TruncInt64ToInt32(ChangeTaggedPointerToInt64(value)));
                    Store(VariableType::INT16(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = TruncInt32ToInt16(ChangeFloat64ToInt32(CastInt64ToFloat64(
                        ChangeTaggedPointerToInt64(value))));
                    Store(VariableType::INT16(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
            // 1 : index of this buffer
            Bind(&labelBuffer1[1]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::TWO)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = TruncInt32ToInt16(TruncInt64ToInt32(ChangeTaggedPointerToInt64(value)));
                    Store(VariableType::INT16(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = TruncInt32ToInt16(ChangeFloat64ToInt32(CastInt64ToFloat64(
                        ChangeTaggedPointerToInt64(value))));
                    Store(VariableType::INT16(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
            // 2 : index of this buffer
            Bind(&labelBuffer1[2]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = TruncInt64ToInt32(ChangeTaggedPointerToInt64(value));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = ChangeFloat64ToInt32(CastInt64ToFloat64(ChangeTaggedPointerToInt64(value)));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
        }
        Bind(&notInt16);
        {
            // 3 : this switch has 3 case
            Switch(jsType, &defaultLabel, valueBuffer2, labelBuffer2, 3);
            // 0 : index of this buffer
            Bind(&labelBuffer2[0]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = TruncInt64ToInt32(ChangeTaggedPointerToInt64(value));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = ChangeFloat64ToInt32(CastInt64ToFloat64(ChangeTaggedPointerToInt64(value)));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
            // 1 : index of this buffer
            Bind(&labelBuffer2[1]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::FOUR)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = TruncInt64ToInt32(ChangeTaggedPointerToInt64(value));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = ChangeFloat64ToInt32(CastInt64ToFloat64(ChangeTaggedPointerToInt64(value)));
                    Store(VariableType::INT32(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
            // 2 : index of this buffer
            Bind(&labelBuffer2[2]);
            {
                Label valueIsInt(env);
                Label valueIsDouble(env);
                GateRef byteIndex = Int32Add(Int32Mul(index, Int32(base::ElementSize::EIGHT)), offset);
                GateRef block = GetDataPointFromBuffer(buffer);
                BRANCH(valueType, &valueIsInt, &valueIsDouble);
                Bind(&valueIsInt);
                {
                    GateRef val = ChangeTaggedPointerToInt64(value);
                    Store(VariableType::INT64(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
                Bind(&valueIsDouble);
                {
                    GateRef val = ChangeTaggedPointerToInt64(value);
                    Store(VariableType::INT64(), glue, block, byteIndex, val);
                    Jump(&exit);
                }
            }
        }
    }

    Bind(&defaultLabel);
    {
        Jump(&exit);
    }
    Bind(&exit);
    env->SubCfgExit();
    return;
}

void BuiltinsTypedArrayStubBuilder::GenTypedArrayConstructor(GateRef glue, GateRef nativeCode, GateRef func,
    GateRef newTarget, GateRef thisValue, GateRef numArgs, GateRef constructorName, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    DEFVARIABLE(res, VariableType::JS_ANY(), Undefined());
    DEFVARIABLE(elementLength, VariableType::INT32(), Int32(0));
    DEFVARIABLE(elementLengthTagged, VariableType::JS_ANY(), IntToTaggedPtr(Int32(0)));

    Label newTargetIsHeapObject(env);
    Label newTargetIsJSFunction(env);
    Label slowPath(env);
    Label slowPath1(env);
    Label hasException(env);
    Label exit(env);

    BRANCH(TaggedIsHeapObject(newTarget), &newTargetIsHeapObject, &slowPath);
    Bind(&newTargetIsHeapObject);
    BRANCH(IsJSFunction(newTarget), &newTargetIsJSFunction, &slowPath);
    Bind(&newTargetIsJSFunction);
    {
        Label intialHClassIsHClass(env);
        GateRef intialHClass = Load(VariableType::JS_ANY(), newTarget,
                                    IntPtr(JSFunction::PROTO_OR_DYNCLASS_OFFSET));
        BRANCH(IsJSHClass(intialHClass), &intialHClassIsHClass, &slowPath1);
        Bind(&intialHClassIsHClass);
        {
            Label isEcmaObj(env);
            Label notEcmaObj(env);
            GateRef arg0 = GetArgFromArgv(IntPtr(0), numArgs, true);
            BRANCH(IsEcmaObject(arg0), &isEcmaObj, &notEcmaObj);
            Bind(&notEcmaObj);
            {
                Label isUndef(env);
                Label notUndef(env);
                BRANCH(TaggedIsUndefined(arg0), &isUndef, &notUndef);
                Bind(&notUndef);
                {
                    Label notException(env);
                    GateRef index = ToIndex(glue, arg0);
                    elementLengthTagged = index;
                    BRANCH(HasPendingException(glue), &hasException, &notException);
                    Bind(&notException);
                    {
                        elementLength = DoubleToInt(glue, GetDoubleOfTNumber(index));
                        Jump(&isUndef);
                    }
                }
                Bind(&isUndef);
                {
                    res = AllocateTypedArray(glue, constructorName, func, newTarget,
                        *elementLength, *elementLengthTagged, arrayType);
                    BRANCH(HasPendingException(glue), &hasException, &exit);
                }
            }
            Bind(&isEcmaObj);
            {
                Label isArrayBuffer(env);
                Label notArrayBuffer(env);
                Branch(TaggedIsArrayBuffer(arg0), &isArrayBuffer, &notArrayBuffer);
                Bind(&isArrayBuffer);
                {
                    Label createFromArrayBuffer(env);
                    res = AllocateTypedArray(glue, constructorName, func, newTarget, arrayType);
                    BRANCH(HasPendingException(glue), &hasException, &createFromArrayBuffer);
                    Bind(&createFromArrayBuffer);
                    CreateFromArrayBuffer(&res, glue, numArgs, &exit, &slowPath, arrayType);
                }
                Bind(&notArrayBuffer);
                {
                    Label isStableJSArray(env);
                    BRANCH(IsStableArray(LoadHClass(arg0)), &isStableJSArray, &slowPath);
                    Bind(&isStableJSArray);
                    Label createFromArray(env);
                    res = AllocateTypedArray(glue, constructorName, func, newTarget, arrayType);
                    BRANCH(HasPendingException(glue), &hasException, &createFromArray);
                    Bind(&createFromArray);
                    FastCopyElementFromArray(&res, glue, arg0, &exit, &slowPath, arrayType);
                }
            }
            Bind(&hasException);
            {
                res = Exception();
                Jump(&exit);
            }
        }
        Bind(&slowPath1);
        {
            GateRef argv = GetArgv();
            res = CallBuiltinRuntimeWithNewTarget(glue,
                { glue, nativeCode, func, thisValue, numArgs, argv, newTarget });
            Jump(&exit);
        }
    }
    Bind(&slowPath);
    {
        GateRef argv = GetArgv();
        res = CallBuiltinRuntime(glue, { glue, nativeCode, func, thisValue, numArgs, argv }, true);
        Jump(&exit);
    }
    Bind(&exit);
    Return(*res);
}

GateRef BuiltinsTypedArrayStubBuilder::AllocateTypedArray(GateRef glue, GateRef constructorName,
    GateRef func, GateRef newTarget, GateRef length, GateRef lengthTagged, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    Label subentry(env);
    env->SubCfgEntry(&subentry);
    DEFVARIABLE(res, VariableType::JS_ANY(), Hole());
    Label exit(env);

    NewObjectStubBuilder newObjectStubBuilder(this);
    res = newObjectStubBuilder.NewJSObjectByConstructor(glue, func, newTarget);
    Label hasException(env);
    Label notException(env);
    BRANCH(HasPendingException(glue), &hasException, &notException);
    Bind(&notException);
    {
        SetViewedArrayBufferOrByteArray(glue, *res, Undefined(), MemoryAttribute::NoBarrier());
        SetTypedArrayName(glue, *res, constructorName);
        AllocateTypedArrayBuffer(glue, *res, length, lengthTagged, arrayType);
        BRANCH(HasPendingException(glue), &hasException, &exit);
    }
    Bind(&hasException);
    {
        res = Exception();
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *res;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::AllocateTypedArray(GateRef glue, GateRef constructorName,
    GateRef func, GateRef newTarget, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    Label subentry(env);
    env->SubCfgEntry(&subentry);
    DEFVARIABLE(res, VariableType::JS_ANY(), Hole());
    Label exit(env);

    NewObjectStubBuilder newObjectStubBuilder(this);
    res = newObjectStubBuilder.NewJSObjectByConstructor(glue, func, newTarget);
    Label hasException(env);
    Label notException(env);
    BRANCH(HasPendingException(glue), &hasException, &notException);
    Bind(&notException);
    {
        SetViewedArrayBufferOrByteArray(glue, *res, Undefined(), MemoryAttribute::NoBarrier());
        if (arrayType == DataViewType::BIGINT64 ||
            arrayType == DataViewType::BIGUINT64) {
            SetContentType(glue, *res, Int8(static_cast<uint8_t>(ContentType::BigInt)));
        } else {
            SetContentType(glue, *res, Int8(static_cast<uint8_t>(ContentType::Number)));
        }
        SetTypedArrayName(glue, *res, constructorName);
        SetByteLength(glue, *res, Int32(0));
        SetByteOffset(glue, *res, Int32(0));
        SetTypedArrayLength(glue, *res, Int32(0));
        Jump(&exit);
    }
    Bind(&hasException);
    {
        res = Exception();
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *res;
    env->SubCfgExit();
    return ret;
}

GateRef BuiltinsTypedArrayStubBuilder::AllocateTypedArrayBuffer(GateRef glue, GateRef typedArray,
    GateRef length, GateRef lengthTagged, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    Label subentry(env);
    env->SubCfgEntry(&subentry);
    DEFVARIABLE(data, VariableType::JS_ANY(), Hole());
    DEFVARIABLE(result, VariableType::JS_ANY(), typedArray);
    Label exit(env);
    Label slowPath(env);
    Label valid(env);
    Label next(env);

    BRANCH(Int32UnsignedGreaterThan(length, Int32(JSTypedArray::MAX_TYPED_ARRAY_INDEX)), &slowPath, &valid);
    Bind(&valid);
    GateRef elementSize = Int32(base::TypedArrayHelper::GetSizeFromType(arrayType));
    GateRef byteLength = Int64Mul(ZExtInt32ToInt64(elementSize), ZExtInt32ToInt64(length));
    BRANCH(Int64UnsignedLessThanOrEqual(byteLength, Int64(JSTypedArray::MAX_ONHEAP_LENGTH)), &next, &slowPath);
    Bind(&next);
    {
        Label newByteArrayExit(env);
        NewObjectStubBuilder newObjectStubBuilder(this);
        newObjectStubBuilder.SetParameters(glue, 0);
        newObjectStubBuilder.NewByteArray(&data, &newByteArrayExit, elementSize, length);
        Bind(&newByteArrayExit);
        {
            Label hasException(env);
            Label notException(env);
            BRANCH(HasPendingException(glue), &hasException, &notException);
            Bind(&hasException);
            {
                result = Exception();
                Jump(&exit);
            }
            Bind(&notException);
            GateRef objHclass = LoadHClass(typedArray);
            GateRef newHclass = GetOnHeapHclassFromType(glue, objHclass, arrayType);
            NotifyHClassChanged(glue, objHclass, newHclass);
            Store(VariableType::JS_ANY(), glue, typedArray, IntPtr(TaggedObject::HCLASS_OFFSET),
                  newHclass, MemoryAttribute::NeedBarrierAndAtomic());
            if (arrayType == DataViewType::BIGINT64 ||
                arrayType == DataViewType::BIGUINT64) {
                SetContentType(glue, typedArray, Int8(static_cast<uint8_t>(ContentType::BigInt)));
            } else {
                SetContentType(glue, typedArray, Int8(static_cast<uint8_t>(ContentType::Number)));
            }
            SetViewedArrayBufferOrByteArray(glue, typedArray, *data);
            SetByteLength(glue, typedArray, TruncInt64ToInt32(byteLength));
            SetByteOffset(glue, typedArray, Int32(0));
            SetTypedArrayLength(glue, typedArray, length);
            Jump(&exit);
        }
    }
    Bind(&slowPath);
    {
        result = CallRuntime(glue, RTSTUB_ID(AllocateTypedArrayBuffer), { typedArray, lengthTagged });
        Jump(&exit);
    }
    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}

void BuiltinsTypedArrayStubBuilder::CreateFromArrayBuffer(Variable *result, GateRef glue, GateRef numArgs,
    Label *exit, Label *slowPath, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    DEFVARIABLE(newByteLength, VariableType::INT64(), Int64(0));
    Label hasException(env);
    Label notHasException(env);
    Label next(env);
    Label setArrayBufferProperties(env);

    GateRef elementSize = Int32(base::TypedArrayHelper::GetSizeFromType(arrayType));
    GateRef byteOffset = GetArgFromArgv(IntPtr(base::BuiltinsBase::ArgsPosition::SECOND), numArgs, true);
    GateRef index = ToIndex(glue, byteOffset);
    BRANCH(HasPendingException(glue), &hasException, &notHasException)
    Bind(&notHasException);
    GateRef offset = DoubleToInt(glue, GetDoubleOfTNumber(index));
    BRANCH(Int32Equal(Int32Mod(offset, elementSize), Int32(0)), &next, slowPath);
    Bind(&next);
    {
        Label notDetach(env);
        Label isUndef(env);
        Label notUndef(env);
        GateRef length = GetArgFromArgv(IntPtr(base::BuiltinsBase::ArgsPosition::THIRD), numArgs, true);
        GateRef buffer = GetArgFromArgv(IntPtr(0));
        BRANCH(IsDetachedBuffer(buffer), slowPath, &notDetach);
        Bind(&notDetach);
        GateRef bufferByteLength = GetArrayBufferByteLength(buffer);
        BRANCH(TaggedIsUndefined(length), &isUndef, &notUndef);
        Bind(&notUndef);
        {
            Label notHasException1(env);
            GateRef indexLength = ToIndex(glue, length);
            BRANCH(HasPendingException(glue), &hasException, &notHasException1);
            Bind(&notHasException1);
            {
                GateRef newLength = DoubleToInt(glue, GetDoubleOfTNumber(indexLength));
                newByteLength = Int64Mul(ZExtInt32ToInt64(newLength), ZExtInt32ToInt64(elementSize));
                BRANCH(Int64UnsignedGreaterThan(
                    Int64Add(ZExtInt32ToInt64(offset), *newByteLength), ZExtInt32ToInt64(bufferByteLength)),
                    slowPath, &setArrayBufferProperties);
            }
        }
        Bind(&isUndef);
        {
            Label next1(env);
            Label next2(env);
            BRANCH(Int32Equal(Int32Mod(bufferByteLength, elementSize), Int32(0)), &next1, slowPath);
            Bind(&next1);
            {
                BRANCH(Int32UnsignedLessThan(bufferByteLength, offset), slowPath, &next2);
                Bind(&next2);
                newByteLength = ZExtInt32ToInt64(Int32Sub(bufferByteLength, offset));
                Jump(&setArrayBufferProperties);
            }
        }
    }
    Bind(&setArrayBufferProperties);
    {
        SetArrayBufferProperties(glue, result->ReadVariable(), TruncInt64ToInt32(*newByteLength),
                                 offset, TruncInt64ToInt32(Int64Div(*newByteLength, ZExtInt32ToInt64(elementSize))));
        Jump(exit);
    }

    Bind(&hasException);
    {
        result->WriteVariable(Exception());
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::FastCopyElementFromArray(Variable *result, GateRef glue, GateRef array,
    Label *exit, Label *slowPath, const DataViewType arrayType)
{
    auto env = GetEnvironment();
    Label hasException(env);
    Label allocateTypedArray(env);
    Label copyElements(env);

    GateRef len = Load(VariableType::INT32(), array, IntPtr(panda::ecmascript::JSArray::LENGTH_OFFSET));
    GateRef elements = GetElementsArray(array);
    BRANCH_UNLIKELY(Int32UnsignedLessThan(GetLengthOfTaggedArray(elements), len), slowPath, &allocateTypedArray);
    Bind(&allocateTypedArray);
    {
        AllocateTypedArrayBuffer(glue, result->ReadVariable(), len, IntToTaggedInt(len), arrayType);
        BRANCH(HasPendingException(glue), &hasException, &copyElements);
    }
    Bind(&copyElements);
    {
        Label check(env);
        FastCopyFromArrayToTypedArray(glue, array, result, Int32(0), len, &check, slowPath, arrayType, true);
        Bind(&check);
        BRANCH(HasPendingException(glue), &hasException, exit);
    }
    Bind(&hasException);
    {
        result->WriteVariable(Exception());
        Jump(exit);
    }
}

void BuiltinsTypedArrayStubBuilder::FastCopyFromArrayToTypedArray(GateRef glue, GateRef array, Variable *result,
    GateRef targetOffset, GateRef srcLength, Label *check, Label *slowPath,
    const DataViewType arrayType, bool typedArrayFromCtor)
{
    if (arrayType == DataViewType::UINT8_CLAMPED || arrayType == DataViewType::BIGINT64
        || arrayType == DataViewType::BIGUINT64) {
        CallRuntime(glue, RTSTUB_ID(FastCopyFromArrayToTypedArray),
            { result->ReadVariable(), IntToTaggedInt(srcLength), array });
        Jump(check);
        return;
    }
    auto env = GetEnvironment();
    Label next(env);
    Label setValue(env);
    Label isTagged(env);
    Label mutantArrayEnabled(env);

    GateRef buffer = GetViewedArrayBufferOrByteArray(result->ReadVariable());
    if (!typedArrayFromCtor) {
        BRANCH(IsDetachedBuffer(buffer), slowPath, &next);
        Bind(&next);
    }
    GateRef targetByteOffset = GetByteOffset(result->ReadVariable());
    GateRef elementSize = Int32(base::TypedArrayHelper::GetSizeFromType(arrayType));
    if (!typedArrayFromCtor) {
        GateRef targetLength = GetArrayLength(result->ReadVariable());
        BRANCH_UNLIKELY(Int32GreaterThan(Int32Add(srcLength, targetOffset), targetLength), slowPath, &setValue);
        Bind(&setValue);
    }
    GateRef targetByteIndex;
    if (typedArrayFromCtor) {
        targetByteIndex = Int32(0);
    } else {
        targetByteIndex = Int32Add(Int32Mul(targetOffset, elementSize), targetByteOffset);
    }
    BRANCH(IsEnableMutantArray(glue), &mutantArrayEnabled, &isTagged);
    Bind(&mutantArrayEnabled);
    {
        CopyElementsToArrayBuffer(glue, srcLength, array, buffer, targetByteIndex, arrayType, true);
        Jump(check);
    }
    Bind(&isTagged);
    {
        CopyElementsToArrayBuffer(glue, srcLength, array, buffer, targetByteIndex, arrayType, false);
        Jump(check);
    }
}

void BuiltinsTypedArrayStubBuilder::CopyElementsToArrayBuffer(GateRef glue, GateRef srcLength, GateRef array,
    GateRef buffer, GateRef targetByteIndex, const DataViewType arrayType, bool getWithKind)
{
    auto env = GetEnvironment();
    Label entry(env);
    env->SubCfgEntry(&entry);
    DEFVARIABLE(i, VariableType::INT32(), Int32(0));
    DEFVARIABLE(byteIndex, VariableType::INT32(), targetByteIndex);
    Label loopHead(env);
    Label loopEnd(env);
    Label exit(env);
    Label copyElement(env);
    GateRef elementsArray = GetElementsArray(array);
    GateRef elementSize = Int32(base::TypedArrayHelper::GetSizeFromType(arrayType));
    Jump(&loopHead);
    LoopBegin(&loopHead);
    {
        Label storeValue(env);
        BRANCH(Int32UnsignedLessThan(*i, srcLength), &storeValue, &exit);
        Bind(&storeValue);
        {
            GateRef value = getWithKind ? GetTaggedValueWithElementsKind(glue, array, *i)
                                        : GetValueFromTaggedArray(elementsArray, *i);
            GateRef val = ToNumber(glue, value);
            BRANCH(HasPendingException(glue), &exit, &copyElement);
            Bind(&copyElement);
            FastSetValueInBuffer(glue, buffer, *byteIndex, TaggedGetNumber(val), arrayType);
            i = Int32Add(*i, Int32(1));
            byteIndex = Int32Add(*byteIndex, elementSize);
            Jump(&loopEnd);
        }
    }
    Bind(&loopEnd);
    LoopEnd(&loopHead, env, glue);

    Bind(&exit);
    env->SubCfgExit();
}

// don't consider LittleEndianToBigEndian, use it carefully
void BuiltinsTypedArrayStubBuilder::FastSetValueInBuffer(GateRef glue, GateRef buffer,
    GateRef byteIndex, GateRef val, const DataViewType arrayType)
{
    GateRef block = GetDataPointFromBuffer(buffer);
    switch (arrayType) {
        case DataViewType::UINT8:
            SetValueInBufferForByte(glue, val, block, byteIndex);
            break;
        case DataViewType::INT8:
            SetValueInBufferForByte(glue, val, block, byteIndex);
            break;
        case DataViewType::UINT16:
            SetValueInBufferForInteger<uint16_t>(glue, val, block, byteIndex);
            break;
        case DataViewType::INT16:
            SetValueInBufferForInteger<int16_t>(glue, val, block, byteIndex);
            break;
        case DataViewType::UINT32:
            SetValueInBufferForInteger<uint32_t>(glue, val, block, byteIndex);
            break;
        case DataViewType::INT32:
            SetValueInBufferForInteger<int32_t>(glue, val, block, byteIndex);
            break;
        case DataViewType::FLOAT32:
            SetValueInBufferForFloat<float>(glue, val, block, byteIndex);
            break;
        case DataViewType::FLOAT64:
            SetValueInBufferForFloat<double>(glue, val, block, byteIndex);
            break;
        default:
            LOG_ECMA(FATAL) << "this branch is unreachable";
            UNREACHABLE();
    }
}

void BuiltinsTypedArrayStubBuilder::SetValueInBufferForByte(GateRef glue, GateRef val,
    GateRef pointer, GateRef byteIndex)
{
    auto env = GetEnvironment();
    Label entry(env);
    env->SubCfgEntry(&entry);
    Label exit(env);
    Label setValue(env);
    Label converse(env);
    DEFVARIABLE(result, VariableType::INT8(), Int8(0));
    BRANCH(DoubleIsNanOrInf(val), &setValue, &converse);
    Bind(&converse);
    {
        result = TruncInt32ToInt8(DoubleToInt(glue, val));
        Jump(&setValue);
    }
    Bind(&setValue);
    {
        Store(VariableType::INT8(), glue, pointer, byteIndex, *result);
        Jump(&exit);
    }
    Bind(&exit);
    env->SubCfgExit();
}

template<typename T>
void BuiltinsTypedArrayStubBuilder::SetValueInBufferForInteger(GateRef glue, GateRef val,
    GateRef pointer, GateRef byteIndex)
{
    auto env = GetEnvironment();
    Label entry(env);
    env->SubCfgEntry(&entry);
    Label exit(env);
    Label setValue(env);
    Label converse(env);
    DEFVARIABLE(result, VariableType::INT32(), Int32(0));
    BRANCH(DoubleIsNanOrInf(val), &setValue, &converse);
    Bind(&converse);
    {
        result = DoubleToInt(glue, val);
        Jump(&setValue);
    }
    Bind(&setValue);
    {
        if constexpr (std::is_same_v<T, uint16_t> || std::is_same_v<T, int16_t>) {
            Store(VariableType::INT16(), glue, pointer, byteIndex, TruncInt32ToInt16(*result));
        } else {
            Store(VariableType::INT32(), glue, pointer, byteIndex, *result);
        }
        Jump(&exit);
    }
    Bind(&exit);
    env->SubCfgExit();
}

template<typename T>
void BuiltinsTypedArrayStubBuilder::SetValueInBufferForFloat(GateRef glue, GateRef val,
    GateRef pointer, GateRef byteIndex)
{
    if constexpr (std::is_same_v<T, float>) {
        Store(VariableType::FLOAT32(), glue, pointer, byteIndex, TruncDoubleToFloat32(val));
    } else {
        Store(VariableType::FLOAT64(), glue, pointer, byteIndex, val);
    }
}

void BuiltinsTypedArrayStubBuilder::SetArrayBufferProperties(GateRef glue, GateRef typedArray,
    GateRef newByteLength, GateRef offset, GateRef arrayLength)
{
    GateRef buffer = GetArgFromArgv(IntPtr(0));
    SetViewedArrayBufferOrByteArray(glue, typedArray, buffer);
    SetByteLength(glue, typedArray, newByteLength);
    SetByteOffset(glue, typedArray, offset);
    SetTypedArrayLength(glue, typedArray, arrayLength);
}

GateRef BuiltinsTypedArrayStubBuilder::GetOnHeapHclassFromType(GateRef glue, GateRef objHclass,
                                                               const DataViewType arrayType)
{
    auto env = GetEnvironment();
    Label entry(env);
    env->SubCfgEntry(&entry);

    DEFVARIABLE(result, VariableType::JS_ANY(), Undefined());
    GateRef glueGlobalEnvOffset = IntPtr(JSThread::GlueData::GetGlueGlobalEnvOffset(env->Is32Bit()));
    GateRef glueGlobalEnv = Load(VariableType::NATIVE_POINTER(), glue, glueGlobalEnvOffset);
    Label slowPath(env);
    Label exit(env);

    switch (arrayType) {
#define BUILTIN_COMPILER_TYPED_ARRAY_LABEL(TYPE, type, index)                           \
        case DataViewType::TYPE:                                                        \
        {                                                                               \
            Label isEqual(env);                                                         \
            GateRef hclass = GetGlobalEnvValue(VariableType::JS_ANY(), glueGlobalEnv,   \
                GlobalEnv::TYPE##_ARRAY_ROOT_HCLASS_INDEX);                             \
            BRANCH(IntPtrEqual(objHclass, hclass), &isEqual, &slowPath);                \
            Bind(&isEqual);                                                             \
            result = GetGlobalEnvValue(VariableType::JS_ANY(), glueGlobalEnv,           \
                GlobalEnv::TYPE##_ARRAY_ROOT_HCLASS_ON_HEAP_INDEX);                     \
            Jump(&exit);                                                                \
            break;                                                                      \
        }
BUILTIN_COMPILER_TYPED_ARRAY_TYPES(BUILTIN_COMPILER_TYPED_ARRAY_LABEL)
#undef BUILTIN_COMPILER_TYPED_ARRAY_LABEL
        default:
            LOG_ECMA(FATAL) << "this branch is unreachable";
            UNREACHABLE();
    }

    Bind(&slowPath);
    {
        result = CallRuntime(glue, RTSTUB_ID(CloneHclass), { objHclass });
        Jump(&exit);
    }

    Bind(&exit);
    auto ret = *result;
    env->SubCfgExit();
    return ret;
}
}  // namespace panda::ecmascript::kungfu
