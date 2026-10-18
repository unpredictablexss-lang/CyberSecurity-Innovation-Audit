/**
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <charconv>
#include <optional>
#include <type_traits>
#include <cmath>
#include "ets_handle.h"
#include "ets_panda_file_items.h"
#include "libarkbase/utils/utf.h"
#include "libarkbase/utils/utils.h"
#include "plugins/ets/runtime/ets_platform_types.h"
#include "plugins/ets/runtime/types/ets_typed_arrays.h"
#include "plugins/ets/runtime/types/ets_typed_unsigned_arrays.h"
#include "plugins/ets/runtime/intrinsics/helpers/ets_intrinsics_helpers.h"
#include "intrinsics.h"
#include "cross_values.h"
#include "types/ets_object.h"
#include "types/ets_primitives.h"

constexpr uint64_t DOUBLE_SIGNIFICAND_SIZE = 52;
constexpr uint64_t DOUBLE_EXPONENT_BIAS = 1023;
constexpr uint64_t DOUBLE_SIGN_MASK = 0x8000000000000000ULL;
constexpr uint64_t DOUBLE_EXPONENT_MASK = (0x7FFULL << DOUBLE_SIGNIFICAND_SIZE);
constexpr uint64_t DOUBLE_SIGNIFICAND_MASK = 0x000FFFFFFFFFFFFFULL;
constexpr uint64_t DOUBLE_HIDDEN_BIT = (1ULL << DOUBLE_SIGNIFICAND_SIZE);
#define INT64_BITS (64)
#define INT8_BITS (8)
#define INT16_BITS (16)
#define INT32_BITS (32)

namespace ark::ets::intrinsics {

static void ThrowRangeError(const char *message)
{
    auto *executionCtx = EtsExecutionContext::GetCurrent();
    ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreRangeError, message);
}

static void ThrowNullPointerError(const char *message)
{
    auto *executionCtx = EtsExecutionContext::GetCurrent();
    ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreNullPointerError, message);
}

static inline int32_t NormalizeIndex(int32_t idx, int32_t arrayLength)
{
    if (idx < -arrayLength) {
        return 0;
    }
    if (idx < 0) {
        return arrayLength + idx;
    }
    if (idx > arrayLength) {
        return arrayLength;
    }
    return idx;
}

static bool CheckedAdd(size_t lhs, size_t rhs, size_t *result)
{
    if (UNLIKELY(lhs > std::numeric_limits<size_t>::max() - rhs)) {
        return false;
    }
    *result = lhs + rhs;
    return true;
}

static bool CheckedMul(size_t lhs, size_t rhs, size_t *result)
{
    if (UNLIKELY(rhs != 0 && lhs > std::numeric_limits<size_t>::max() / rhs)) {
        return false;
    }
    *result = lhs * rhs;
    return true;
}

template <typename T>
static bool GetTypedArrayByteRange(T *array, size_t elementOffset, size_t elementCount, size_t *byteOffset,
                                   size_t *byteCount)
{
    auto *arrayBuffer = static_cast<EtsStdCoreArrayBuffer *>(&*array->GetBuffer());
    const EtsInt bufferLength = arrayBuffer->GetByteLength();
    const EtsInt arrayLength = array->GetLengthInt();
    const auto arrayByteOffset = static_cast<EtsInt>(array->GetByteOffset());
    if (UNLIKELY(bufferLength < 0 || arrayLength < 0 || arrayByteOffset < 0)) {
        ThrowRangeError("typed array range is out of bounds");
        return false;
    }

    const auto bufferSize = static_cast<size_t>(bufferLength);
    const auto length = static_cast<size_t>(arrayLength);
    const auto baseByteOffset = static_cast<size_t>(arrayByteOffset);
    size_t rangeByteOffset = 0;
    size_t rangeByteCount = 0;
    if (UNLIKELY(elementOffset > length || elementCount > length - elementOffset ||
                 !CheckedMul(elementOffset, sizeof(typename T::ElementType), &rangeByteOffset) ||
                 !CheckedAdd(rangeByteOffset, baseByteOffset, &rangeByteOffset) ||
                 !CheckedMul(elementCount, sizeof(typename T::ElementType), &rangeByteCount) ||
                 rangeByteOffset > bufferSize || rangeByteCount > bufferSize - rangeByteOffset)) {
        ThrowRangeError("typed array range is out of bounds");
        return false;
    }
    *byteOffset = rangeByteOffset;
    *byteCount = rangeByteCount;
    return true;
}

template <typename T>
static void *GetNativeData(T *array)
{
    auto *arrayBuffer = static_cast<EtsStdCoreArrayBuffer *>(&*array->GetBuffer());
    if (UNLIKELY(arrayBuffer->WasDetached())) {
        EtsExecutionContext *executionCtx = EtsExecutionContext::GetCurrent();
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreTypeError, "ArrayBuffer was detached");
        return nullptr;
    }
    return arrayBuffer->GetData();
}

template <typename T>
static void EtsEscompatTypedArraySet(T *thisArray, EtsInt pos, typename T::ElementType val)
{
    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return;
    }

    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (UNLIKELY(pos < 0 || pos >= thisArray->GetLengthInt())) {
        EtsExecutionContext *executionCtx = EtsExecutionContext::GetCurrent();
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreRangeError, "invalid index");
        return;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    ObjectAccessor::SetPrimitive(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
        data, pos * sizeof(typename T::ElementType) + static_cast<EtsInt>(thisArray->GetByteOffset()), val);
}

template <typename T>
typename T::ElementType EtsEscompatTypedArrayGet(T *thisArray, EtsInt pos)
{
    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return 0;
    }

    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (UNLIKELY(pos < 0 || pos >= thisArray->GetLengthInt())) {
        EtsExecutionContext *executionCtx = EtsExecutionContext::GetCurrent();
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreRangeError, "invalid index");
        return 0;
    }
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    return ObjectAccessor::GetPrimitive<typename T::ElementType>(
        // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
        data, pos * sizeof(typename T::ElementType) + static_cast<EtsInt>(thisArray->GetByteOffset()));
}

template <typename T>
typename T::ElementType EtsEscompatTypedArrayGetUnsafe(T *thisArray, EtsInt pos)
{
    ASSERT(pos >= 0 && pos < thisArray->GetLengthInt());

    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return 0;
    }

    return ObjectAccessor::GetPrimitive<typename T::ElementType>(
        data, pos * sizeof(typename T::ElementType) + static_cast<EtsInt>(thisArray->GetByteOffset()));
}

extern "C" void EtsEscompatInt8ArraySetInt(ark::ets::EtsEscompatInt8Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" void EtsEscompatInt8ArraySetByte(ark::ets::EtsEscompatInt8Array *thisArray, EtsInt pos, EtsByte val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatInt8ArrayGet(ark::ets::EtsEscompatInt8Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsByte EtsEscompatInt8ArrayGetUnsafe(ark::ets::EtsEscompatInt8Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

// We can just copy the backing buffer if the types are the same, or if we are converting e.g. Int16 <-> Uint16, as
// the binary representation will be the same. Unfortunately, we cannot use this fact to convert Uint32 -> Int32,
// because in the already implemented method Int32Array.from(ArrayLike<number>), the Uint32 -> Double -> Int32
// conversion takes place actually and Double -> Int32 clips values to MAX_INT.
template <typename T, typename U>
struct CompatibleElements : std::false_type {
};

template <>
struct CompatibleElements<EtsEscompatInt8Array, EtsEscompatUInt8Array> : std::true_type {
};

template <>
struct CompatibleElements<EtsEscompatUInt8Array, EtsEscompatInt8Array> : std::true_type {
};

template <>
struct CompatibleElements<EtsEscompatInt16Array, EtsEscompatUInt16Array> : std::true_type {
};

template <>
struct CompatibleElements<EtsEscompatUInt16Array, EtsEscompatInt16Array> : std::true_type {
};

template <>
struct CompatibleElements<EtsEscompatUInt32Array, EtsEscompatInt32Array> : std::true_type {
};

template <typename T, typename S = T,
          typename = std::enable_if_t<std::disjunction_v<std::is_same<T, S>, CompatibleElements<T, S>>>>
static void EtsEscompatTypedArraySetValuesImpl(T *thisArray, S *srcArray, EtsInt pos)
{
    auto *dstData = GetNativeData(thisArray);
    if (UNLIKELY(dstData == nullptr)) {
        return;
    }
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *srcData = GetNativeData(srcArray);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (UNLIKELY(srcData == nullptr)) {
        return;
    }

    using ElementType = typename T::ElementType;
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    const auto srcLength = srcArray->GetLengthInt();
    const auto dstLength = thisArray->GetLengthInt();
    if (UNLIKELY(pos < 0 || pos > dstLength || srcLength > dstLength - pos)) {
        EtsExecutionContext *executionCtx = EtsExecutionContext::GetCurrent();
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreRangeError, "offset is out of bounds");
        return;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (UNLIKELY(srcLength == 0)) {
        return;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *dst = ToVoidPtr(ToUintPtr(dstData) + thisArray->GetByteOffset() + pos * sizeof(ElementType));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *src = ToVoidPtr(ToUintPtr(srcData) + srcArray->GetByteOffset());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    [[maybe_unused]] auto error = memmove_s(dst, (dstLength - pos) * sizeof(ElementType), src,
                                            // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
                                            srcLength * sizeof(ElementType));
    ASSERT(error == EOK);
}

namespace {

namespace unbox {

constexpr uint64_t LONG_SHIFT = 32U;
constexpr uint64_t LONG_MASK = (uint64_t {1} << LONG_SHIFT) - uint64_t {1U};

[[nodiscard]] EtsLong GetLong(const EtsBigInt *bigint)
{
    const auto *bytes = bigint->GetBytes();
    ASSERT(bytes != nullptr);
    auto buff = EtsLong {0};
    const auto len = std::min(uint32_t {2U}, static_cast<uint32_t>(bytes->GetLength()));
    for (uint32_t i = 0; i < len; ++i) {
        buff += static_cast<EtsLong>((static_cast<uint32_t>(bytes->Get(i)) & LONG_MASK) << i * LONG_SHIFT);
    }
    return bigint->GetSign() * buff;
}

[[nodiscard]] EtsUlong GetULong(const EtsBigInt *bigint)
{
    return static_cast<EtsUlong>(GetLong(bigint));
}

template <typename T, typename = void>
class ArrayElement;

template <typename T>
class ArrayElement<T, std::enable_if_t<std::is_integral_v<typename T::ElementType>>> {
public:
    using Type = typename T::ElementType;

    ArrayElement() : coreIntClass_(PlatformTypes(EtsExecutionContext::GetCurrent())->coreInt) {}

    std::optional<Type> GetTyped(EtsObject *object) const
    {
        const auto value = Unbox(object);
        return value.has_value() ? std::optional(ToTyped(*value)) : std::nullopt;
    }

private:
    std::optional<EtsInt> Unbox(EtsObject *object) const
    {
        const auto *objectClass = object->GetClass();
        if (LIKELY(objectClass->IsBoxedInt())) {
            return EtsBoxPrimitive<EtsInt>::Unbox(object);
        }
        ThrowClassCastException(coreIntClass_->GetRuntimeClass(), objectClass->GetRuntimeClass());
        return std::nullopt;
    }

    static Type ToTyped(EtsInt value)
    {
        return static_cast<Type>(value);
    }

    const EtsClass *coreIntClass_;
};

template <typename T>
class ArrayElement<T, std::enable_if_t<std::is_floating_point_v<typename T::ElementType>>> {
public:
    using Type = typename T::ElementType;

    ArrayElement() : coreDoubleClass_(PlatformTypes(EtsExecutionContext::GetCurrent())->coreDouble) {}

    std::optional<Type> GetTyped(EtsObject *object) const
    {
        const auto value = Unbox(object);
        return value.has_value() ? std::optional(ToTyped(*value)) : std::nullopt;
    }

private:
    std::optional<EtsDouble> Unbox(EtsObject *object) const
    {
        const auto *objectClass = object->GetClass();
        if (LIKELY(objectClass->IsBoxedDouble())) {
            return EtsBoxPrimitive<EtsDouble>::Unbox(object);
        }
        ThrowClassCastException(coreDoubleClass_->GetRuntimeClass(), objectClass->GetRuntimeClass());
        return std::nullopt;
    }

    static Type ToTyped(EtsDouble value);

    const EtsClass *coreDoubleClass_;
};

template <>
auto ArrayElement<EtsEscompatInt32Array>::ToTyped(EtsInt value) -> Type
{
    return value;
}

template <>
auto ArrayElement<EtsEscompatUInt8ClampedArray>::ToTyped(EtsInt value) -> Type
{
    if (!(value > ark::ets::EtsEscompatUInt8ClampedArray::MIN)) {
        return ark::ets::EtsEscompatUInt8ClampedArray::MIN;
    }
    if (value > ark::ets::EtsEscompatUInt8ClampedArray::MAX) {
        return ark::ets::EtsEscompatUInt8ClampedArray::MAX;
    }
    return static_cast<uint8_t>(value);
}

template <>
auto ArrayElement<EtsEscompatFloat32Array>::ToTyped(EtsDouble value) -> Type
{
    return static_cast<Type>(value);
}

template <>
auto ArrayElement<EtsEscompatFloat64Array>::ToTyped(EtsDouble value) -> Type
{
    return value;
}

template <typename ArrayType>
class BigInt64ArrayElement {
public:
    using Type = typename ArrayType::ElementType;

    BigInt64ArrayElement() : stdCoreBigIntClass_(PlatformTypes(EtsExecutionContext::GetCurrent())->coreBigInt) {}

    std::optional<Type> GetTyped(EtsObject *object) const
    {
        const auto *bigint = Cast(object);
        return bigint != nullptr ? std::optional(ArrayElement<ArrayType>::ToTyped(bigint)) : std::nullopt;
    }

private:
    const EtsBigInt *Cast(EtsObject *object) const
    {
        const auto *objectClass = object->GetClass();
        if (LIKELY(objectClass->IsBigInt())) {
            return EtsBigInt::FromEtsObject(object);
        }
        ThrowClassCastException(stdCoreBigIntClass_->GetRuntimeClass(), objectClass->GetRuntimeClass());
        return nullptr;
    }

    static Type ToTyped([[maybe_unused]] const EtsBigInt *bigint);

    friend ArrayElement<ArrayType>;

    const EtsClass *stdCoreBigIntClass_;
};

template <>
class ArrayElement<EtsEscompatBigInt64Array> final : public BigInt64ArrayElement<EtsEscompatBigInt64Array> {
private:
    static Type ToTyped(const EtsBigInt *bigint)
    {
        ASSERT(bigint != nullptr);
        return GetLong(bigint);
    }
    friend BigInt64ArrayElement<EtsEscompatBigInt64Array>;
};

template <>
class ArrayElement<EtsEscompatBigUInt64Array> final : public BigInt64ArrayElement<EtsEscompatBigUInt64Array> {
private:
    static Type ToTyped(const EtsBigInt *bigint)
    {
        ASSERT(bigint != nullptr);
        return GetULong(bigint);
    }
    friend BigInt64ArrayElement<EtsEscompatBigUInt64Array>;
};

}  // namespace unbox
}  // namespace

template <typename T>
static void EtsEscompatTypedArraySetValuesFromFixedArray(T *thisArray, void *dstData, EtsObjectArray *srcData,
                                                         uint32_t actualLength)
{
    using ElementType = typename T::ElementType;

    ASSERT(thisArray != nullptr);
    ASSERT(dstData != nullptr);
    ASSERT(srcData != nullptr);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    size_t offset = 0;
    size_t byteCount = 0;
    if (!GetTypedArrayByteRange(thisArray, 0, actualLength, &offset, &byteCount)) {
        return;
    }

    const auto arrayElement = unbox::ArrayElement<T>();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    for (size_t i = 0; i < actualLength; ++i) {
        const auto val = arrayElement.GetTyped(srcData->Get(i));
        if (!val.has_value()) {
            break;
        }
        ObjectAccessor::SetPrimitive(dstData, offset, *val);
        offset += sizeof(ElementType);
    }
}

template <typename T>
static bool ValidateSetValuesFromArrayLength(T *thisArray, EtsInt thisArrayLength, EtsInt sourceLength,
                                             EtsExecutionContext *executionCtx)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (UNLIKELY(sourceLength < 0 || sourceLength > thisArrayLength)) {
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreRangeError, "offset is out of bounds");
        return false;
    }
    size_t initialOffset = 0;
    size_t byteCount = 0;
    return GetTypedArrayByteRange(thisArray, 0, static_cast<size_t>(sourceLength), &initialOffset, &byteCount);
}

template <typename T>
static bool SetValueFromArrayAt(EtsHandle<EtsObject> &thisArrayHandle, EtsHandle<EtsStdCoreArray> &srcArrayHandle,
                                const unbox::ArrayElement<T> &arrayElement, size_t index,
                                EtsExecutionContext *executionCtx)
{
    auto optElement = srcArrayHandle->GetRef(executionCtx, index);
    if (UNLIKELY(!optElement)) {
        ASSERT(executionCtx->GetMT()->HasPendingException());
        return false;
    }
    if (UNLIKELY(*optElement == nullptr)) {
        PandaStringStream ss;
        ss << "element at index " << index << " is undefined";
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreNullPointerError, ss.str());
        return false;
    }
    const auto value = arrayElement.GetTyped(*optElement);
    if (!value.has_value()) {
        ASSERT(executionCtx->GetMT()->HasPendingException());
        return false;
    }

    // GetRef and GetTyped may execute user code or throw. Revalidate the backing buffer before every write.
    auto *currentArray = reinterpret_cast<T *>(thisArrayHandle.GetPtr());
    auto *dstData = GetNativeData(currentArray);
    if (UNLIKELY(dstData == nullptr)) {
        return false;
    }
    size_t offset = 0;
    size_t elementBytes = 0;
    if (!GetTypedArrayByteRange(currentArray, index, 1, &offset, &elementBytes)) {
        return false;
    }
    ObjectAccessor::SetPrimitive(dstData, offset, *value);
    return true;
}

/// Slow path, because methods of `srcArray` might be overridden
template <typename T>
static void EtsEscompatTypedArraySetValuesFromArraySlowPath(T *thisArray, EtsStdCoreArray *srcArray,
                                                            EtsExecutionContext *executionCtx)
{
    ASSERT(thisArray != nullptr);
    ASSERT(srcArray != nullptr);
    ASSERT(executionCtx != nullptr);

    EtsInt thisArrayLengthInt = thisArray->GetLengthInt();
    EtsHandleScope scope(executionCtx);
    EtsHandle<EtsObject> thisArrayHandle(executionCtx, reinterpret_cast<EtsObject *>(thisArray));
    EtsHandle<EtsStdCoreArray> srcArrayHandle(executionCtx, srcArray);

    EtsInt actualLength = 0;
    if (UNLIKELY(!srcArrayHandle->GetLength(executionCtx, &actualLength))) {
        ASSERT(executionCtx->GetMT()->HasPendingException());
        return;
    }

    if (!ValidateSetValuesFromArrayLength(reinterpret_cast<T *>(thisArrayHandle.GetPtr()), thisArrayLengthInt,
                                          actualLength, executionCtx)) {
        return;
    }

    const auto arrayElement = unbox::ArrayElement<T>();
    for (size_t i = 0; i < static_cast<size_t>(actualLength); ++i) {
        if (!SetValueFromArrayAt<T>(thisArrayHandle, srcArrayHandle, arrayElement, i, executionCtx)) {
            return;
        }
    }
}

template <typename T>
static void EtsEscompatTypedArraySetValuesFromArrayImpl(T *thisArray, EtsStdCoreArray *srcArray)
{
    ASSERT(thisArray != nullptr);
    ASSERT(srcArray != nullptr);

    auto *dstData = GetNativeData(thisArray);
    if (UNLIKELY(dstData == nullptr)) {
        return;
    }

    EtsExecutionContext *executionCtx = EtsExecutionContext::GetCurrent();
    if (LIKELY(srcArray->IsExactlyStdCoreArray(executionCtx))) {
        // Fast path in case of `srcArray` being exactly `std.core.Array`
        EtsEscompatTypedArraySetValuesFromFixedArray(thisArray, dstData, srcArray->GetDataFromStdCoreArray(),
                                                     srcArray->GetActualLengthFromStdCoreArray());
    } else {
        EtsEscompatTypedArraySetValuesFromArraySlowPath(thisArray, srcArray, executionCtx);
    }
}

extern "C" void EtsEscompatInt8ArraySetValues(ark::ets::EtsEscompatInt8Array *thisArray,
                                              ark::ets::EtsEscompatInt8Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatInt8ArraySetValuesFromUnsigned(ark::ets::EtsEscompatInt8Array *thisArray,
                                                          ark::ets::EtsEscompatUInt8Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatInt8ArraySetValuesWithOffset(ark::ets::EtsEscompatInt8Array *thisArray,
                                                        ark::ets::EtsEscompatInt8Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatInt8ArraySetValuesFromArray(ark::ets::EtsEscompatInt8Array *thisArray,
                                                       ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

template <typename T, typename V>
static void EtsEscompatTypedArrayFillInternal(T *thisArray, V val, EtsInt begin, EtsInt end)
{
    static_assert(sizeof(V) == sizeof(typename T::ElementType));
    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return;
    }
    const auto length = thisArray->GetLengthInt();
    size_t byteOffset = 0;
    size_t byteCount = 0;
    // The managed wrapper normalizes both bounds, so a violation here is an internal contract bug.
    // Assert it in debug builds, but clamp in release: `fill` never throws a RangeError per the spec.
    ASSERT(begin >= 0 && begin <= length && end >= 0 && end <= length);
    begin = NormalizeIndex(begin, length);
    end = NormalizeIndex(end, length);
    if (end <= begin) {
        return;
    }
    if (!GetTypedArrayByteRange(thisArray, static_cast<size_t>(begin), static_cast<size_t>(end - begin), &byteOffset,
                                &byteCount)) {
        return;
    }
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto offset = byteOffset;
    for (auto i = begin; i < end; ++i) {
        ObjectAccessor::SetPrimitive(data, offset, val);
        offset += sizeof(V);
    }
}

extern "C" void EtsEscompatInt8ArrayFillInternal(ark::ets::EtsEscompatInt8Array *thisArray, EtsByte val, EtsInt begin,
                                                 EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatInt16ArraySetInt(ark::ets::EtsEscompatInt16Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" void EtsEscompatInt16ArraySetShort(ark::ets::EtsEscompatInt16Array *thisArray, EtsInt pos, EtsShort val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatInt16ArrayGet(ark::ets::EtsEscompatInt16Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsShort EtsEscompatInt16ArrayGetUnsafe(ark::ets::EtsEscompatInt16Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatInt16ArraySetValues(ark::ets::EtsEscompatInt16Array *thisArray,
                                               ark::ets::EtsEscompatInt16Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatInt16ArraySetValuesFromUnsigned(ark::ets::EtsEscompatInt16Array *thisArray,
                                                           ark::ets::EtsEscompatUInt16Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatInt16ArraySetValuesWithOffset(ark::ets::EtsEscompatInt16Array *thisArray,
                                                         ark::ets::EtsEscompatInt16Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatInt16ArraySetValuesFromArray(ark::ets::EtsEscompatInt16Array *thisArray,
                                                        ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatInt16ArrayFillInternal(ark::ets::EtsEscompatInt16Array *thisArray, EtsShort val,
                                                  EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatInt32ArraySetInt(ark::ets::EtsEscompatInt32Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatInt32ArrayGet(ark::ets::EtsEscompatInt32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsInt EtsEscompatInt32ArrayGetUnsafe(ark::ets::EtsEscompatInt32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatInt32ArraySetValues(ark::ets::EtsEscompatInt32Array *thisArray,
                                               ark::ets::EtsEscompatInt32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatInt32ArraySetValuesWithOffset(ark::ets::EtsEscompatInt32Array *thisArray,
                                                         ark::ets::EtsEscompatInt32Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatInt32ArraySetValuesFromArray(ark::ets::EtsEscompatInt32Array *thisArray,
                                                        ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatInt32ArrayFillInternal(ark::ets::EtsEscompatInt32Array *thisArray, EtsInt val, EtsInt begin,
                                                  EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatBigInt64ArraySetLong(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsInt pos, EtsLong val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsLong EtsEscompatBigInt64ArrayGet(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsLong EtsEscompatBigInt64ArrayGetUnsafe(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatBigInt64ArraySetValues(ark::ets::EtsEscompatBigInt64Array *thisArray,
                                                  ark::ets::EtsEscompatBigInt64Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatBigInt64ArraySetValuesWithOffset(ark::ets::EtsEscompatBigInt64Array *thisArray,
                                                            ark::ets::EtsEscompatBigInt64Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatBigInt64ArraySetValuesFromArray(ark::ets::EtsEscompatBigInt64Array *thisArray,
                                                           ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatBigInt64ArrayFillInternal(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsLong val,
                                                     EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatFloat32ArraySetFloat(ark::ets::EtsEscompatFloat32Array *thisArray, EtsInt pos, EtsFloat val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatFloat32ArrayGet(ark::ets::EtsEscompatFloat32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsFloat EtsEscompatFloat32ArrayGetUnsafe(ark::ets::EtsEscompatFloat32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatFloat32ArraySetValues(ark::ets::EtsEscompatFloat32Array *thisArray,
                                                 ark::ets::EtsEscompatFloat32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatFloat32ArraySetValuesWithOffset(ark::ets::EtsEscompatFloat32Array *thisArray,
                                                           ark::ets::EtsEscompatFloat32Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatFloat32ArraySetValuesFromArray(ark::ets::EtsEscompatFloat32Array *thisArray,
                                                          ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatFloat32ArrayFillInternal(ark::ets::EtsEscompatFloat32Array *thisArray, EtsFloat val,
                                                    EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatFloat32ArrayFillInternalInt(ark::ets::EtsEscompatFloat32Array *thisArray, int32_t val,
                                                       EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatFloat64ArraySetDouble(ark::ets::EtsEscompatFloat64Array *thisArray, EtsInt pos,
                                                 EtsDouble val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatFloat64ArrayGet(ark::ets::EtsEscompatFloat64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsDouble EtsEscompatFloat64ArrayGetUnsafe(ark::ets::EtsEscompatFloat64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatFloat64ArraySetValues(ark::ets::EtsEscompatFloat64Array *thisArray,
                                                 ark::ets::EtsEscompatFloat64Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatFloat64ArraySetValuesWithOffset(ark::ets::EtsEscompatFloat64Array *thisArray,
                                                           ark::ets::EtsEscompatFloat64Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatFloat64ArraySetValuesFromArray(ark::ets::EtsEscompatFloat64Array *thisArray,
                                                          ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatFloat64ArrayFillInternal(ark::ets::EtsEscompatFloat64Array *thisArray, EtsDouble val,
                                                    EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatFloat64ArrayFillInternalInt(ark::ets::EtsEscompatFloat64Array *thisArray, int64_t val,
                                                       EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

extern "C" void EtsEscompatUInt8ClampedArraySetInt(ark::ets::EtsEscompatUInt8ClampedArray *thisArray, EtsInt pos,
                                                   EtsInt val)
{
    if (val > ark::ets::EtsEscompatUInt8ClampedArray::MAX) {
        val = ark::ets::EtsEscompatUInt8ClampedArray::MAX;
    } else if (val < ark::ets::EtsEscompatUInt8ClampedArray::MIN) {
        val = ark::ets::EtsEscompatUInt8ClampedArray::MIN;
    }
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatUInt8ClampedArrayGet(ark::ets::EtsEscompatUInt8ClampedArray *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsInt EtsEscompatUInt8ClampedArrayGetUnsafe(ark::ets::EtsEscompatUInt8ClampedArray *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatUInt8ClampedArraySetValues(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                      ark::ets::EtsEscompatUInt8ClampedArray *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUInt8ClampedArraySetValuesWithOffset(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                                ark::ets::EtsEscompatUInt8ClampedArray *srcArray,
                                                                EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatUint8ClampedArraySetValuesFromArray(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                               ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatUInt8ClampedArrayFillInternal(ark::ets::EtsEscompatUInt8ClampedArray *thisArray, EtsInt val,
                                                         EtsInt begin, EtsInt end)
{
    using ElementType = ark::ets::EtsEscompatUInt8ClampedArray::ElementType;
    EtsEscompatTypedArrayFillInternal(thisArray, static_cast<ElementType>(val), begin, end);
}

extern "C" void EtsEscompatUInt8ArraySetInt(ark::ets::EtsEscompatUInt8Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatUInt8ArrayGet(ark::ets::EtsEscompatUInt8Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsInt EtsEscompatUInt8ArrayGetUnsafe(ark::ets::EtsEscompatUInt8Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatUInt8ArraySetValues(ark::ets::EtsEscompatUInt8Array *thisArray,
                                               ark::ets::EtsEscompatUInt8Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUint8ArraySetValuesFromSigned(ark::ets::EtsEscompatUInt8Array *thisArray,
                                                         ark::ets::EtsEscompatInt8Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUInt8ArraySetValuesWithOffset(ark::ets::EtsEscompatUInt8Array *thisArray,
                                                         ark::ets::EtsEscompatUInt8Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatUint8ArraySetValuesFromArray(ark::ets::EtsEscompatUInt8Array *thisArray,
                                                        ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatUInt8ArrayFillInternal(ark::ets::EtsEscompatUInt8Array *thisArray, EtsInt val, EtsInt begin,
                                                  EtsInt end)
{
    using ElementType = ark::ets::EtsEscompatUInt8Array::ElementType;
    EtsEscompatTypedArrayFillInternal(thisArray, static_cast<ElementType>(val), begin, end);
}

extern "C" void EtsEscompatUInt16ArraySetInt(ark::ets::EtsEscompatUInt16Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatUInt16ArrayGet(ark::ets::EtsEscompatUInt16Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsInt EtsEscompatUInt16ArrayGetUnsafe(ark::ets::EtsEscompatUInt16Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatUInt16ArraySetValues(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                ark::ets::EtsEscompatUInt16Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUint16ArraySetValuesFromSigned(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                          ark::ets::EtsEscompatInt16Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUInt16ArraySetValuesWithOffset(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                          ark::ets::EtsEscompatUInt16Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatUint16ArraySetValuesFromArray(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                         ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatUInt16ArrayFillInternal(ark::ets::EtsEscompatUInt16Array *thisArray, EtsInt val,
                                                   EtsInt begin, EtsInt end)
{
    using ElementType = ark::ets::EtsEscompatUInt16Array::ElementType;
    EtsEscompatTypedArrayFillInternal(thisArray, static_cast<ElementType>(val), begin, end);
}

extern "C" void EtsEscompatUInt32ArraySetInt(ark::ets::EtsEscompatUInt32Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" void EtsEscompatUInt32ArraySetLong(ark::ets::EtsEscompatUInt32Array *thisArray, EtsInt pos, EtsLong val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsDouble EtsEscompatUInt32ArrayGet(ark::ets::EtsEscompatUInt32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsLong EtsEscompatUInt32ArrayGetUnsafe(ark::ets::EtsEscompatUInt32Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatUInt32ArraySetValues(ark::ets::EtsEscompatUInt32Array *thisArray,
                                                ark::ets::EtsEscompatUInt32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUint32ArraySetValuesFromSigned(ark::ets::EtsEscompatUInt32Array *thisArray,
                                                          ark::ets::EtsEscompatInt32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatUInt32ArraySetValuesWithOffset(ark::ets::EtsEscompatUInt32Array *thisArray,
                                                          ark::ets::EtsEscompatUInt32Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatUint32ArraySetValuesFromArray(ark::ets::EtsEscompatUInt32Array *thisArray,
                                                         ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatUInt32ArrayFillInternal(ark::ets::EtsEscompatUInt32Array *thisArray, EtsLong val,
                                                   EtsInt begin, EtsInt end)
{
    using ElementType = ark::ets::EtsEscompatUInt32Array::ElementType;
    EtsEscompatTypedArrayFillInternal(thisArray, static_cast<ElementType>(val), begin, end);
}

extern "C" void EtsEscompatBigUInt64ArraySetInt(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsInt pos, EtsInt val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" void EtsEscompatBigUInt64ArraySetLong(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsInt pos,
                                                 EtsLong val)
{
    EtsEscompatTypedArraySet(thisArray, pos, val);
}

extern "C" EtsLong EtsEscompatBigUInt64ArrayGet(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGet(thisArray, pos);
}

extern "C" EtsLong EtsEscompatBigUInt64ArrayGetUnsafe(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsInt pos)
{
    return EtsEscompatTypedArrayGetUnsafe(thisArray, pos);
}

extern "C" void EtsEscompatBigUInt64ArraySetValues(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                   ark::ets::EtsEscompatBigUInt64Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}

extern "C" void EtsEscompatBigUInt64ArraySetValuesWithOffset(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                             ark::ets::EtsEscompatBigUInt64Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}

extern "C" void EtsEscompatBigUint64ArraySetValuesFromArray(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                            ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}

extern "C" void EtsEscompatBigUInt64ArrayFillInternal(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsLong val,
                                                      EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}

/*
 * Typed Arrays: Reverse Implementation
 */
template <typename T>
static inline T *EtsEscompatTypedArrayReverseImpl(T *thisArray)
{
    auto *arrData = GetNativeData(thisArray);
    if (UNLIKELY(arrData == nullptr)) {
        return nullptr;
    }
    using ElementType = typename T::ElementType;
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *ptrFirst = reinterpret_cast<ElementType *>(ToVoidPtr(ToUintPtr(arrData) + thisArray->GetByteOffset()));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    auto *ptrLast = ptrFirst +
                    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
                    thisArray->GetLengthInt();
    std::reverse(ptrFirst, ptrLast);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    return thisArray;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define REVERSE_CALL_DECL(Type)                                                     \
    /* CC-OFFNXT(G.PRE.02) name part */                                             \
    extern "C" ark::ets::EtsEscompat##Type##Array *EtsEscompat##Type##ArrayReverse( \
        ark::ets::EtsEscompat##Type##Array *thisArray)                              \
    {                                                                               \
        /* CC-OFFNXT(G.PRE.05) function gen */                                      \
        return EtsEscompatTypedArrayReverseImpl(thisArray);                         \
    }  // namespace ark::ets::intrinsics

REVERSE_CALL_DECL(Int8)
REVERSE_CALL_DECL(Int16)
REVERSE_CALL_DECL(Int32)
REVERSE_CALL_DECL(BigInt64)
REVERSE_CALL_DECL(Float32)
REVERSE_CALL_DECL(Float64)

REVERSE_CALL_DECL(UInt8)
REVERSE_CALL_DECL(UInt8Clamped)
REVERSE_CALL_DECL(UInt16)
REVERSE_CALL_DECL(UInt32)
REVERSE_CALL_DECL(BigUInt64)

#undef REVERSE_CALL_DECL

/*
 * Typed Arrays: reversed alloc data implementation: needs for toReversed().
 */
template <typename ElementType>
static ALWAYS_INLINE inline void TypedArrayReverseCopyBuffer(EtsStdCoreArrayBuffer *dstBuf,
                                                             EtsStdCoreArrayBuffer *srcBuf, EtsInt byteOffset,
                                                             EtsInt srcLength)
{
    ASSERT(srcBuf != nullptr);
    ASSERT(dstBuf != nullptr);
    ASSERT(!srcBuf->WasDetached());
    ASSERT(!dstBuf->WasDetached());
    ASSERT(byteOffset >= 0);
    ASSERT(static_cast<unsigned long>(byteOffset) <= (srcLength * sizeof(ElementType)));
    const void *src = srcBuf->GetData();
    auto *dest = dstBuf->GetData<ElementType *>();
    ASSERT(src != nullptr);
    ASSERT(dest != nullptr);
    const ElementType *start = reinterpret_cast<ElementType *>(ToUintPtr(src) + byteOffset);
    std::reverse_copy(start, start + srcLength, dest);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    ASSERT(*dest == *(start + srcLength - 1));          // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define REVERSE_COPY_BUFFER_CALL_DECL(Type)                                                                \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                    \
    extern "C" void EtsEscompat##Type##ArrayReverseCopyBuffer(                                             \
        EtsStdCoreArrayBuffer *dstBuf, EtsStdCoreArrayBuffer *srcBuf, EtsInt byteOffset, EtsInt srcLength) \
    {                                                                                                      \
        using ElementType = EtsEscompat##Type##Array::ElementType;                                         \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                             \
        TypedArrayReverseCopyBuffer<ElementType>(dstBuf, srcBuf, byteOffset, srcLength);                   \
    }  // namespace ark::ets::intrinsics

REVERSE_COPY_BUFFER_CALL_DECL(Int8)
REVERSE_COPY_BUFFER_CALL_DECL(Int16)
REVERSE_COPY_BUFFER_CALL_DECL(Int32)
REVERSE_COPY_BUFFER_CALL_DECL(BigInt64)
REVERSE_COPY_BUFFER_CALL_DECL(Float32)
REVERSE_COPY_BUFFER_CALL_DECL(Float64)

REVERSE_COPY_BUFFER_CALL_DECL(UInt8)
REVERSE_COPY_BUFFER_CALL_DECL(UInt16)
REVERSE_COPY_BUFFER_CALL_DECL(UInt32)
REVERSE_COPY_BUFFER_CALL_DECL(BigUInt64)

#undef REVERSE_COPY_BUFFER_CALL_DECL

template <typename T>
void EtsEscompatTypedArrayCopyWithinImpl(T *thisArray, EtsInt target, EtsInt start, EtsInt count)
{
    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return;
    }

    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto arrayLength = thisArray->GetLengthInt();
    // The managed wrapper clamps `count` against both ends, so a violation here is an internal
    // contract bug. Assert it in debug builds, but clamp in release: `copyWithin` never throws a
    // RangeError per the spec, and clamping still keeps the memmove below inside the array.
    ASSERT(target >= 0 && start >= 0 && target <= arrayLength && start <= arrayLength && count <= arrayLength - start &&
           count <= arrayLength - target);
    if (UNLIKELY(arrayLength <= 0 || count <= 0)) {
        return;
    }
    target = NormalizeIndex(target, arrayLength);
    start = NormalizeIndex(start, arrayLength);
    count = std::min({count, arrayLength - start, arrayLength - target});
    if (count <= 0) {
        return;
    }
    size_t targetOffset = 0;
    size_t targetBytes = 0;
    size_t startOffset = 0;
    size_t startBytes = 0;
    if (!GetTypedArrayByteRange(thisArray, static_cast<size_t>(target), static_cast<size_t>(count), &targetOffset,
                                &targetBytes)) {
        return;
    }
    /**
     * False-positive static-analyzer report:
     * GetTypedArrayByteRange touches the GC only on ThrowException, and that path always reports
     * failure, so reaching this line means no GC happened and `thisArray` is still valid.
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (!GetTypedArrayByteRange(thisArray, static_cast<size_t>(start), static_cast<size_t>(count), &startOffset,
                                &startBytes)) {
        return;
    }
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *targetAddress = ToVoidPtr(ToUintPtr(data) + targetOffset);
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *startAddress = ToVoidPtr(ToUintPtr(data) + startOffset);
    [[maybe_unused]] auto error = memmove_s(targetAddress, targetBytes, startAddress, startBytes);
    ASSERT(error == EOK);
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ETS_ESCOMPAT_COPY_WITHIN(Type)                                                                    \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                   \
    extern "C" void EtsEscompat##Type##ArrayCopyWithinImpl(ark::ets::EtsEscompat##Type##Array *thisArray, \
                                                           EtsInt target, EtsInt start, EtsInt end)       \
    {                                                                                                     \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                            \
        EtsEscompatTypedArrayCopyWithinImpl(thisArray, target, start, end);                               \
    }  // namespace ark::ets::intrinsics

ETS_ESCOMPAT_COPY_WITHIN(Int8)
ETS_ESCOMPAT_COPY_WITHIN(Int16)
ETS_ESCOMPAT_COPY_WITHIN(Int32)
ETS_ESCOMPAT_COPY_WITHIN(BigInt64)
ETS_ESCOMPAT_COPY_WITHIN(Float32)
ETS_ESCOMPAT_COPY_WITHIN(Float64)
ETS_ESCOMPAT_COPY_WITHIN(UInt8)
ETS_ESCOMPAT_COPY_WITHIN(UInt16)
ETS_ESCOMPAT_COPY_WITHIN(UInt32)
ETS_ESCOMPAT_COPY_WITHIN(BigUInt64)
ETS_ESCOMPAT_COPY_WITHIN(UInt8Clamped)

#undef ETS_ESCOMPAT_COPY_WITHIN

template <typename T>
bool Cmp(const typename T::ElementType &left, const typename T::ElementType &right)
{
    const auto lNumber = static_cast<double>(left);
    const auto rNumber = static_cast<double>(right);
    if (std::isnan(lNumber)) {
        return false;
    }
    if (std::isnan(rNumber)) {
        return true;
    }
    return left < right;
}

template <typename T>
T *EtsEscompatTypedArraySortWrapper(T *thisArray, bool withNaN = false)
{
    using ElementType = typename T::ElementType;

    auto nBytes = static_cast<size_t>(thisArray->GetByteLength());
    ASSERT(nBytes == (static_cast<size_t>(thisArray->GetLengthInt()) * sizeof(ElementType)));
    // If it's an empty or one-element array then nothing to sort.
    if (UNLIKELY(nBytes <= sizeof(ElementType))) {
        return thisArray;
    }

    auto *arrayBuffer = static_cast<EtsStdCoreArrayBuffer *>(&*thisArray->GetBuffer());
    if (UNLIKELY(arrayBuffer->WasDetached())) {
        auto executionCtx = EtsExecutionContext::GetCurrent();
        [[maybe_unused]] EtsHandleScope scope(executionCtx);
        EtsHandle<EtsObject> handle(executionCtx, thisArray);
        ThrowEtsException(executionCtx, PlatformTypes(executionCtx)->coreTypeError, "ArrayBuffer was detached");
        return static_cast<T *>(handle.GetPtr());
    }
    void *dataPtr = arrayBuffer->GetData();
    ASSERT(dataPtr != nullptr);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    Span<EtsByte> data(static_cast<EtsByte *>(dataPtr) + static_cast<size_t>(thisArray->GetByteOffset()), nBytes);
    if (withNaN) {
        std::sort(reinterpret_cast<ElementType *>(data.begin()), reinterpret_cast<ElementType *>(data.end()), Cmp<T>);
    } else {
        std::sort(reinterpret_cast<ElementType *>(data.begin()), reinterpret_cast<ElementType *>(data.end()));
    }
    return thisArray;
}

template <typename T>
T *EtsEscompatTypedArraySortWithNaN(T *thisArray)
{
    return EtsEscompatTypedArraySortWrapper(thisArray, true);
}

template <typename T>
T *EtsEscompatTypedArraySort(T *thisArray)
{
    return EtsEscompatTypedArraySortWrapper(thisArray);
}

extern "C" ark::ets::EtsEscompatInt8Array *EtsEscompatInt8ArraySort(ark::ets::EtsEscompatInt8Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatInt16Array *EtsEscompatInt16ArraySort(ark::ets::EtsEscompatInt16Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatInt32Array *EtsEscompatInt32ArraySort(ark::ets::EtsEscompatInt32Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatBigInt64Array *EtsEscompatBigInt64ArraySort(
    ark::ets::EtsEscompatBigInt64Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatFloat32Array *EtsEscompatFloat32ArraySort(ark::ets::EtsEscompatFloat32Array *thisArray)
{
    return EtsEscompatTypedArraySortWithNaN(thisArray);
}

extern "C" ark::ets::EtsEscompatFloat64Array *EtsEscompatFloat64ArraySort(ark::ets::EtsEscompatFloat64Array *thisArray)
{
    return EtsEscompatTypedArraySortWithNaN(thisArray);
}

template <typename Array, typename = std::enable_if_t<std::is_floating_point_v<typename Array::ElementType>>>
static bool EtsEscompatTypedArrayContainsNaN(Array *array, EtsInt pos)
{
    using ElementType = typename Array::ElementType;
    auto length = array->GetLengthInt();
    auto byteOffset = static_cast<size_t>(array->GetByteOffset());
    uint32_t normalIndex = NormalizeIndex(pos, length);
    auto *data = GetNativeData(array);
    if (UNLIKELY(data == nullptr)) {
        return false;
    }
    auto *begin = ToVoidPtr(ToUintPtr(data) + byteOffset);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    Span<ElementType> span(static_cast<ElementType *>(begin) + normalIndex, length - normalIndex);
    return std::any_of(span.begin(), span.end(), [](ElementType elem) { return elem != elem; });
}

extern "C" EtsBoolean EtsEscompatFloat32ArrayContainsNaN(ark::ets::EtsEscompatFloat32Array *thisArray, EtsInt pos)
{
    return ToEtsBoolean(EtsEscompatTypedArrayContainsNaN(thisArray, pos));
}

extern "C" EtsBoolean EtsEscompatFloat64ArrayContainsNaN(ark::ets::EtsEscompatFloat64Array *thisArray, EtsInt pos)
{
    return ToEtsBoolean(EtsEscompatTypedArrayContainsNaN(thisArray, pos));
}

extern "C" ark::ets::EtsEscompatUInt8ClampedArray *EtsEscompatUInt8ClampedArraySort(
    ark::ets::EtsEscompatUInt8ClampedArray *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatUInt8Array *EtsEscompatUInt8ArraySort(ark::ets::EtsEscompatUInt8Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatUInt16Array *EtsEscompatUInt16ArraySort(ark::ets::EtsEscompatUInt16Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatUInt32Array *EtsEscompatUInt32ArraySort(ark::ets::EtsEscompatUInt32Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

extern "C" ark::ets::EtsEscompatBigUInt64Array *EtsEscompatBigUInt64ArraySort(
    ark::ets::EtsEscompatBigUInt64Array *thisArray)
{
    return EtsEscompatTypedArraySort(thisArray);
}

#define INVALID_INDEX (-1)

template <typename T, typename Pred>
static EtsInt EtsEscompatTypedArrayIndexOf(T *thisArray, EtsInt fromIndex, Pred pred)
{
    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return INVALID_INDEX;
    }

    using ElementType = typename T::ElementType;
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *array = reinterpret_cast<ElementType *>(ToUintPtr(data) + static_cast<int>(thisArray->GetByteOffset()));
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto arrayLength = thisArray->GetLengthInt();
    fromIndex = NormalizeIndex(fromIndex, arrayLength);
    Span<ElementType> span(static_cast<ElementType *>(array), arrayLength);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const auto idxIt = std::find_if(span.begin() + fromIndex, span.end(), pred);
    return idxIt == span.end() ? INVALID_INDEX : std::distance(span.begin(), idxIt);
}

template <typename T>
static EtsInt EtsEscompatTypedArrayIndexOfNumber(T *thisArray, double searchElement, EtsInt fromIndex);

template <typename T, typename SE>
static EtsInt EtsEscompatTypedArrayIndexOfLong(T *thisArray, SE searchElement, EtsInt fromIndex)
{
    using ElementType = typename T::ElementType;
    if constexpr (std::is_same_v<ElementType, int64_t> || std::is_same_v<ElementType, uint64_t>) {
        // 64-bit integer arrays: preserve exact element-type comparison.
        // BigInt search elements may carry values outside int64 range (wrapped by getLong),
        // so double-domain comparison would be incorrect. static_cast to the element type
        // correctly unwraps via two's complement.
        return EtsEscompatTypedArrayIndexOf(
            thisArray, fromIndex,
            [element = static_cast<ElementType>(searchElement)](ElementType e) { return e == element; });
    } else {
        // ECMAScript semantics: compare in Number (double) domain via SameValueZero.
        // Delegate to IndexOfNumber which promotes each element to double and handles NaN.
        return EtsEscompatTypedArrayIndexOfNumber(thisArray, static_cast<double>(searchElement), fromIndex);
    }
}

template <typename T>
static EtsInt EtsEscompatTypedArrayIndexOfNumber(T *thisArray, double searchElement, EtsInt fromIndex)
{
    if (std::isnan(searchElement)) {
        return INVALID_INDEX;
    }

    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return INVALID_INDEX;
    }

    using ElementType = typename T::ElementType;
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *array = reinterpret_cast<ElementType *>(ToUintPtr(data) + static_cast<int>(thisArray->GetByteOffset()));
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto arrayLength = thisArray->GetLengthInt();
    fromIndex = NormalizeIndex(fromIndex, arrayLength);
    for (int i = fromIndex; i < arrayLength; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if (static_cast<double>(array[i]) == searchElement) {
            return i;
        }
    }
    return INVALID_INDEX;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ETS_ESCOMPAT_INDEX_OF_NUMBER(Type)                                                                 \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                    \
    extern "C" EtsInt EtsEscompat##Type##ArrayIndexOfNumber(ark::ets::EtsEscompat##Type##Array *thisArray, \
                                                            EtsDouble searchElement, EtsInt fromIndex)     \
    {                                                                                                      \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                             \
        return EtsEscompatTypedArrayIndexOfNumber(thisArray, searchElement, fromIndex);                    \
    }  // namespace ark::ets::intrinsics

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ETS_ESCOMPAT_INDEX_OF_LONG(Type)                                                                 \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                  \
    extern "C" EtsInt EtsEscompat##Type##ArrayIndexOfLong(ark::ets::EtsEscompat##Type##Array *thisArray, \
                                                          EtsLong searchElement, EtsInt fromIndex)       \
    {                                                                                                    \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                           \
        return EtsEscompatTypedArrayIndexOfLong(thisArray, searchElement, fromIndex);                    \
    }  // namespace ark::ets::intrinsics

ETS_ESCOMPAT_INDEX_OF_NUMBER(Int8)
ETS_ESCOMPAT_INDEX_OF_NUMBER(Int16)
ETS_ESCOMPAT_INDEX_OF_NUMBER(Int32)
ETS_ESCOMPAT_INDEX_OF_NUMBER(BigInt64)
ETS_ESCOMPAT_INDEX_OF_NUMBER(Float32)
ETS_ESCOMPAT_INDEX_OF_NUMBER(Float64)
ETS_ESCOMPAT_INDEX_OF_NUMBER(UInt8)
ETS_ESCOMPAT_INDEX_OF_NUMBER(UInt16)
ETS_ESCOMPAT_INDEX_OF_NUMBER(UInt32)
ETS_ESCOMPAT_INDEX_OF_NUMBER(BigUInt64)
ETS_ESCOMPAT_INDEX_OF_NUMBER(UInt8Clamped)
ETS_ESCOMPAT_INDEX_OF_LONG(Int8)
ETS_ESCOMPAT_INDEX_OF_LONG(Int16)
ETS_ESCOMPAT_INDEX_OF_LONG(Int32)
ETS_ESCOMPAT_INDEX_OF_LONG(BigInt64)
ETS_ESCOMPAT_INDEX_OF_LONG(Float32)
ETS_ESCOMPAT_INDEX_OF_LONG(Float64)
ETS_ESCOMPAT_INDEX_OF_LONG(UInt8)
ETS_ESCOMPAT_INDEX_OF_LONG(UInt16)
ETS_ESCOMPAT_INDEX_OF_LONG(UInt32)
ETS_ESCOMPAT_INDEX_OF_LONG(BigUInt64)
ETS_ESCOMPAT_INDEX_OF_LONG(UInt8Clamped)

template <typename T>
static EtsInt EtsEscompatTypedArrayLastIndexOfNumber(T *thisArray, double searchElement, EtsInt fromIndex);

template <typename T1, typename T2>
static EtsInt EtsEscompatTypedArrayLastIndexOfLong(T1 *thisArray, T2 searchElement, EtsInt fromIndex)
{
    using ElementType = typename T1::ElementType;
    if constexpr (std::is_same_v<ElementType, int64_t> || std::is_same_v<ElementType, uint64_t>) {
        // 64-bit integer arrays: preserve exact element-type comparison (see IndexOfLong).
        auto *data = GetNativeData(thisArray);
        if (UNLIKELY(data == nullptr)) {
            return INVALID_INDEX;
        }
        // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
        int arrayLength = thisArray->GetLengthInt();
        if (arrayLength == 0) {
            return INVALID_INDEX;
        }

        int startIndex = arrayLength + fromIndex;
        if (fromIndex >= 0) {
            startIndex = (arrayLength - 1 < fromIndex) ? arrayLength - 1 : fromIndex;
        }

        /**
         * False-positive static-analyzer report:
         * GC can happen only on ThrowException in GetNativeData.
         * But such case meaning data to be nullptr and retun prevents
         * us from proceeding
         */
        // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
        auto *array = reinterpret_cast<ElementType *>(ToUintPtr(data) + static_cast<int>(thisArray->GetByteOffset()));
        auto element = static_cast<ElementType>(searchElement);
        for (int i = startIndex; i >= 0; i--) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            if (array[i] == element) {
                return i;
            }
        }
        return INVALID_INDEX;
    } else {
        // ECMAScript semantics: compare in Number (double) domain via SameValueZero.
        return EtsEscompatTypedArrayLastIndexOfNumber(thisArray, static_cast<double>(searchElement), fromIndex);
    }
}

template <typename T>
static EtsInt EtsEscompatTypedArrayLastIndexOfNumber(T *thisArray, double searchElement, EtsInt fromIndex)
{
    if (std::isnan(searchElement)) {
        return INVALID_INDEX;
    }

    auto *data = GetNativeData(thisArray);
    if (UNLIKELY(data == nullptr)) {
        return INVALID_INDEX;
    }

    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    int arrayLength = thisArray->GetLengthInt();
    if (arrayLength == 0) {
        return INVALID_INDEX;
    }

    int startIndex = arrayLength + fromIndex;
    if (fromIndex >= 0) {
        startIndex = (arrayLength - 1 < fromIndex) ? arrayLength - 1 : fromIndex;
    }

    using ElementType = typename T::ElementType;
    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    auto *array = reinterpret_cast<ElementType *>(ToUintPtr(data) + static_cast<int>(thisArray->GetByteOffset()));
    for (int i = startIndex; i >= 0; i--) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if (static_cast<double>(array[i]) == searchElement) {
            return i;
        }
    }

    return INVALID_INDEX;
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Type)                                                                \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                        \
    extern "C" EtsInt EtsEscompat##Type##ArrayLastIndexOfNumber(ark::ets::EtsEscompat##Type##Array *thisArray, \
                                                                EtsDouble searchElement, EtsInt fromIndex)     \
    {                                                                                                          \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                                 \
        return EtsEscompatTypedArrayLastIndexOfNumber(thisArray, searchElement, fromIndex);                    \
    }  // namespace ark::ets::intrinsics

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Type)                                                                \
    /* CC-OFFNXT(G.PRE.02) name part */                                                                      \
    extern "C" EtsInt EtsEscompat##Type##ArrayLastIndexOfLong(ark::ets::EtsEscompat##Type##Array *thisArray, \
                                                              EtsLong searchElement, EtsInt fromIndex)       \
    {                                                                                                        \
        /* CC-OFFNXT(G.PRE.05) function gen */                                                               \
        return EtsEscompatTypedArrayLastIndexOfLong(thisArray, searchElement, fromIndex);                    \
    }  // namespace ark::ets::intrinsics

ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Int8)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Int16)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Int32)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(BigInt64)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Float32)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(Float64)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(UInt8)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(UInt16)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(UInt32)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(BigUInt64)
ETS_ESCOMPAT_LAST_INDEX_OF_NUMBER(UInt8Clamped)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Int8)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Int16)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Int32)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(BigInt64)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Float32)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(Float64)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(UInt8)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(UInt16)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(UInt32)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(BigUInt64)
ETS_ESCOMPAT_LAST_INDEX_OF_LONG(UInt8Clamped)

#undef INVALID_INDEX

/* Compute a max size in chars required for not null-terminated string
 * representation of the specified integral or floating point type.
 */
template <typename T>
constexpr size_t MaxChars()
{
    static_assert(std::numeric_limits<T>::radix == 2U);
    if constexpr (std::is_integral_v<T>) {
        auto bits = std::numeric_limits<T>::digits;
        auto digitPerBit = std::log10(std::numeric_limits<T>::radix);
        auto digits = std::ceil(bits * digitPerBit) + static_cast<int>(std::is_signed_v<T>);
        return digits;
    } else {
        static_assert(std::is_floating_point_v<T>);
        auto bits = std::numeric_limits<double>::digits;
        auto digitPerBit = std::log10(std::numeric_limits<double>::radix);
        auto sigDigits = static_cast<size_t>(std::ceil(bits * digitPerBit)) + 1U;
        return static_cast<size_t>(std::is_signed_v<double>) + 1U + 1U + 5U + sigDigits;
    }
}

template <typename T>
size_t NumberToU8Chars(PandaVector<char> &buf, size_t pos, T number)
{
    if constexpr (std::is_integral_v<T>) {
        auto [strEnd, result] = std::to_chars(&buf[pos], &buf[pos + MaxChars<T>()], number);
        ASSERT(result == std::errc());
        return strEnd - &buf[pos];
    } else {
        static_assert(std::is_floating_point_v<T>);
        // Forced to treat T as double
        auto asDouble = static_cast<double>(number);
        return intrinsics::helpers::FpToStringDecimalRadix(asDouble, [&buf, &pos](std::string_view str) {
            ASSERT(str.length() <= MaxChars<T>());
            auto err = memcpy_s(&buf[pos], MaxChars<T>(), str.data(), str.length());
            if (err != EOK) {
                UNREACHABLE();
            }
            return str.length();
        });
    }
}

template <typename T>
size_t NumberToU16Chars(PandaVector<EtsChar> &buf, size_t pos, T number)
{
    if constexpr (std::is_integral_v<T>) {
        auto num = number < 0 ? -static_cast<uint64_t>(number) : static_cast<uint64_t>(number);
        auto nDigits = (CountDigits(num) + static_cast<uint32_t>(number < 0));
        ASSERT(pos + nDigits <= buf.size());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        utf::UInt64ToUtf16Array(num, buf.data() + pos, nDigits, number < 0);
        return nDigits;
    } else {
        static_assert(std::is_floating_point_v<T>);
        static_assert(std::is_unsigned_v<EtsChar>);
        // Forced to treat T as double
        auto asDouble = static_cast<double>(number);
        return intrinsics::helpers::FpToStringDecimalRadix(asDouble, [&buf, &pos](std::string_view str) {
            ASSERT(str.length() <= MaxChars<T>());
            for (size_t i = 0; i < str.length(); i++) {
                buf[pos + i] = static_cast<EtsChar>(str[i]);
            }
            return str.length();
        });
    }
}

template <typename T>
static ark::ets::EtsString *TypedArrayJoinUtf16(Span<T> &data, ark::ets::EtsString *separator)
{
    ASSERT(!data.empty());
    ASSERT(separator->IsUtf16());

    const size_t sepSize = separator->GetUtf16Length();
    size_t elementSize = 0;
    size_t allocationSize = 0;
    if (UNLIKELY(!CheckedAdd(MaxChars<T>(), sepSize, &elementSize) ||
                 !CheckedMul(data.Size(), elementSize, &allocationSize))) {
        ThrowRangeError("typed array join result is too large");
        return nullptr;
    }
    PandaVector<EtsChar> buf(allocationSize);
    size_t strSize = 0;
    auto n = data.Size() - 1;
    if (sepSize == 1) {
        PandaVector<uint16_t> tree16Buf;
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        auto sep =
            separator->IsTreeString() ? separator->GetTreeStringDataUtf16(tree16Buf)[0] : separator->GetDataUtf16()[0];
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (auto i = 0U; i < n; i++) {
            strSize += NumberToU16Chars(buf, strSize, static_cast<T>(data[i]));
            buf[strSize] = sep;
            strSize += 1;
        }
    } else {
        for (auto i = 0U; i < n; i++) {
            strSize += NumberToU16Chars(buf, strSize, static_cast<T>(data[i]));
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            separator->CopyDataUtf16(buf.data() + strSize, sepSize);
            strSize += sepSize;
        }
    }
    strSize += NumberToU16Chars(buf, strSize, static_cast<T>(data[n]));
    return EtsString::CreateFromUtf16(reinterpret_cast<EtsChar *>(buf.data()), strSize);
}

template <typename T>
static ark::ets::EtsString *TypedArrayJoinUtf8(Span<T> &data)
{
    ASSERT(!data.empty());
    size_t allocationSize = 0;
    if (UNLIKELY(!CheckedMul(data.Size(), MaxChars<T>(), &allocationSize))) {
        ThrowRangeError("typed array join result is too large");
        return nullptr;
    }
    PandaVector<char> buf(allocationSize);
    size_t strSize = 0;
    auto n = data.Size();
    for (auto i = 0U; i < n; i++) {
        strSize += NumberToU8Chars(buf, strSize, data[i]);
    }
    return EtsString::CreateFromUtf8(buf.data(), strSize);
}

template <typename T>
static ark::ets::EtsString *TypedArrayJoinUtf8(Span<T> &data, ark::ets::EtsString *separator)
{
    ASSERT(!data.empty());
    ASSERT(!separator->IsUtf16() && !separator->IsEmpty());
    const size_t sepSize = separator->GetUtf8Length();
    size_t elementSize = 0;
    size_t allocationSize = 0;
    if (UNLIKELY(!CheckedAdd(MaxChars<T>(), sepSize, &elementSize) ||
                 !CheckedMul(data.Size(), elementSize, &allocationSize))) {
        ThrowRangeError("typed array join result is too large");
        return nullptr;
    }
    PandaVector<char> buf(allocationSize);
    size_t strSize = 0;
    auto n = data.Size() - 1;
    if (sepSize == 1) {
        PandaVector<uint8_t> tree8Buf;
        // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        auto sep =
            separator->IsTreeString() ? separator->GetTreeStringDataUtf8(tree8Buf)[0] : separator->GetDataUtf8()[0];
        // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        for (auto i = 0U; i < n; i++) {
            strSize += NumberToU8Chars(buf, strSize, data[i]);
            buf[strSize] = sep;
            strSize += 1;
        }
    } else {
        for (auto i = 0U; i < n; i++) {
            strSize += NumberToU8Chars(buf, strSize, data[i]);
            separator->CopyDataMUtf8(&buf[strSize], sepSize, false);
            strSize += sepSize;
        }
    }
    strSize += NumberToU8Chars(buf, strSize, data[n]);
    return EtsString::CreateFromUtf8(buf.data(), strSize);
}

template <typename T>
static ark::ets::EtsString *TypedArrayJoin(T *thisArray, ark::ets::EtsString *separator)
{
    using ElementType = typename T::ElementType;

    auto length = thisArray->GetLengthInt();
    if (UNLIKELY(length <= 0)) {
        return EtsString::CreateNewEmptyString();
    }

    void *dataPtr = GetNativeData(thisArray);
    if (UNLIKELY(dataPtr == nullptr)) {
        return nullptr;
    }

    /**
     * False-positive static-analyzer report:
     * GC can happen only on ThrowException in GetNativeData.
     * But such case meaning data to be nullptr and retun prevents
     * us from proceeding
     */
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    auto *tyDataPtr = reinterpret_cast<ElementType *>(static_cast<EtsByte *>(dataPtr) +
                                                      // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
                                                      static_cast<size_t>(thisArray->GetByteOffset()));
    Span<ElementType> data(tyDataPtr, length);
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (separator->IsEmpty()) {
        return TypedArrayJoinUtf8(data);
    }
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    if (!separator->IsUtf16()) {
        // See (GetNativeData) reason
        // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
        return TypedArrayJoinUtf8(data, separator);
    }
    // See (GetNativeData) reason
    // SUPPRESS_CSA_NEXTLINE(alpha.core.WasteObjHeader)
    return TypedArrayJoinUtf16(data, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatInt8ArrayJoin(ark::ets::EtsEscompatInt8Array *thisArray,
                                                         ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatUint8ArrayJoin(ark::ets::EtsEscompatUInt8Array *thisArray,
                                                          ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatUint8ClampedArrayJoin(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                                 ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatInt16ArrayJoin(ark::ets::EtsEscompatInt16Array *thisArray,
                                                          ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatUint16ArrayJoin(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                           ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatInt32ArrayJoin(ark::ets::EtsEscompatInt32Array *thisArray,
                                                          ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatUint32ArrayJoin(ark::ets::EtsEscompatUInt32Array *thisArray,
                                                           ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatBigInt64ArrayJoin(ark::ets::EtsEscompatBigInt64Array *thisArray,
                                                             ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatBigUint64ArrayJoin(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                              ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatFloat32ArrayJoin(ark::ets::EtsEscompatFloat32Array *thisArray,
                                                            ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" ark::ets::EtsString *EtsEscompatFloat64ArrayJoin(ark::ets::EtsEscompatFloat64Array *thisArray,
                                                            ark::ets::EtsString *separator)
{
    return TypedArrayJoin(thisArray, separator);
}

extern "C" EtsInt TypedArrayDoubleToInt(EtsDouble val, uint32_t bits = INT32_BITS)
{
    int32_t ret = 0;
    auto u64 = bit_cast<uint64_t>(val);
    int exp = static_cast<int>((u64 & DOUBLE_EXPONENT_MASK) >> DOUBLE_SIGNIFICAND_SIZE) - DOUBLE_EXPONENT_BIAS;
    if (exp < static_cast<int>(bits - 1)) {
        // smaller than INT<bits>_MAX, fast conversion
        ret = static_cast<int32_t>(val);
    } else if (exp < static_cast<int>(bits + DOUBLE_SIGNIFICAND_SIZE)) {
        // Still has significand bits after mod 2^<bits>
        // Get low <bits> bits by shift left <64 - bits> and shift right <64 - bits>
        uint64_t value = (((u64 & DOUBLE_SIGNIFICAND_MASK) | DOUBLE_HIDDEN_BIT)
                          << (static_cast<uint32_t>(exp) - DOUBLE_SIGNIFICAND_SIZE + INT64_BITS - bits)) >>
                         (INT64_BITS - bits);
        ret = static_cast<int32_t>(value);
        if ((u64 & DOUBLE_SIGN_MASK) == DOUBLE_SIGN_MASK && ret != INT32_MIN) {
            ret = -ret;
        }
    } else {
        // No significand bits after mod 2^<bits>, contains NaN and INF
        ret = 0;
    }
    return ret;
}

extern "C" EtsInt TypedArrayDoubleToInt32(EtsDouble val)
{
    return TypedArrayDoubleToInt(val, INT32_BITS);
}

extern "C" EtsShort TypedArrayDoubleToInt16(EtsDouble val)
{
    return TypedArrayDoubleToInt(val, INT16_BITS);
}

extern "C" EtsByte TypedArrayDoubleToInt8(EtsDouble val)
{
    return TypedArrayDoubleToInt(val, INT8_BITS);
}

extern "C" EtsLong TypedArrayDoubleToUint32(EtsDouble val)
{
    // Convert to int32_t first, then cast to uint32_t
    auto ret = TypedArrayDoubleToInt(val, INT32_BITS);
    auto pTmp = reinterpret_cast<uint32_t *>(&ret);
    return static_cast<EtsLong>(static_cast<uint32_t>(*pTmp));
}

extern "C" EtsInt TypedArrayDoubleToUint16(EtsDouble val)
{
    // Convert to int16_t first, then cast to uint16_t
    auto ret = TypedArrayDoubleToInt(val, INT16_BITS);
    auto pTmp = reinterpret_cast<int16_t *>(&ret);
    return static_cast<EtsInt>(static_cast<uint16_t>(*pTmp));
}

extern "C" EtsInt TypedArrayDoubleToUint8(EtsDouble val)
{
    // Convert to int8_t first, then cast to uint8_t
    auto ret = TypedArrayDoubleToInt(val, 8);
    auto pTmp = reinterpret_cast<uint8_t *>(&ret);
    return static_cast<EtsInt>(reinterpret_cast<uint8_t>(*pTmp));
}

template <typename T>
static T CastNumberHelper(double val) = delete;

template <typename T>
static T CastNumber(double val)
{
    if (std::isinf(val)) {
        return 0;
    }
    if (std::isnan(val)) {
        return 0;
    }
    return CastNumberHelper<T>(val);
}

template <>
EtsByte CastNumberHelper(double val)
{
    return TypedArrayDoubleToInt8(val);
}

template <>
EtsShort CastNumberHelper(double val)
{
    return TypedArrayDoubleToInt16(val);
}

template <>
EtsInt CastNumberHelper(double val)
{
    return TypedArrayDoubleToInt32(val);
}

template <>
EtsLong CastNumberHelper(double val)
{
    return StdCoreDoubleToLong(val);
}

template <typename T>
static T CastNumberUnsignedHelper(double val) = delete;

template <typename T>
static T CastNumberUnsigned(double val)
{
    if (std::isinf(val)) {
        return 0;
    }
    return CastNumberUnsignedHelper<T>(val);
}

template <>
uint8_t CastNumberUnsignedHelper(double val)
{
    auto ret = TypedArrayDoubleToInt(val, INT8_BITS);
    auto pTmp = reinterpret_cast<uint8_t *>(&ret);
    return reinterpret_cast<uint8_t>(*pTmp);
}

template <>
uint16_t CastNumberUnsignedHelper(double val)
{
    auto ret = TypedArrayDoubleToInt(val, INT16_BITS);
    auto pTmp = reinterpret_cast<uint16_t *>(&ret);
    return static_cast<uint16_t>(*pTmp);
}

template <>
uint32_t CastNumberUnsignedHelper(double val)
{
    auto ret = TypedArrayDoubleToInt(val, INT32_BITS);
    auto pTmp = reinterpret_cast<uint32_t *>(&ret);
    return static_cast<uint32_t>(*pTmp);
}

template <typename T1, typename T2, typename Convert>
static void EtsEscompatTypedArrayOfImpl(T1 *thisArray, EtsCharArray *srcArray, Convert convert)
{
    if (UNLIKELY(srcArray == nullptr)) {
        ThrowNullPointerError("typed array source is null");
        return;
    }
    auto *arrayPtr = GetNativeData(thisArray);
    if (UNLIKELY(arrayPtr == nullptr)) {
        return;
    }

    using ElementType = typename T1::ElementType;
    const auto length = thisArray->GetLengthInt();
    size_t dstOffset = 0;
    size_t dstBytes = 0;
    if (UNLIKELY(length < 0 || srcArray->GetElementSize() != sizeof(T2) ||
                 static_cast<size_t>(length) > srcArray->GetLength() ||
                 !GetTypedArrayByteRange(thisArray, 0, static_cast<size_t>(length), &dstOffset, &dstBytes))) {
        if (!EtsExecutionContext::GetCurrent()->GetMT()->HasPendingException()) {
            ThrowRangeError("typed array source or destination is too small");
        }
        return;
    }
    if (length == 0) {
        return;
    }
    auto *srcData = srcArray->GetCoreType()->GetData();
    if (UNLIKELY(srcData == nullptr)) {
        ThrowNullPointerError("typed array source data is null");
        return;
    }
    auto *src = reinterpret_cast<T2 *>(srcData);
    auto *dst = reinterpret_cast<ElementType *>(ToUintPtr(arrayPtr) + dstOffset);
    for (EtsInt i = 0; i < length; ++i) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        dst[i] = convert(src[i]);
    }
}

template <typename T1, typename T2>
static void EtsEscompatTypedArrayOfImpl(T1 *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<T1, T2>(thisArray, src, [](T2 value) { return value; });
}

static int Clamp(double val)
{
    const int minUint8 = 0;
    const int maxUint8 = 255;
    if (std::isnan(val)) {
        return minUint8;
    }
    if (val > maxUint8) {
        val = maxUint8;
    } else if (val < minUint8) {
        val = minUint8;
    }
    return std::lrint(val);
}

template <typename T1, typename T2>
static void EtsEscompatTypedArrayOfImplNumber(T1 *thisArray, EtsCharArray *src)
{
    using ElementType = typename T1::ElementType;
    EtsEscompatTypedArrayOfImpl<T1, T2>(thisArray, src, [](T2 value) { return CastNumber<ElementType>(value); });
}

template <typename T1, typename T2>
static void EtsEscompatTypedArrayOfImplNumberUnsigned(T1 *thisArray, EtsCharArray *src)
{
    using ElementType = typename T1::ElementType;
    EtsEscompatTypedArrayOfImpl<T1, T2>(thisArray, src,
                                        [](T2 value) { return CastNumberUnsigned<ElementType>(value); });
}

template <typename T1, typename T2>
static void EtsEscompatTypedArrayOfImplClamped(T1 *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<T1, T2>(thisArray, src, [](T2 value) { return Clamp(value); });
}

extern "C" void EtsEscompatInt8ArrayOfInt(ark::ets::EtsEscompatInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatInt8Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatInt8ArrayOfNumber(ark::ets::EtsEscompatInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumber<EtsEscompatInt8Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatInt8ArrayOfByte(ark::ets::EtsEscompatInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatInt8Array, EtsByte>(thisArray, src);
}

extern "C" void EtsEscompatInt16ArrayOfInt(ark::ets::EtsEscompatInt16Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatInt16Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatInt16ArrayOfNumber(ark::ets::EtsEscompatInt16Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumber<EtsEscompatInt16Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatInt16ArrayOfShort(ark::ets::EtsEscompatInt16Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatInt16Array, EtsShort>(thisArray, src);
}

extern "C" void EtsEscompatInt32ArrayOfInt(ark::ets::EtsEscompatInt32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatInt32Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatInt32ArrayOfNumber(ark::ets::EtsEscompatInt32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumber<EtsEscompatInt32Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatBigInt64ArrayOfInt(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatBigInt64Array, EtsInt>(thisArray, src);
}

template <typename T, typename ToLong>
void EtsEscompatTypedArrayOfBigIntImpl(T *thisArray, EtsTypedObjectArray<EtsBigInt> *src, ToLong toLong)
{
    if (UNLIKELY(src == nullptr)) {
        ThrowNullPointerError("typed array source is null");
        return;
    }
    auto *arrayPtr = GetNativeData(thisArray);
    if (UNLIKELY(arrayPtr == nullptr)) {
        return;
    }

    using ElementType = typename T::ElementType;
    size_t dstOffset = 0;
    size_t dstBytes = 0;
    if (!GetTypedArrayByteRange(thisArray, 0, src->GetLength(), &dstOffset, &dstBytes)) {
        return;
    }
    for (size_t i = 0; i < src->GetLength(); ++i) {
        if (UNLIKELY(src->Get(i) == nullptr)) {
            ThrowNullPointerError("BigInt source element is null");
            return;
        }
    }
    auto *dst = reinterpret_cast<ElementType *>(ToUintPtr(arrayPtr) + dstOffset);
    std::generate_n(dst, src->GetLength(), [idx = 0, src, toLong]() mutable { return toLong(src->Get(idx++)); });
}

extern "C" void EtsEscompatBigInt64ArrayOfBigInt(ark::ets::EtsEscompatBigInt64Array *thisArray, ark::ObjectHeader *src)
{
    // The method fills the typed array from a FixedArray<bigint> and in contrast to
    // EtsEscompatBigInt64ArraySetValuesFromArray, which fills a typed array from std.core.Array<bigint>, we can be
    // sure that `src` is an instance of the EtsTypedObjectArray<EtsBigInt> class.
    EtsEscompatTypedArrayOfBigIntImpl(thisArray,
                                      src == nullptr ? nullptr : EtsTypedObjectArray<EtsBigInt>::FromCoreType(src),
                                      [](EtsBigInt *bigint) { return unbox::GetLong(bigint); });
}

extern "C" void EtsEscompatBigInt64ArrayOfLong(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatBigInt64Array, EtsLong>(thisArray, src);
}

extern "C" void EtsEscompatBigInt64ArrayOfNumber(ark::ets::EtsEscompatBigInt64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumber<EtsEscompatBigInt64Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatFloat32ArrayOfInt(ark::ets::EtsEscompatFloat32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatFloat32Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatFloat32ArrayOfFloat(ark::ets::EtsEscompatFloat32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatFloat32Array, EtsFloat>(thisArray, src);
}

extern "C" void EtsEscompatFloat32ArrayOfNumber(ark::ets::EtsEscompatFloat32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatFloat32Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatFloat64ArrayOfInt(ark::ets::EtsEscompatFloat64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatFloat64Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatFloat64ArrayOfNumber(ark::ets::EtsEscompatFloat64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatFloat64Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatUint8ClampedArrayOfNumber(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                     EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplClamped<EtsEscompatUInt8ClampedArray, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatUint8ClampedArrayOfInt(ark::ets::EtsEscompatUInt8ClampedArray *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplClamped<EtsEscompatUInt8ClampedArray, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatUint8ClampedArrayOfShort(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                    EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplClamped<EtsEscompatUInt8ClampedArray, EtsShort>(thisArray, src);
}

extern "C" void EtsEscompatUint8ArrayOfNumber(ark::ets::EtsEscompatUInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumberUnsigned<EtsEscompatUInt8Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatUint8ArrayOfInt(ark::ets::EtsEscompatUInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatUInt8Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatUint8ArrayOfShort(ark::ets::EtsEscompatUInt8Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatUInt8Array, EtsShort>(thisArray, src);
}

extern "C" void EtsEscompatUint16ArrayOfNumber(ark::ets::EtsEscompatUInt16Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumberUnsigned<EtsEscompatUInt16Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatUint16ArrayOfInt(ark::ets::EtsEscompatUInt16Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatUInt16Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatUint32ArrayOfNumber(ark::ets::EtsEscompatUInt32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImplNumberUnsigned<EtsEscompatUInt32Array, EtsDouble>(thisArray, src);
}

extern "C" void EtsEscompatUint32ArrayOfInt(ark::ets::EtsEscompatUInt32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatUInt32Array, EtsUint>(thisArray, src);
}

extern "C" void EtsEscompatUint32ArrayOfLong(ark::ets::EtsEscompatUInt32Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatUInt32Array, EtsLong>(thisArray, src);
}

extern "C" void EtsEscompatBigUint64ArrayOfInt(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatBigUInt64Array, EtsInt>(thisArray, src);
}

extern "C" void EtsEscompatBigUint64ArrayOfLong(ark::ets::EtsEscompatBigUInt64Array *thisArray, EtsCharArray *src)
{
    EtsEscompatTypedArrayOfImpl<EtsEscompatBigUInt64Array, EtsLong>(thisArray, src);
}

extern "C" void EtsEscompatBigUint64ArrayOfBigInt(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                  ark::ObjectHeader *src)
{
    // The method fills the typed array from a FixedArray<bigint> and in contrast to
    // EtsEscompatBigUint64ArraySetValuesFromArray, which fills a typed array from std.core.Array<bigint>, we can be
    // sure that `src` is an instance of the EtsTypedObjectArray<EtsBigInt> class.
    EtsEscompatTypedArrayOfBigIntImpl(thisArray,
                                      src == nullptr ? nullptr : EtsTypedObjectArray<EtsBigInt>::FromCoreType(src),
                                      [](EtsBigInt *bigint) { return unbox::GetULong(bigint); });
}
}  // namespace ark::ets::intrinsics
