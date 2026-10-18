# Independent C-line holdout review packet

Review the source excerpts below without access to detector predictions. For each ID, label model applicability (`in_scope`, `out_of_scope`, or `unknown`), behavior/evidence (`candidate`, `repair`, `safe`, `blocked`, or `unknown`), and root cause. Cite source lines and mark unknown when type/build/runtime dependencies are insufficient. These excerpts alone cannot establish product impact.

## H001

````cpp
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
````

## H002

````cpp
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
````

## H003

````cpp
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
````

## H004

````cpp
extern "C" void EtsEscompatFloat32ArrayFillInternalInt(ark::ets::EtsEscompatFloat32Array *thisArray, int32_t val,
                                                       EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}
````

## H005

````cpp
extern "C" void EtsEscompatFloat64ArrayFillInternal(ark::ets::EtsEscompatFloat64Array *thisArray, EtsDouble val,
                                                    EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}
````

## H006

````cpp
extern "C" void EtsEscompatFloat64ArrayFillInternalInt(ark::ets::EtsEscompatFloat64Array *thisArray, int64_t val,
                                                       EtsInt begin, EtsInt end)
{
    EtsEscompatTypedArrayFillInternal(thisArray, val, begin, end);
}
````

## H007

````cpp
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
````

## H008

````cpp
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
````

## H009

````cpp
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
````

## H010

````cpp
extern "C" void EtsEscompatInt8ArraySetValues(ark::ets::EtsEscompatInt8Array *thisArray,
                                              ark::ets::EtsEscompatInt8Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}
````

## H011

````cpp
extern "C" void EtsEscompatFloat32ArraySetValues(ark::ets::EtsEscompatFloat32Array *thisArray,
                                                 ark::ets::EtsEscompatFloat32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}
````

## H012

````cpp
extern "C" void EtsEscompatUint16ArraySetValuesFromArray(ark::ets::EtsEscompatUInt16Array *thisArray,
                                                         ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}
````

## H013

````cpp
extern "C" void EtsEscompatBigUInt64ArraySetValuesWithOffset(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                             ark::ets::EtsEscompatBigUInt64Array *srcArray, EtsInt pos)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, pos);
}
````

## H014

````cpp
extern "C" void EtsEscompatUint8ClampedArraySetValuesFromArray(ark::ets::EtsEscompatUInt8ClampedArray *thisArray,
                                                               ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}
````

## H015

````cpp
extern "C" void EtsEscompatInt32ArraySetValues(ark::ets::EtsEscompatInt32Array *thisArray,
                                               ark::ets::EtsEscompatInt32Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}
````

## H016

````cpp
extern "C" void EtsEscompatUint8ArraySetValuesFromArray(ark::ets::EtsEscompatUInt8Array *thisArray,
                                                        ark::ets::EtsStdCoreArray *srcArray)
{
    EtsEscompatTypedArraySetValuesFromArrayImpl(thisArray, srcArray);
}
````

## H017

````cpp
extern "C" void EtsEscompatBigUInt64ArraySetValues(ark::ets::EtsEscompatBigUInt64Array *thisArray,
                                                   ark::ets::EtsEscompatBigUInt64Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}
````

## H018

````cpp
extern "C" void EtsEscompatBigInt64ArraySetValues(ark::ets::EtsEscompatBigInt64Array *thisArray,
                                                  ark::ets::EtsEscompatBigInt64Array *srcArray)
{
    EtsEscompatTypedArraySetValuesImpl(thisArray, srcArray, 0);
}
````

## H019

````cpp
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
````

## H020

````cpp
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
````
