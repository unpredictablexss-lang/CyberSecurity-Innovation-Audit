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
