JSTaggedValue TypedArrayHelper::TypedArrayConstructor(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);
    uint32_t elementLength = 0;
    elementLength = static_cast<uint32_t>(index.GetNumber());
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
