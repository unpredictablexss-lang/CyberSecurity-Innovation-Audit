JSTaggedValue TypedArrayHelper::TypedArrayConstructor(EcmaRuntimeCallInfo *argv) {
    JSTaggedNumber index = JSTaggedValue::ToIndex(thread, firstArg);
    int32_t elementLength = 0;
    elementLength = ConvertLength(index.GetNumber());
    JSHandle<JSObject> obj = TypedArrayHelper::AllocateTypedArray(thread, constructorName, newTarget,
                                                                  elementLength, arrayType);
    return obj.GetTaggedValue();
}
