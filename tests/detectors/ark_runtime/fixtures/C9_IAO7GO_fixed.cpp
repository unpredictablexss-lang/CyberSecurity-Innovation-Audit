namespace panda::ecmascript::kungfu {
void NativeInlineLowering::LowerReflectApply(GateRef glue) {
    JSTaggedValue result = JSFunction::Call(glue);
    RETURN_VALUE_IF_ABRUPT_COMPLETION(glue, result);
    Return(result);
}
}
