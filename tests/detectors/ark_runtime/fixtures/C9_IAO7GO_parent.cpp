namespace panda::ecmascript::kungfu {
void NativeInlineLowering::LowerReflectApply(GateRef glue) {
    JSTaggedValue result = JSFunction::Call(glue);
    Return(result);
}
}
