namespace panda::ecmascript::kungfu {
void NativeInlineLowering::LowerReflectApply(GateRef glue, Thread *thread) {
    JSTaggedValue result = JSFunction::Call(glue);
    bool completed = !thread->HasPendingException();
    if (!completed) {
        return;
    }
    Return(result);
}
}
