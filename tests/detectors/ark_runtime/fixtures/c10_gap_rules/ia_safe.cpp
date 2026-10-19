class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    if (builder_.HasPendingException(glue_)) {
        builder_.ReturnException();
        return;
    }
    builder_.ReturnValue(value);
}
};
