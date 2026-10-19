namespace panda::ecmascript::kungfu {
void NativeInlineLowering::TryInlineReflectApply(GateRef gate, size_t argc,
        BuiltinsStubCSigns::ID id, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(),
        {target, thisValue, argumentsList});
    ReplaceGateWithPendingException(gate, ret);
}
}
