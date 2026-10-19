namespace panda::ecmascript::kungfu {
void NativeInlineLowering::TryInlineReflectApply(GateRef gate, size_t argc,
        BuiltinsStubCSigns::ID id, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(),
        {target, thisValue, argumentsList});
    ReplaceGateWithPendingException(gate, ret);
}
void NativeInlineLowering::ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef state = builder_.GetState();
    GateRef exceptionVal = builder_.ExceptionConstant();
    GateRef equal = builder_.Equal(value, exceptionVal);
    auto ifBranch = builder_.Branch(state, equal, 1, BranchWeight::DEOPT_WEIGHT);
    GateRef ifTrue = builder_.IfTrue(ifBranch);
    GateRef ifFalse = builder_.IfFalse(ifBranch);
    StateDepend success(ifFalse, builder_.DependRelay(ifFalse, depend));
    StateDepend exception(ifTrue, builder_.DependRelay(ifTrue, depend));
    acc_.ReplaceHirWithIfBranch(hirGate, success, exception, value);
}
}
