class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), {target, fn, argv});
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef state = builder_.GetState();
    GateRef exceptionVal = builder_.ExceptionConstant();
    GateRef equal = builder_.Equal(value, exceptionVal);
    auto ifBranch = builder_.Branch(state, equal, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
