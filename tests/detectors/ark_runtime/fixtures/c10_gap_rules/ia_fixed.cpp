class NativeInlineLowering {
void TryInlineReflectApply(GateRef gate, size_t argc, bool skipThis) {
    GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), {target, fn, argv});
    ReplaceGateWithPendingException(gate, ret);
}
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef state = builder_.GetState();
    GateRef condition = builder_.HasPendingException(glue_);
    auto ifBranch = builder_.Branch(state, condition, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
