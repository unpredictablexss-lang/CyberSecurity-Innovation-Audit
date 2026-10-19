class Decoder {
void ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {
    GateRef exceptionVal = builder_.ExceptionConstant();
    GateRef equal = builder_.Equal(value, exceptionVal);
    builder_.Branch(builder_.GetState(), equal, 1, BranchWeight::DEOPT_WEIGHT, "checkException");
}
};
