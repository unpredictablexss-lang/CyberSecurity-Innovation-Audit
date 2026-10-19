GateRef wrapper(GateRef value) {
    Audit(value);
    return value;
}
GateRef caller(GateRef input) { return wrapper(input); }
