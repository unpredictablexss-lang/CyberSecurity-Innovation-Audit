GateRef wrapper(GateRef value) {
    return Opaque(value);
}
GateRef caller(GateRef input) { return wrapper(input); }
