GateRef inner(GateRef value) { return value; }
GateRef outer(GateRef value) { return inner(value); }
GateRef caller(GateRef value) { return outer(value); }
