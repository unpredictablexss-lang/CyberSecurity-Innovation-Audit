// C10 unrelated control: owner and rule do not apply.
namespace unrelated {
void Builder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
StoreTypedArrayElement(glue, input, count, input, input);
}
}
