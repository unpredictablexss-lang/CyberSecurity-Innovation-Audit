// Self-authored syntax fixture; not a runnable exploit or independent vulnerability label.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef originKind = GetObjectType(LoadHClass(input));
NewObjectStubBuilder factoryLocal(this);
GateRef freshTarget = factoryLocal.NewTypedArray(glue, input, originKind, count);
StoreTypedArrayElement(glue, freshTarget, count, input, originKind);
}
}
