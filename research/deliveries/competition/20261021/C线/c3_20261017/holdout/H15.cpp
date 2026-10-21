namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef seed = GetObjectType(LoadHClass(input));
GateRef preserved = seed; NewObjectStubBuilder alloc(this);
GateRef dst = alloc.NewTypedArray(glue, input, seed, count);
GateRef current = GetObjectType(LoadHClass(dst));
GateRef &escaped = current; escaped = preserved;
StoreTypedArrayElement(glue, dst, count, input, current);

}
}
