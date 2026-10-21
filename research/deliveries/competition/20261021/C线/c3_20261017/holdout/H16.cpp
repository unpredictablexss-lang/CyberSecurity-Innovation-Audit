namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef seed = GetObjectType(LoadHClass(input));
GateRef preserved = seed; NewObjectStubBuilder alloc(this);
GateRef dst = alloc.NewTypedArray(glue, input, seed, count);
Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);
dst = alloc.NewTypedArray(glue, input, seed, count);
StoreTypedArrayElement(glue, dst, count, input, preserved);
LoopEnd(&again);
}
}
