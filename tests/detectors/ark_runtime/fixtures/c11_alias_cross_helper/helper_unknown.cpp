GateRef PassObject(GateRef value) { return value; }
GateRef PassType(GateRef value) { return value; }
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
GateRef outputTag = GetObjectType(LoadHClass(output));
UnknownGlobalEffect();
StoreTypedArrayElement(glue, PassObject(output), count, input, outputTag);
}
}
