namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
GateRef target = (GateRef)output;
GateRef token = (GateRef)inputTag;
GateRef outputTag = GetObjectType(LoadHClass(output));
StoreTypedArrayElement(glue, target, count, input, outputTag);
}
}
