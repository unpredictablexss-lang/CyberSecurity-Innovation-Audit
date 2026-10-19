// C10 safe local control: a fresh result sample is a local proof, not a safety verdict.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
GateRef outputTag = GetObjectType(LoadHClass(output));
StoreTypedArrayElement(glue, output, count, input, outputTag);
}
}
