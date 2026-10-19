// C10 source-bound fixed control: result type token comes from the exact exemplar.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArraySameType(glue, input, inputTag, count);
StoreTypedArrayElement(glue, output, count, input, inputTag);
}
}
