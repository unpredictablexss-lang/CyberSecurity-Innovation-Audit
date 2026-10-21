// C10 source-bound control: CVE-2025-24304/Map species-sensitive result shape.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Map(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
StoreTypedArrayElement(glue, output, count, input, inputTag);
}
}
