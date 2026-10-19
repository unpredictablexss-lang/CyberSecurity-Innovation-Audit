// Self-authored syntax fixture; not a runnable exploit or independent vulnerability label.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
GateRef chosen;
if (count) { chosen = GetObjectType(LoadHClass(output)); }
else { chosen = inputTag; }
StoreTypedArrayElement(glue, output, count, input, chosen);
}
}
