// Self-authored syntax fixture; not a runnable exploit or independent vulnerability label.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
Label storeLabel(GetEnvironment());
BRANCH_WITH_DEOPT(count, &storeLabel, exit);
Bind(&storeLabel);
StoreTypedArrayElement(glue, output, count, input, inputTag);
}
}
