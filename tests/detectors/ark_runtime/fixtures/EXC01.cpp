// Self-authored exception-order control fixture; not a runnable exploit or product label.
namespace panda::ecmascript::kungfu {
void BuiltinsTypedArrayStubBuilder::Positive(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
GateRef klass = GetObjectType(LoadHClass(glue, output));
}

void BuiltinsTypedArrayStubBuilder::Fixed(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label done(GetEnvironment());
BRANCH(HasPendingException(glue), &exception, &normal);
Bind(&exception); result->WriteVariable(Exception()); Jump(&done);
Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&done);
Bind(&done);
}

void BuiltinsTypedArrayStubBuilder::Safe(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArraySameType(glue, input, inputTag, count);
Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label done(GetEnvironment());
BRANCH(HasPendingException(glue), &exception, &normal);
Bind(&exception); result->WriteVariable(Exception()); Jump(&done);
Bind(&normal); CopyTypedArrayBuffer(glue, input, output); Jump(&done);
Bind(&done);
}

void BuiltinsTypedArrayStubBuilder::Unrelated(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
CopyTypedArrayBuffer(glue, input, input);
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArray(glue, input, inputTag, count);
}

void BuiltinsTypedArrayStubBuilder::Unknown(GateRef glue, GateRef input, GateRef count, Variable *result, Label *exit, Label *slowPath) {
GateRef inputTag = GetObjectType(LoadHClass(input));
NewObjectStubBuilder builder(this);
GateRef output = builder.NewTypedArraySameType(glue, input, inputTag, count);
Label empty(GetEnvironment()); Label copy(GetEnvironment()); Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label done(GetEnvironment());
BRANCH(Int32Equal(count, Int32(0)), &empty, &copy);
Bind(&empty); return;
Bind(&copy); BRANCH(HasPendingException(glue), &exception, &normal);
Bind(&exception); result->WriteVariable(Exception()); Jump(&done);
Bind(&normal); CopyTypedArrayBuffer(glue, input, output); Jump(&done);
Bind(&done);
}
}
