class BuiltinsTypedArray {
JSTaggedValue Filter(EcmaRuntimeCallInfo *argv) {
    JSThread *thread = argv->GetThread();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    JSTaggedValue callbackOutcome = Normalize(JSFunction::Call(info));
    while (condition) {
        bool accepted = callbackOutcome.ToBoolean();
    }
    return JSTaggedValue::Undefined();
}
};
JSTaggedValue Normalize(JSTaggedValue value) { Touch(); return value; }
