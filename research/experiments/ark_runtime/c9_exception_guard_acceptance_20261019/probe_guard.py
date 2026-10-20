from tests.detectors.ark_runtime.test_runtime_exception import source
from src.ohscanner.detectors.ark_runtime.syntax import parse_functions, walk
from src.ohscanner.detectors.ark_runtime.runtime_exception import _exception_result_condition, _returns_pending_exception
text = source(body="    if (callbackOutcome.IsException()) return JSTaggedValue::Exception();")
_, funcs = parse_functions(text.encode())
fn = funcs[0]
for node in walk(fn.body):
    if node.type == "if_statement":
        c=node.child_by_field_name("condition"); q=node.child_by_field_name("consequence")
        print("cond", c.type, repr(fn.text(c)), "unwrap call", [x.type for x in walk(c)])
        print("cons", q.type, repr(fn.text(q)))
        ident = next(x for x in walk(fn.body) if x.type=="identifier" and fn.text(x)=="callbackOutcome")
        binding=fn.resolve("callbackOutcome", ident)
        print("binding", binding, binding.type_name)
        print("condition result", _exception_result_condition(fn,c,binding))
        print("return result", _returns_pending_exception(fn,q,binding))
        for ret in walk(q):
            if ret.type=="return_statement":
                v=ret.child_by_field_name("value")
                print("return value", v.type if v else None, repr(fn.text(v)) if v else None)
