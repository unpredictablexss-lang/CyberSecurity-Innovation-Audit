from src.ohscanner.detectors.ark_runtime.syntax import parse_functions
text = b'''namespace panda::ecmascript::kungfu {
class BuiltinsStubBuilder : public StubBuilder {};
class BuiltinsArrayStubBuilder : public BuiltinsStubBuilder {};
void StubBuilder::Branch(GateRef condition, Label *trueLabel, Label *falseLabel) {
 GateRef branch = builder->Branch(control, condition);
 GateRef onTrue = builder->IfTrue(branch);
 trueLabel->MergeControl(onTrue);
 GateRef onFalse = builder->IfFalse(branch);
 falseLabel->MergeControl(onFalse);
}
}
'''
tree, funcs = parse_functions(text)
def dump(n, depth=0):
    if depth > 7: return
    fields=[]
    for name in ('name','body','declarator','parameters','arguments'):
        child=n.child_by_field_name(name)
        if child is not None: fields.append(f'{name}={child.type}:{text[child.start_byte:child.end_byte][:60]!r}')
    print('  '*depth + n.type + ' ' + ' '.join(fields))
    for c in n.named_children: dump(c, depth+1)
dump(tree.root_node)
print([(f.qualified_name, f.parameter_types) for f in funcs])
