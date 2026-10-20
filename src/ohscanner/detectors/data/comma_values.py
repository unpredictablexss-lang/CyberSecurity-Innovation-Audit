"""Conservative source-local proof of fundamental operands for built-in comma.

This does not resolve general C++ types or overloads. Unknown syntax/binding keeps
the detector's existing may-flow value, including both operand dependencies.
"""
import re


def walk(node):
    yield node
    for child in node.named_children:yield from walk(child)


class BuiltinCommaProof:
    def __init__(self,flow):
        self.flow=flow;self.functions={};self.locals={}
        units=flow.resolver.units if flow.resolver is not None else (flow.u,)
        self.enabled=(len(units)==1 and flow.u.parse_status=='complete'
            and not flow.tree.root_node.has_error
            and (flow.resolver is None or getattr(flow.resolver,'switch_join_scope_complete',False))
            and not re.search(r'^\s*#|\boperator\s*,',flow.u.text,re.M)
            and not any(n.type in ('class_specifier','struct_specifier','enum_specifier',
                'type_definition','alias_declaration','using_declaration','using_directive',
                'namespace_definition') for n in walk(flow.tree.root_node)))
        if not self.enabled:return
        # Direct translation-unit declarations only. Duplicate names, local
        # shadowing and unsupported signatures must not acquire a return type.
        for root in flow.tree.root_node.named_children:
            if root.type not in ('declaration','function_definition'):continue
            for declarator in root.children_by_field_name('declarator'):
                name=flow.name(declarator)
                if name:self.functions.setdefault(name,[]).append((root,declarator))

    def typed(self,type_node,declarator,function=False):
        if type_node is None or type_node.type not in ('primitive_type','sized_type_specifier'):return None
        text=self.flow.text(type_node)
        if not re.fullmatch(r'(?:void|bool|char|wchar_t|char8_t|char16_t|char32_t|int|float|double|signed|unsigned|short|long)(?:\s+(?:int|char|double|signed|unsigned|short|long))*',text):return None
        depth=0;node=declarator
        while node is not None:
            if node.type=='init_declarator':node=node.child_by_field_name('declarator');continue
            if node.type in ('pointer_declarator','abstract_pointer_declarator'):
                depth+=1;node=node.child_by_field_name('declarator');continue
            if node.type in ('reference_declarator','abstract_reference_declarator'):
                children=node.named_children
                node=node.child_by_field_name('declarator') or (children[0] if len(children)==1 else None)
                if node is None:return None
                continue
            if node.type=='function_declarator':
                if not function:return None
                name=node.child_by_field_name('declarator')
                return (depth,node) if name is not None and name.type=='identifier' else None
            if node.type=='identifier':return None if function else depth
            return None
        return None if function else depth

    def identifier(self,node):
        name=self.flow.text(node)
        if name not in self.flow.shadows:return None
        function=node.parent
        while function is not None and function.type!='function_definition':function=function.parent
        if function is None:return None
        key=(function.id,name)
        if key not in self.locals:
            matches=[]
            for declaration in walk(function):
                if declaration.type not in ('parameter_declaration','declaration'):continue
                for declarator in declaration.children_by_field_name('declarator'):
                    if self.flow.name(declarator)==name:matches.append((declaration,declarator))
            self.locals[key]=matches
        matches=self.locals[key]
        if len(matches)!=1 or matches[0][0].start_byte>=node.start_byte:return None
        declaration,declarator=matches[0]
        return self.typed(declaration.child_by_field_name('type'),declarator)

    def call(self,node):
        function=node.child_by_field_name('function');args=node.child_by_field_name('arguments')
        if function is None or function.type!='identifier' or args is None:return None
        name=self.flow.text(function)
        if name in self.flow.shadows:return None
        matches=self.functions.get(name,())
        if len(matches)!=1:return None
        declaration,declarator=matches[0]
        if declaration.start_byte>=node.start_byte:return None
        result=self.typed(declaration.child_by_field_name('type'),declarator,function=True)
        if result is None:return None
        depth,fd=result;parameters=fd.child_by_field_name('parameters')
        if parameters is None:return None
        fixed=[]
        for parameter in parameters.named_children:
            if parameter.type!='parameter_declaration':return None
            if self.typed(parameter.child_by_field_name('type'),parameter.child_by_field_name('declarator')) is None:return None
            fixed.append(parameter)
        if len(fixed)==1 and self.flow.text(fixed[0])=='void':fixed=[]
        variadic=any(child.type=='...' for child in parameters.children)
        actual=len(args.named_children)
        if actual<len(fixed) or (not variadic and actual!=len(fixed)):return None
        return depth

    def kind(self,node):
        if node is None:return None
        if node.type in ('number_literal','char_literal','true','false','null'):return 0
        if node.type in ('string_literal','concatenated_string'):return 1
        if node.type=='identifier':return self.identifier(node)
        if node.type=='call_expression':return self.call(node)
        if node.type=='parenthesized_expression' and len(node.named_children)==1:
            return self.kind(node.named_children[0])
        if node.type=='comma_expression':
            left=self.kind(node.child_by_field_name('left'));right=self.kind(node.child_by_field_name('right'))
            return right if left is not None and right is not None else None
        if node.type=='pointer_expression':
            value=self.kind(node.child_by_field_name('argument'))
            if value is None:return None
            op=self.flow.text(node.child_by_field_name('operator'))
            if op=='&':return value+1
            if op=='*' and value>0:return value-1
        if node.type=='subscript_expression':
            value=self.kind(node.child_by_field_name('argument'))
            indices=node.child_by_field_name('indices')
            if value is not None and value>0 and indices is not None and len(indices.named_children)==1:
                if self.kind(indices.named_children[0])==0:return value-1
        return None

    def is_builtin(self,node):
        return self.enabled and node.type=='comma_expression' and self.kind(node) is not None
