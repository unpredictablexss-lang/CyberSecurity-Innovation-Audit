"""Recover only C/C++-common assignment/comma parentheses at original spans.

No source rewriting or whole-file C fallback. A small Node inspection view grafts
validated, same-byte C expression subtrees into the original C++ syntax tree.
Uncovered errors/missing tokens remain errors. This is syntax, never type proof.
"""
import tree_sitter_c
from tree_sitter import Language, Parser


def _walk(node):
    yield node
    for child in node.named_children:yield from _walk(child)


_COMMON = frozenset(('parenthesized_expression','comma_expression','assignment_expression',
    'identifier','number_literal','string_literal','string_content','escape_sequence',
    'char_literal','character','true','false','null','pointer_expression','conditional_expression',
    'binary_expression','unary_expression','update_expression','field_expression','field_identifier',
    'call_expression','argument_list'))
_CPP_ONLY = frozenset(('lambda_expression','fold_expression','template_declaration','template_function',
    'template_type','raw_string_literal','decltype','sizeof_expression','alignof_expression',
    'attribute_specifier','attribute_declaration','comment'))
_KEYWORDS = frozenset((b'operator',b'typeid',b'decltype',b'new',b'delete',b'co_await',
    b'static_cast',b'reinterpret_cast',b'const_cast',b'dynamic_cast',b'requires'))


def _common_assignment_comma(node,source):
    if node.has_error:return False
    bare_assignment=False
    for child in _walk(node):
        if child.type not in _COMMON or child.is_missing:return False
        if child.type=='identifier' and source[child.start_byte:child.end_byte] in _KEYWORDS:return False
        if child.type=='assignment_expression':
            operator=child.child_by_field_name('operator')
            if operator is None or source[operator.start_byte:operator.end_byte]!=b'=':return False
            if child.parent is not None and child.parent.type=='comma_expression':bare_assignment=True
        if child.type=='binary_expression':
            operator=child.child_by_field_name('operator')
            if operator is None or source[operator.start_byte:operator.end_byte] in (b'<',b'>',b'<<',b'>>'):return False
        if child.type=='call_expression':
            function=child.child_by_field_name('function')
            if function is None or function.type!='identifier':return False
        if child.type=='conditional_expression' and any(child.child_by_field_name(field) is None
                for field in ('condition','consequence','alternative')):return False
    return bare_assignment


class _NodeView:
    def __init__(self,owner,node,origin):self._owner,self._node,self._origin=owner,node,origin
    def __getattr__(self,name):
        if name in ('walk','edit'):raise AttributeError('Recovery view supports node inspection, not cursors/editing')
        return getattr(self._node,name)
    @property
    def id(self):return -self._node.id if self._origin else self._node.id
    @property
    def children(self):return [self._owner.view(c,self._origin) for c in self._node.children]
    @property
    def named_children(self):return [self._owner.view(c,self._origin) for c in self._node.named_children]
    @property
    def parent(self):
        if self._origin and self._node.id in self._owner.parents:
            return self._owner.view(self._owner.parents[self._node.id],0)
        return self._owner.view(self._node.parent,self._origin)
    def child(self,index):
        children=self.children
        return children[index] if 0<=index<len(children) else None
    def named_child(self,index):
        children=self.named_children
        return children[index] if 0<=index<len(children) else None
    def child_by_field_name(self,name):return self._owner.view(self._node.child_by_field_name(name),self._origin)
    def children_by_field_name(self,name):return [self._owner.view(c,self._origin) for c in self._node.children_by_field_name(name)]
    @property
    def has_error(self):
        key=(self._origin,self._node.id)
        if key not in self._owner.errors:
            affected=(not self._origin and any(self.start_byte<=start and end<=self.end_byte
                                              for start,end in self._owner.ranges))
            self._owner.errors[key]=(self.is_error or self.is_missing or any(c.has_error for c in self.children)
                                     if affected else self._node.has_error)
        return self._owner.errors[key]


class _RecoveryTree:
    def __init__(self,cpp_tree,c_tree,matches):
        self.raw_cpp_tree,self.c_tree=cpp_tree,c_tree
        self.replacements={old.id:new for old,new in matches}
        self.parents={new.id:old.parent for old,new in matches}
        self.ranges=tuple((old.start_byte,old.end_byte) for old,new in matches)
        self.views={};self.errors={}
        self.recovery_spans=tuple({'kind':'recovered_cpp_assignment_comma',
            'start_line':old.start_point[0]+1,'end_line':old.end_point[0]+1,
            'start_byte':old.start_byte,'end_byte':old.end_byte} for old,new in matches)
        self.root_node=self.view(cpp_tree.root_node,0)
    def view(self,node,origin):
        if node is None:return None
        if not origin and node.id in self.replacements:node=self.replacements[node.id];origin=1
        key=(origin,node.id)
        if key not in self.views:self.views[key]=_NodeView(self,node,origin)
        return self.views[key]


def recover_cpp_assignment_commas(source:bytes,cpp_tree):
    """Return raw tree or a bounded inspection view with explicit recovery spans."""
    if not cpp_tree.root_node.has_error:return cpp_tree
    candidates=[]
    for node in _walk(cpp_tree.root_node):
        if node.type!='parenthesized_expression' or not node.has_error:continue
        if source[node.start_byte:node.start_byte+1]!=b'(' or source[node.end_byte-1:node.end_byte]!=b')':continue
        if any(n.type in _CPP_ONLY or n.type.startswith('preproc_') for n in _walk(node)):continue
        parent=node.parent;protected=False
        while parent is not None:
            if parent.type in _CPP_ONLY or parent.type.startswith('preproc_'):protected=True;break
            parent=parent.parent
        if not protected:candidates.append(node)
    if not candidates:return cpp_tree
    c_tree=Parser(Language(tree_sitter_c.language())).parse(source)
    compatible={(n.start_byte,n.end_byte):n for n in _walk(c_tree.root_node)
                if n.type=='parenthesized_expression' and _common_assignment_comma(n,source)}
    matches=[]
    for old in sorted(candidates,key=lambda n:n.end_byte-n.start_byte):
        new=compatible.get((old.start_byte,old.end_byte))
        if new is None or any(old.start_byte<other.end_byte and other.start_byte<old.end_byte for other,_ in matches):continue
        matches.append((old,new))
        if len(matches)==64:break
    return _RecoveryTree(cpp_tree,c_tree,matches) if matches else cpp_tree
