"""Bounded disjunctive interpretation of structured C/C++ IPC functions.

Private detector analysis, not a replacement shared IR. It reuses the project's
Tree-sitter dependency to recover branches absent from the public AST outline.
No compiler CFG, overload resolution, macro expansion or exploitability proof.
"""
from dataclasses import dataclass, field, replace
import re
from typing import Optional

from tree_sitter import Language, Parser
import tree_sitter_cpp
import tree_sitter_c

from .models import IpcPolicy


def walk(node, kind=None):
    stack = [node]
    while stack:
        current = stack.pop()
        if kind is None or current.type == kind:
            yield current
        stack.extend(reversed(current.named_children))


def terminal(text):
    return re.split(r"::|->|\.", text)[-1].strip()


@dataclass(frozen=True)
class Value:
    kind: str = "unknown"
    key: str = ""
    subject: str = ""
    permission: str = ""
    predicate: tuple = ()
    terms: tuple = ()


UNKNOWN = Value()


@dataclass
class State:
    env: dict = field(default_factory=dict)
    auth: frozenset = frozenset()
    descriptor: frozenset = frozenset()
    owner: frozenset = frozenset()
    lower: frozenset = frozenset()
    upper: frozenset = frozenset()
    size_lower: frozenset = frozenset()
    caller_class: frozenset = frozenset()
    identity_issues: tuple = ()
    reset: bool = False
    trace: tuple = ()
    flow: str = "normal"
    returned: Value = UNKNOWN

    def fork(self, **kwargs):
        return replace(self, env=dict(self.env), **kwargs)


@dataclass(frozen=True)
class Function:
    file: str
    name: str
    qualified: str
    owner: str
    node: object
    body: object
    source: bytes
    params: tuple
    parcel_params: tuple

    def text(self, node):
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte].decode("utf-8")


@dataclass(frozen=True)
class Observation:
    family: str
    rule: str
    file: str
    line: int
    symbol: str
    message: str
    trace: tuple
    root_key: tuple


def normalize_syntax(source):
    """Model only known format-string tokens and unresolved member dispatch.

    Byte lengths/newlines remain unchanged. Original source is retained for
    evidence. This is not macro expansion or resolution of member pointers.
    """
    pattern = rb'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|(?P<fmt>\bPRI[diouxX](?:8|16|32|64|MAX|PTR)\b)'
    def fmt(match):
        token=match.group('fmt')
        if token is not None:
            before=source[:match.start()].rstrip();after=source[match.end():].lstrip()
            if before.endswith(b'"') and after.startswith(b'"'):
                return b'"'+b' '*(len(token)-2)+b'"'
        return match.group(0)
    normalized=re.sub(pattern,fmt,source,flags=re.S)
    normalized=re.sub(rb'\(this\s*->\s*\*\s*[A-Za-z_]\w*\)(?=\s*\()',
                      lambda m:m.group(0).replace(b'*',b' ',1),normalized)
    return normalized


class Interpreter:
    def __init__(self, units, policy: IpcPolicy):
        self.policy = policy
        self.functions = []
        self.observations = []
        self.limitations = set()
        self.seen_permissions = set()
        self.root = None
        self.active = ()
        self.capacities = {}
        for unit in units:
            grammar = tree_sitter_c.language() if unit.language == "c" else tree_sitter_cpp.language()
            raw=unit.text.encode("utf-8")
            normalized=normalize_syntax(raw)
            if normalized!=raw:
                self.limitations.add("Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: "+unit.path)
            tree = Parser(Language(grammar)).parse(normalized)
            if tree.root_node.has_error:
                self.limitations.add("Partial source: only error-free functions can be inspected in " + unit.path)
            source = unit.text.encode("utf-8")
            for node in walk(tree.root_node, "function_definition"):
                dec = node.child_by_field_name("declarator")
                while dec is not None and dec.type not in ("function_declarator",):
                    dec = dec.child_by_field_name("declarator")
                if dec is None:
                    continue
                name_node = dec.child_by_field_name("declarator")
                if name_node is None:
                    continue
                q = source[name_node.start_byte:name_node.end_byte].decode("utf-8")
                owner = q.rsplit("::", 1)[0] if "::" in q else ""
                if not owner:
                    parent = node.parent
                    while parent is not None:
                        if parent.type in ("class_specifier", "struct_specifier"):
                            n = parent.child_by_field_name("name")
                            owner = source[n.start_byte:n.end_byte].decode() if n else ""
                            break
                        parent = parent.parent
                params, parcels = [], []
                plist = dec.child_by_field_name("parameters")
                for param in plist.named_children if plist else ():
                    pd = param.child_by_field_name("declarator")
                    while pd is not None and pd.child_by_field_name("declarator") is not None:
                        pd = pd.child_by_field_name("declarator")
                    if pd is None:
                        continue
                    ids = list(walk(pd, "identifier"))
                    pname_node = ids[-1] if ids else pd
                    pname = source[pname_node.start_byte:pname_node.end_byte].decode()
                    params.append(pname)
                    if re.search(r"\b(?:MessageParcel|Parcel)\b",source[param.start_byte:param.end_byte].decode()):
                        parcels.append(pname)
                body = node.child_by_field_name("body")
                if body and not node.has_error:
                    self.functions.append(Function(unit.path, terminal(q), q, owner, node, body,
                                                   source, tuple(params), tuple(parcels[:1])))

    def bounded(self, states):
        # Keep a conservative merged state when the disjunction exceeds budget.
        # Intersect guards/ranges, union only identical provenance; never truncate
        # an unprotected path while retaining protected ones.
        if len(states) <= self.policy.max_paths:
            return states
        self.limitations.add("Path budget exceeded: conservative state join; path precision reduced.")
        result = []
        for flow in sorted({s.flow for s in states}):
            group = [s for s in states if s.flow == flow]
            env = {}
            for key in set().union(*(s.env.keys() for s in group)):
                values = {s.env.get(key, UNKNOWN) for s in group}
                env[key] = values.pop() if len(values) == 1 else UNKNOWN
            def intersection(attr):
                return frozenset.intersection(*(getattr(s, attr) for s in group))
            result.append(State(env=env, auth=intersection("auth"),
                                descriptor=intersection("descriptor"), owner=intersection("owner"),
                                lower=intersection("lower"), upper=intersection("upper"), size_lower=intersection("size_lower"), caller_class=intersection("caller_class"),
                                identity_issues=tuple(issue for s in group for issue in s.identity_issues),
                                reset=any(s.reset for s in group), flow=flow,
                                trace=((0, "conservative path join"),)))
        return result

    def emit(self, family, rule, fn, node, state, message):
        self.observations.append(Observation(family, rule, fn.file,
            node.start_point[0] + 1, fn.qualified, message, state.trace, (self.root.file, self.root.qualified)))

    def resolve(self, fn, name):
        # No arbitrary receiver or global name-only cross-class resolution.
        receiver = name.rsplit("->", 1)[0] if "->" in name else None
        if "." in name or (receiver is not None and receiver != "this"):
            return None
        prefix = name.rsplit("::", 1)[0] if "::" in name else fn.owner
        matches = [f for f in self.functions if f.file == fn.file
                   and f.name == terminal(name) and f.owner == prefix]
        return matches[0] if len(matches) == 1 else None

    def authorized(self, state, name):
        expected = dict(self.policy.expected_permissions).get(name)
        if expected:return expected in state.auth
        if name in ("GetRemoteHapTokenInfo","DeleteRemoteHapTokenInfo","UpdateRemoteHapTokenInfo"):
            return bool(state.auth or state.caller_class.intersection({"TOKEN_NATIVE"}))
        return bool(state.auth)

    def action(self, fn, node, state, name, args):
        if self.root is None:
            return
        root_key = (self.root.file, self.root.qualified)
        sensitive = name in self.policy.sensitive_calls or name in self.policy.object_sensitive_calls
        if sensitive:
            for issue_fn,issue_node,issue_rule,issue_message in state.identity_issues:
                self.emit("AUTH-03",issue_rule,issue_fn,issue_node,state,issue_message)
        if sensitive and not self.authorized(state, name):
            self.emit("AUTH-02", "ipc.auth.missing", fn, node, state,
                      "Sensitive modeled call " + name + " has a structured path without a recognized caller authorization.")
        if name in self.policy.caller_class_sensitive_calls and not state.caller_class:
            self.emit("AUTH-03","ipc.auth.caller-class",fn,node,state,
                      "Sensitive token/privacy operation lacks a caller-class/system-application boundary: "+name)
        if name in ("StartBackgroundRunningForInner","StopBackgroundRunningForInner") and args:
            if args[0].key not in state.owner:
                self.emit("AUTH-03","ipc.auth.object-owner",fn,node,state,
                          "Background-task target UID is not bound to calling UID.")
        if name in self.policy.object_sensitive_calls:
            resources = {v.key for v in args if v.kind == "request"}
            if resources and not resources.issubset(state.owner):
                self.emit("AUTH-03", "ipc.auth.object-owner", fn, node, state,
                          "Caller/resource relation is not established for " + name + ": " + ", ".join(sorted(resources)))
        if name in self.policy.capability_calls and not state.auth:
            if args and args[0].key not in ("nullptr", "NULL", "0"):
                self.emit("CAP-01", "ipc.capability.export", fn, node, state,
                          "Capability export " + name + " lacks a recognized caller authorization on this path.")
        if name in self.policy.copy_calls and args:
            index = 3 if name in ("memcpy_s", "memmove_s") else 2
            if len(args) > index and args[index].kind == "request":
                length = args[index].key
                cap = args[1].key if index == 3 else self.capacities.get(args[0].key)
                upper = any(key == length and (cap is not None and bound in (cap,"sizeof("+args[0].key+")"))
                            for key, bound in state.upper)
                if not upper or length not in state.lower:
                    self.emit("DATA-01", "ipc.parcel.copy-range", fn, node, state,
                              "Parcel-derived copy length " + length + " lacks matched nonnegative/destination-capacity bounds.")
        if self.root.name in self.policy.entry_names and name not in self.policy.entry_names and (sensitive or name.startswith("On")
                or name in self.policy.capability_calls or name in self.policy.copy_calls):
            parcel_keys = {v.key for v in state.env.values() if v.kind == "parcel"}
            if parcel_keys and not parcel_keys.intersection(state.descriptor):
                self.emit("AUTH-01", "ipc.relay.descriptor-boundary", fn, node, state,
                          "IPC dispatch/callback reaches " + name + " without a matched interface-descriptor guard; relay/exposure still requires review.")

    def value(self, fn, node, state, depth):
        if node is None:
            return UNKNOWN
        text = fn.text(node)
        if node.type in ("parenthesized_expression", "condition_clause"):
            child = node.child_by_field_name("value")
            return self.value(fn, child or (node.named_children[-1] if node.named_children else None), state, depth)
        if node.type in ("identifier", "field_identifier"):
            return state.env.get(text, Value("constant", text))
        if node.type in ("number_literal", "true", "false", "null", "nullptr", "string_literal", "concatenated_string"):
            return Value("constant", text)
        if node.type == "call_expression":
            callee = fn.text(node.child_by_field_name("function"));name = terminal(callee)
            an = node.child_by_field_name("arguments")
            args = [self.value(fn, a, state, depth) for a in an.named_children] if an else []
            receiver = re.split(r"->|\.", callee)[0] if re.search(r"->|\.", callee) else ""
            if name in self.policy.caller_token_calls | self.policy.caller_uid_calls:
                return Value("self" if state.reset else "caller", text, "uid" if name in self.policy.caller_uid_calls else "token")
            if name in self.policy.self_calls:
                return Value("self", text, "uid" if name in ("getuid","geteuid") else "token")
            if name == "ResetCallingIdentity":
                state.reset = True
                return Value("saved_identity", text)
            if name == "SetCallingIdentity":
                # Restoration cannot establish the original caller unless the
                # corresponding identity token's provenance is available.
                state.reset = not (args and args[0].kind == "saved_identity")
                return UNKNOWN
            if name == "ReadInterfaceToken":
                rv = state.env.get(receiver, UNKNOWN)
                return Value("descriptor_read", rv.key) if rv.kind == "parcel" else UNKNOWN
            if name == "GetDescriptor":
                if "::" in callee and callee.rsplit("::",1)[0] != fn.owner:
                    return UNKNOWN
                return Value("descriptor_expected", fn.owner)
            if name in ("GetTokenTypeFlag", "GetTokenType") and args and args[0].kind=="caller" and args[0].subject=="token":
                return Value("caller_type",args[0].key)
            if name=="GetNativeTokenInfo" and len(args)>1 and args[0].kind=="caller" and args[0].subject=="token":
                state.env[args[1].key]=Value("caller_info",args[1].key)
            if name=="compare" and args:
                receiver_node=node.child_by_field_name("function")
                receiver_arg=receiver_node.child_by_field_name("argument") if receiver_node else None
                rv=self.value(fn,receiver_arg,state,depth)
                if rv.kind=="caller_process" and args[0].key=='"hdcd"':
                    return Value("permission_result",text,"caller","<caller-native-process:hdcd>")
            if name in ("IsSystemAppCalling","CheckCallerIsSystemApp"):
                return Value("predicate",predicate=("caller_class","system_app",True))
            if name in ("IsPrivilegedCalling","IsAccessTokenCalling"):
                return Value("predicate",predicate=("auth","<caller-service-role>",True))
            if name=="GetDataSize" and state.env.get(receiver,UNKNOWN).kind=="parcel":
                return Value("parcel_size",re.sub(r"\s+","",text))
            if name=="RewindRead" and args:
                self.check_subtractions(fn,node,state,args[0])
            if name in self.policy.owner_calls:
                return Value("owner", args[0].key if args else receiver)
            if name in self.policy.parcel_reads:
                rv = state.env.get(receiver, UNKNOWN)
                if rv.kind == "parcel":
                    return Value("request", text, "unsigned" if name.startswith("ReadU") else "signed")
            if callee.lstrip().startswith("(this->*") and self.root.name in self.policy.entry_names and not state.descriptor:
                self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                          "Unresolved member-pointer IPC dispatch lacks interface-descriptor validation; callee remains unknown.")
            helper = self.resolve(fn, callee)
            self.action(fn, node, state, name, args)
            if helper and self.root.name in self.policy.entry_names and not state.descriptor:
                self.emit("AUTH-01","ipc.relay.descriptor-boundary",fn,node,state,
                    "IPC entry reaches a locally resolved handler without interface-descriptor validation: "+helper.qualified)
            if helper and depth < self.policy.max_call_depth and helper not in self.active:
                local = state.fork();local.env = dict(zip(helper.params, args))
                old = self.active;self.active = old + (helper,)
                ends = self.block(helper, helper.body, [local], depth + 1)
                self.active = old
                returned = [s.returned for s in ends if s.flow == "return"]
                # A helper is summarized only when all its returns agree. A
                # conditional boolean return gets its guards bound to truth.
                values = set(returned)
                if len(values) == 1 and len(returned) == len(ends):
                    return values.pop()
                good = [s for s in ends if s.flow == "return" and s.returned.key in ("true", "1")]
                bad = [s for s in ends if s.flow == "return" and s.returned.key in ("false", "0")]
                if good and bad and len(good)+len(bad) == len(ends):
                    common = frozenset.intersection(*(s.auth for s in good)) - state.auth
                    if common:
                        return Value("predicate", predicate=("auth", sorted(common)[0], True))
                self.limitations.add("Unresolved multi-outcome helper return: " + helper.qualified)
                return UNKNOWN
            if name in self.policy.boolean_permissions | self.policy.result_permissions:
                self.seen_permissions.add((self.root.file,self.root.qualified))
                subjects = [a.kind for a in args if a.kind in ("caller", "self", "request")]
                subject = subjects[0] if subjects else ("caller" if callee=="TelephonyPermission::CheckPermission" else "unknown")
                if name in self.policy.result_permissions and any(a.kind=="caller" and a.subject=="uid" for a in args):
                    subject="caller_uid"
                    state.identity_issues += ((fn,node,"ipc.auth.identity-domain",
                        "AccessToken authorization consumes a caller UID rather than a caller TokenID: "+text),)
                perm = next((a.key for a in args if a.kind == "constant" and ('\"' in a.key or 'PERMISSION' in a.key)), "<unspecified>")
                if subject == "self":
                    state.identity_issues += ((fn,node,"ipc.auth.service-identity",
                              "Authorization predicate uses service identity before a modeled sensitive effect: "+text),)
                if subject == "request":
                    state.identity_issues += ((fn,node,"ipc.auth.request-identity",
                              "Authorization predicate consumes request-derived identity before a modeled sensitive effect: "+text),)
                kind = "permission_bool" if name in self.policy.boolean_permissions else "permission_result"
                return Value(kind, text, subject, perm)
            if helper and (depth >= self.policy.max_call_depth or helper in self.active):
                self.limitations.add("Call depth/recursion budget reached at " + helper.qualified)
            return Value("unknown", text)
        if node.type == "binary_expression":
            left = self.value(fn,node.child_by_field_name("left"),state,depth)
            right = self.value(fn,node.child_by_field_name("right"),state,depth)
            op = fn.text(node.child_by_field_name("operator"))
            if op in ("==", "!=", "<", "<=", ">", ">="):
                if left.kind == "descriptor_read" and right.kind == "descriptor_expected" or right.kind == "descriptor_read" and left.kind == "descriptor_expected":
                    rd = left if left.kind == "descriptor_read" else right
                    if op in ("==","!="):
                        return Value("predicate",predicate=("descriptor",rd.key,op=="=="))
                pv,cv = (left,right) if left.kind in ("permission_bool","permission_result") else (right,left)
                if pv.kind in ("permission_bool","permission_result") and op in ("==","!="):
                    success = cv.key in ("0", "PERMISSION_GRANTED", "AccessTokenKit::PERMISSION_GRANTED", "true") or terminal(cv.key)=="PERMISSION_GRANTED"
                    failure = (pv.kind=="permission_bool" and cv.key=="false") or (pv.kind=="permission_result" and terminal(cv.key)=="PERMISSION_DENIED")
                    if (success or failure) and pv.subject == "caller":
                        return Value("predicate",predicate=("auth",pv.permission,(success and op=="==") or (failure and op=="!=")))
                if left.kind=="parcel_size" and op in ("<",">="):
                    return Value("predicate",predicate=("size_lower",(left.key,right.key),op==">="))
                if op in ("==","!=") and ((left.kind=="caller_type" and terminal(right.key) in ("TOKEN_NATIVE","TOKEN_SHELL","TOKEN_HAP")) or (right.kind=="caller_type" and terminal(left.key) in ("TOKEN_NATIVE","TOKEN_SHELL","TOKEN_HAP"))):
                    role=right.key if left.kind=="caller_type" else left.key
                    if terminal(role)=="TOKEN_HAP":
                        return Value("predicate",predicate=("caller_class","not_hap",op=="!="))
                    return Value("predicate",predicate=("caller_class",terminal(role),op=="=="))
                if op in ("==","!=") and {left.kind,right.kind} == {"caller","owner"} and (left if left.kind=="caller" else right).subject=="uid":
                    ov = left if left.kind == "owner" else right
                    return Value("predicate",predicate=("owner",ov.key,op=="=="))
                if op in ("==","!=") and ((left.kind=="caller" and left.subject=="uid" and right.key in self.policy.trusted_uids) or (right.kind=="caller" and right.subject=="uid" and left.key in self.policy.trusted_uids)):
                    return Value("predicate",predicate=("auth","<trusted-uid>",op=="=="))
                if left.kind == "request" and right.kind != "request":
                    if op=="<" and right.key=="0":
                        return Value("predicate",predicate=("lower",left.key,False))
                    if op in ("<", "<="):
                        return Value("predicate",predicate=("upper",(left.key,right.key),True))
                    if (op==">=" and right.key=="0") or (op==">" and right.key in ("0","-1")):
                        return Value("predicate",predicate=("lower",left.key,True))
                if left.kind == "request" and right.kind != "request" and op in (">",">="):
                    return Value("predicate",predicate=("upper",(left.key,right.key),False))
            if left.kind == "request" or right.kind == "request":
                return Value("request",re.sub(r"\s+","",text), "arithmetic",terms=(op,left,right))
            if op=="-" and (left.kind=="parcel_size" or left.terms):
                return Value("arithmetic",re.sub(r"\s+","",text),terms=(op,left,right))
            return UNKNOWN
        if node.type == "unary_expression":
            val=self.value(fn,node.child_by_field_name("argument"),state,depth)
            op=fn.text(node.child_by_field_name("operator"))
            if op=="!" and val.predicate:
                kind,key,truth=val.predicate
                return Value("predicate",predicate=(kind,key,not truth))
            if op=="!" and val.kind=="permission_bool" and val.subject=="caller":
                return Value("predicate",predicate=("auth",val.permission,False))
            if op=="-" and val.kind=="constant":
                return Value("constant","-"+val.key)
            return val
        if node.type in ("cast_expression","type_descriptor"):
            return self.value(fn,node.child_by_field_name("value"),state,depth)
        if node.type == "new_expression":
            typ=fn.text(node.child_by_field_name("type"))
            if typ=="HCameraDevice":
                self.action(fn,node,state,"CreateCameraDevice",[])
            for child in node.named_children:self.value(fn,child,state,depth)
            return UNKNOWN
        if node.type=="field_expression" and fn.text(node.child_by_field_name("field"))=="processName":
            base=self.value(fn,node.child_by_field_name("argument"),state,depth)
            if base.kind=="caller_info":return Value("caller_process",base.key)
        if node.type=="field_expression" and fn.text(node.child_by_field_name("field")) in ("uid_","ownerUid"):
            arg=node.child_by_field_name("argument");base=self.value(fn,arg,state,depth)
            if base.kind=="request":return Value("owner",base.key)
        if node.type == "field_expression" and fn.text(node.child_by_field_name("field"))=="type" and "AccessTokenIDInner" in text:
            names=[fn.text(n) for n in walk(node,"identifier")]
            if any(state.env.get(n,UNKNOWN).kind=="caller" and state.env.get(n,UNKNOWN).subject=="token" for n in names):
                return Value("caller_type",text)
        if node.type == "sizeof_expression":
            return Value("constant",text)
        if node.type == "assignment_expression":
            left=fn.text(node.child_by_field_name("left"))
            value=self.value(fn,node.child_by_field_name("right"),state,depth)
            self.assign(state,left,value)
            return state.env[left]
        if node.type in ("subscript_expression","subscript_argument_list"):
            for sub in node.named_children:self.value(fn,sub,state,depth)
            return UNKNOWN
        # Visit nested calls without treating comments or strings as executable.
        for child in node.named_children:self.value(fn,child,state,depth)
        return Value("unknown",text)

    def check_subtractions(self,fn,node,state,value):
        if not value.terms or value.terms[0]!="-":return
        _,left,right=value.terms
        self.check_subtractions(fn,node,state,left)
        valid=(left.kind=="parcel_size" and (left.key,right.key) in state.size_lower) or ((right.key,left.key) in state.upper)
        if not valid:
            self.emit("DATA-01","ipc.parcel.position-underflow",fn,node,state,
                      "Parcel read-position subtraction lacks a matched size/length bound: "+value.key)

    def assign(self,state,name,value):
        # Reassignment invalidates guard facts about the old value.
        old=state.env.get(name)
        if old:
            state.lower=state.lower-{old.key}
            state.upper=frozenset((k,b) for k,b in state.upper if k!=old.key)
            state.owner=state.owner-{old.key}
        if value.kind=="request":
            value=replace(value,key=name)
            if value.subject=="unsigned":state.lower=state.lower|{name}
        state.env[name]=value

    def refine(self,fn,node,state,truth,depth):
        if node is None:return [state.fork()]
        if node.type in ("parenthesized_expression","condition_clause"):
            child=node.child_by_field_name("value") or (node.named_children[-1] if node.named_children else None)
            return self.refine(fn,child,state,truth,depth)
        if node.type=="unary_expression" and fn.text(node.child_by_field_name("operator"))=="!":
            return self.refine(fn,node.child_by_field_name("argument"),state,not truth,depth)
        if node.type=="binary_expression":
            op=fn.text(node.child_by_field_name("operator"));left=node.child_by_field_name("left");right=node.child_by_field_name("right")
            if op in ("&&","||"):
                if (op=="&&" and truth) or (op=="||" and not truth):
                    first=self.refine(fn,left,state,truth,depth)
                    return self.bounded([t for s in first for t in self.refine(fn,right,s,truth,depth)])
                short=self.refine(fn,left,state,truth,depth)
                longer=[t for s in self.refine(fn,left,state,not truth,depth) for t in self.refine(fn,right,s,truth,depth)]
                return self.bounded(short+longer)
        out=state.fork();val=self.value(fn,node,out,depth)
        if val.kind=="constant" and val.key in ("true","false","0","1"):
            if (val.key in ("true","1"))!=truth:return []
        pred=val.predicate
        if val.kind=="permission_bool" and val.subject=="caller":pred=("auth",val.permission,True)
        if pred:
            kind,key,when=pred
            if truth==when:
                attr={"auth":"auth","descriptor":"descriptor","owner":"owner","lower":"lower","upper":"upper","size_lower":"size_lower","caller_class":"caller_class"}[kind]
                setattr(out,attr,getattr(out,attr)|{key})
        out.trace=(out.trace+((node.start_point[0]+1,fn.text(node)+" => "+str(truth)),))[-20:]
        return [out]

    def block(self,fn,node,states,depth):
        if node is None:return states
        if node.type in ("compound_statement","case_statement"):
            for child in node.named_children:
                if node.type=="case_statement" and child==node.child_by_field_name("value"):continue
                states=self.statement(fn,child,states,depth)
            return states
        return self.statement(fn,node,states,depth)

    def statement(self,fn,node,states,depth):
        done=[s for s in states if s.flow!="normal"];active=[s for s in states if s.flow=="normal"]
        if not active:return states
        kind=node.type
        if kind=="compound_statement":return done+self.block(fn,node,active,depth)
        if kind=="if_statement":
            cond=node.child_by_field_name("condition");yes=node.child_by_field_name("consequence");no=node.child_by_field_name("alternative")
            result=[]
            for s in active:
                result+=self.block(fn,yes,self.refine(fn,cond,s,True,depth),depth)
                ns=self.refine(fn,cond,s,False,depth)
                if no and no.type=="else_clause":
                    no=no.named_children[-1] if no.named_children else None
                result+=self.block(fn,no,ns,depth)
            return self.bounded(done+result)
        if kind=="switch_statement":
            body=node.child_by_field_name("body");cases=[c for c in body.named_children if c.type=="case_statement"] if body else []
            result=[]
            for s in active:
                # Independent case entries plus real C/C++ fall-through. A
                # preceding case's guard cannot protect another entry case.
                for index in range(len(cases)):
                    branch=[s.fork(trace=s.trace+((cases[index].start_point[0]+1,"switch entry"),))]
                    for case in cases[index:]:
                        branch=self.block(fn,case,branch,depth)
                    result.extend(t.fork(flow="normal") if t.flow=="break" else t for t in branch)
                if not any(fn.text(c).lstrip().startswith("default") for c in cases):result.append(s.fork())
            return self.bounded(done+result)
        if kind in ("for_statement","while_statement","do_statement","for_range_loop"):
            self.limitations.add("Loops are conservatively explored zero/one iterations; no induction or termination proof.")
            result=[];body=node.child_by_field_name("body")
            for s in active:
                result.append(s.fork())
                one=self.block(fn,body,[s.fork()],depth)
                result.extend(t.fork(flow="normal") if t.flow in ("break","continue") else t for t in one)
            return self.bounded(done+result)
        if kind in ("return_statement","throw_statement"):
            for s in active:
                expr=node.named_children[0] if node.named_children else None
                s.returned=self.value(fn,expr,s,depth);s.flow="return"
            return done+active
        if kind in ("break_statement","continue_statement"):
            return done+[s.fork(flow="break" if kind=="break_statement" else "continue") for s in active]
        if kind in ("goto_statement","try_statement","preproc_if","preproc_ifdef"):
            self.limitations.add("Unsupported control construct: "+kind+"; guards not proved through it.")
            for s in active:
                s.auth=frozenset();s.descriptor=frozenset();s.owner=frozenset()
        for s in active:
            if kind=="declaration":
                for dec in node.named_children:
                    if dec.type=="init_declarator":
                        d=dec.child_by_field_name("declarator")
                        ids=list(walk(d,"identifier")) if d else []
                        name=fn.text(ids[-1] if ids else d)
                        self.assign(s,name,self.value(fn,dec.child_by_field_name("value"),s,depth))
                    elif dec.type=="array_declarator":
                        name=fn.text(dec.child_by_field_name("declarator"));size=fn.text(dec.child_by_field_name("size"))
                        self.capacities[name]=size
                        # sizeof(buf) is a matching bound independently of element size.
                        self.capacities["sizeof("+name+")"]=size
            elif kind=="expression_statement":
                for expr in node.named_children:
                    if expr.type=="binary_expression" and fn.text(expr.child_by_field_name("operator")) in ("&&","||"):
                        # Evaluate both *paths*, never blindly execute both operands.
                        forks=self.refine(fn,expr,s,True,depth)+self.refine(fn,expr,s,False,depth)
                        if forks:
                            s.auth=frozenset.intersection(*(t.auth for t in forks))
                            s.descriptor=frozenset.intersection(*(t.descriptor for t in forks))
                    else:self.value(fn,expr,s,depth)
            else:
                self.value(fn,node,s,depth)
        return self.bounded(done+active)

    def run(self):
        for fn in self.functions:
            if not ((fn.name in self.policy.entry_names or fn.name in self.policy.transport_entries or (fn.name.endswith("Inner") and "Stub" in fn.owner)) and fn.parcel_params or fn.qualified in self.policy.service_entries):
                continue
            self.root=fn;self.capacities={};self.active=(fn,)
            env={p:Value("parcel",p) if p in fn.parcel_params else Value("request",p)
                 for p in fn.params}
            self.block(fn,fn.body,[State(env=env)],0)
        revised=[]
        for obs in self.observations:
            if obs.rule=="ipc.auth.missing":
                # Permission call somewhere is not coverage. Keep the primary
                # finding and add the explicit coverage subtype for these roots.
                if obs.root_key in self.seen_permissions:
                    revised.append(replace(obs,family="AUTH-04",rule="ipc.auth.guard-coverage",
                        message="Authorization checks exist in the analyzed entry set, but this modeled sensitive path has no matched caller guard. "+obs.message))
            revised.append(obs)
        unique={}
        for obs in revised:
            unique.setdefault((obs.file,obs.line,obs.rule,obs.symbol),obs)
        return tuple(unique[k] for k in sorted(unique)),tuple(sorted(self.limitations))
