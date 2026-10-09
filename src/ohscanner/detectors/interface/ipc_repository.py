"""Offline source-derived IPC entry and bounded permission call-chain inventory.

No inferred policy, vulnerability verdict, public schema change, or external
scanner invocation. Missing resolution and macro effects stay explicit.
"""
from collections import defaultdict, deque
import hashlib
import json
import re
from pathlib import PurePosixPath

from tree_sitter import Parser
from src.ohscanner.detectors.interface.cpp_permission import CPP_LANGUAGE


def walk(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def text(data, node):
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="replace") if node else ""


def name_node(node):
    while node is not None and node.type not in {"identifier", "field_identifier", "qualified_identifier"}:
        node = node.child_by_field_name("declarator")
    return node


def parents(node):
    while node.parent is not None:
        node = node.parent
        yield node


def macro_catalog(sources):
    """Collect every definition variant; summarize only common return syntax.

    These summaries do not erase logging/other effects and are not a compiler
    preprocessor. Variadic/token-paste definitions are retained as unresolved.
    """
    definitions = defaultdict(list)
    for path, data in sources.items():
        original = data.decode("utf-8", errors="replace")
        # Ignore apparent directives inside comments; keep physical line locations.
        cleaned = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
            lambda m: "".join("\n" if c == "\n" else " " for c in m[0]) if m[0].startswith(("/*", "//")) else m[0], original, flags=re.S)
        logical, start = "", 1
        conditional = []
        for number, line in enumerate(cleaned.splitlines(), 1):
            if not logical:
                start = number
            continued = line.rstrip().endswith("\\")
            logical += line.rstrip().removesuffix("\\") + " "
            if continued:
                continue
            directive = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", logical)
            if directive:
                command, argument = directive.groups()
                if command in {"if", "ifdef", "ifndef"}:
                    conditional.append(command+argument.strip())
                elif command in {"elif", "else"} and conditional:
                    conditional[-1] = command+argument.strip()
                elif command == "endif" and conditional:
                    conditional.pop()
            match = re.match(r"\s*#\s*define\s+(\w+)(\([^)]*\))?\s+(.*)", logical)
            if match:
                name, params, body = match.groups()
                definitions[name].append({"file": path, "line": start, "body": body.strip(),
                    "parameters": [p.strip() for p in params[1:-1].split(",")] if params else None,
                    "conditional_context": list(conditional),
                    "source_sha256": hashlib.sha256(data).hexdigest()})
            logical = ""
    result = {}
    for name, variants in definitions.items():
        signatures = []
        for definition in variants:
            # Remove comments and string literals before detecting statement syntax.
            body = re.sub(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*', '""', definition["body"], flags=re.S)
            found = re.search(r"if\s*\(\s*\(?(\w+)\)?\s*==\s*nullptr\s*\)\s*\{.*?\breturn\s+(\w+)\s*;", body, re.S)
            signatures.append(found.groups() if found else None)
        common = signatures[0] if signatures and signatures[0] is not None and all(s == signatures[0] for s in signatures) else None
        result[name] = {"definitions": variants, "common_null_return_syntax":
                        {"checked_parameter": common[0], "return_parameter": common[1]} if common else None,
                        "full_effects": "unknown", "permission_guard": False}
    return result


class RepositoryIndex:
    def __init__(self, sources, repository, commit):
        if not isinstance(repository, str) or not repository.strip() or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("repository and full commit required")
        if not isinstance(sources, dict) or not sources or len(sources) > 300:
            raise ValueError("1..300 source files required")
        if all(isinstance(v, bytes) for v in sources.values()) and sum(len(v) for v in sources.values()) > 20_000_000:
            raise ValueError("repository byte budget exceeded")
        self.repository, self.commit = repository, commit
        self.sources, self.trees, self.functions = {}, {}, defaultdict(list)
        self.classes, self.aliases, self.override_candidates = {}, {}, defaultdict(list)
        self.enums = {}
        for path, data in sources.items():
            if not isinstance(path, str) or ":" in path or "\\" in path or PurePosixPath(path).is_absolute() or any(p in {"", ".", ".."} for p in path.split("/")):
                raise ValueError("invalid repository path")
            if not isinstance(data, bytes) or len(data) > 2_000_000:
                raise ValueError("source bytes required; 2MB/file limit")
            self.sources[path] = data
            tree = Parser(CPP_LANGUAGE).parse(data)
            self.trees[path] = tree
            for node in walk(tree.root_node):
                if node.type == "class_specifier":
                    name = text(data, node.child_by_field_name("name"))
                    base = next((c for c in node.named_children if c.type == "base_class_clause"), None)
                    self.classes.setdefault(name, []).append(text(data, base))
                    if base:
                        base_names = [text(data, c).split("::")[-1] for c in base.named_children if c.type in {"type_identifier", "qualified_identifier"}]
                        for member in walk(node):
                            if member.type == "field_declaration" and any(c.type == "virtual_specifier" and text(data, c) == "override" for c in walk(member)):
                                method = next((c for c in walk(member) if c.type == "function_declarator"), None)
                                if method:
                                    method_name = text(data, method.child_by_field_name("declarator"))
                                    for base_name in base_names:
                                        self.override_candidates[base_name+"::"+method_name].append(name+"::"+method_name)
                if node.type == "enumerator":
                    name = text(data, node.child_by_field_name("name"))
                    value = text(data, node.child_by_field_name("value"))
                    self.enums.setdefault(name, set()).add(value or "implicit_unknown")
                if node.type != "function_definition":
                    continue
                declarator = node.child_by_field_name("declarator")
                while declarator is not None and declarator.type != "function_declarator":
                    declarator = declarator.child_by_field_name("declarator")
                if declarator is None:
                    continue
                name = text(data, declarator.child_by_field_name("declarator"))
                if "::" not in name:
                    enclosing = next((p for p in parents(node) if p.type == "class_specifier"), None)
                    if enclosing:
                        name = text(data, enclosing.child_by_field_name("name")) + "::" + name
                params = declarator.child_by_field_name("parameters")
                parameter_names = [text(data, name_node(p.child_by_field_name("declarator"))) for p in params.named_children if p.type == "parameter_declaration"] if params else []
                record = {"name": name, "file": path, "line": node.start_point.row+1, "node": node,
                          "body": node.child_by_field_name("body"), "parameters": parameter_names,
                          "parse_status": "partial" if node.has_error else "complete"}
                self.functions[name].append(record)
        self.macros = macro_catalog(self.sources)
        # Source-backed DelayedSingleton<T> object macro, never guess arbitrary receiver types.
        for alias, record in self.macros.items():
            targets = set()
            for definition in record["definitions"]:
                match = re.fullmatch(r"::[\w:]+<([\w:]+)>::GetInstance\(\)", definition["body"])
                if match:
                    targets.add(match.group(1).split("::")[-1])
            if len(targets) == 1 and len(targets) == len(record["definitions"]):
                self.aliases[alias] = next(iter(targets))

    def location(self, record, node):
        data = self.sources[record["file"]]
        return {"file": record["file"], "line": node.start_point.row+1,
                "source_sha256": hashlib.sha256(data).hexdigest()}

    def enclosing_conditions(self, record, node):
        data = self.sources[record["file"]]
        conditions = []
        for parent in parents(node):
            if parent.type == "if_statement":
                role = "unknown"
                for field in ("condition", "consequence", "alternative"):
                    region = parent.child_by_field_name(field)
                    if region is not None and region.start_byte <= node.start_byte < region.end_byte:
                        role = field
                        break
                conditions.append({"expression": text(data, parent.child_by_field_name("condition")),
                    "role": role, "feasibility": "unknown"})
            if parent.id == record["node"].id:
                break
        return conditions

    def calls(self, record):
        data = self.sources[record["file"]]
        for node in walk(record["body"]):
            if any(p.type == "lambda_expression" for p in parents(node)):
                continue
            if node.type != "call_expression":
                continue
            callee = text(data, node.child_by_field_name("function"))
            args = node.child_by_field_name("arguments")
            arguments = [text(data, a) for a in args.named_children if a.type != "comment"] if args else []
            conditions = self.enclosing_conditions(record, node)
            yield {"callee": callee, "arguments": arguments, "conditions": conditions,
                   "node": node, **self.location(record, node)}

    def resolve(self, record, callee):
        owner = record["name"].rsplit("::", 1)[0] if "::" in record["name"] else ""
        target = callee
        if "->" in callee or "." in callee:
            split = re.split(r"->|\.", callee)
            if len(split) != 2 or split[0] not in self.aliases:
                return None, "unresolved_receiver"
            target = self.aliases[split[0]] + "::" + split[1]
        elif "::" not in callee and owner and owner + "::" + callee in self.functions:
            target = owner + "::" + callee
        candidates = self.functions.get(target, [])
        if len(candidates) == 1:
            return candidates[0], "source_resolved"
        if len(candidates) > 1:
            return None, "ambiguous_overload"
        return None, "definition_missing"

    def entries(self):
        entries = []
        for name, records in self.functions.items():
            if not name.endswith("::OnRemoteRequest"):
                continue
            owner = name.rsplit("::", 1)[0]
            if not any("IRemoteStub<" in base.replace(" ", "") or "IPCObjectStub" in base for base in self.classes.get(owner, [])):
                continue
            for record in records:
                data = self.sources[record["file"]]
                if "MessageParcel" not in text(data, record["node"].child_by_field_name("declarator")):
                    continue
                for node in walk(record["body"]):
                    # std::map initializer pair {Interface::CODE, &Stub::Handler}
                    if node.type == "initializer_list" and len(node.named_children) == 2:
                        code = text(data, node.named_children[0])
                        pointer = text(data, node.named_children[1])
                        match = re.fullmatch(r"&\s*([\w:]+)", pointer)
                        if match and match.group(1).startswith(owner+"::") and self._map_is_dispatched(record, node):
                            handler = match.group(1)
                            entries.append(self._entry(record, node, code, handler, "dispatch_map"))
                    if node.type == "case_statement":
                        code = text(data, node.child_by_field_name("value"))
                        for call in self.calls({**record, "body": node}):
                            target, status = self.resolve(record, call["callee"])
                            # Limit switch dispatch to direct returns of handler(data, reply).
                            if target and status == "source_resolved" and call["node"].parent.type == "return_statement" and call["arguments"][:2] == ["data", "reply"]:
                                entries.append(self._entry(record, call["node"], code, target["name"], "dispatch_switch"))
        return sorted(entries, key=lambda e: (e["file"], e["line"], e["handler"]))

    def _map_is_dispatched(self, record, node):
        data = self.sources[record["file"]]
        declaration = next((p for p in parents(node) if p.type == "init_declarator"), None)
        if declaration is None:
            return False
        map_name = text(data, name_node(declaration.child_by_field_name("declarator")))
        iterators = []
        for item in walk(record["body"]):
            if item.type != "init_declarator":
                continue
            value = item.child_by_field_name("value")
            if value is None or value.type != "call_expression":
                continue
            callee = text(data, value.child_by_field_name("function"))
            args = value.child_by_field_name("arguments")
            if callee == map_name+".find" and text(data, args).replace(" ", "") == "(code)":
                iterators.append(text(data, name_node(item.child_by_field_name("declarator"))))
        return any(call["arguments"] == ["data", "reply"] and any(
            re.fullmatch(r"\(this\s*->\*\s*"+re.escape(it)+r"->second\)", call["callee"])
            for it in iterators) for call in self.calls(record))

    def _entry(self, record, node, code, handler, kind):
        values = [code] if re.fullmatch(r"(?:0x[0-9A-Fa-f]+|\d+)", code) else sorted(self.enums.get(code.split("::")[-1], {"unknown"}))
        return {"dispatcher": record["name"], "handler": handler, "transaction": code,
                "transaction_values": values, "kind": kind, "entry_evidence": "source_dispatch",
                "reachability": "unknown", **self.location(record, node)}

    def binding(self, value, environment):
        value = value.strip()
        if value in environment:
            return environment[value]
        if value.startswith('"'):
            try:
                return {"value": json.loads(value), "origin": "literal"}
            except json.JSONDecodeError:
                pass
        if re.fullmatch(r"(?:OHOS::)?IPCSkeleton::GetCallingTokenID\(\)", value):
            return {"value": "ipc_caller_token", "origin": "caller_token_api"}
        return {"value": value, "origin": "unresolved_expression"}

    def environment_at(self, record, call_node, environment):
        data = self.sources[record["file"]]
        local = dict(environment)
        scopes = {p.id for p in parents(call_node) if p.type == "compound_statement"}
        for node in walk(record["body"]):
            if node.start_byte >= call_node.start_byte:
                continue
            scope = next((p for p in parents(node) if p.type == "compound_statement"), None)
            if scope is None or scope.id not in scopes:
                continue
            if node.type == "init_declarator":
                identifier = text(data, name_node(node.child_by_field_name("declarator")))
                value = text(data, node.child_by_field_name("value"))
                if identifier:
                    local[identifier] = self.binding(value, local)
            if node.type in {"assignment_expression", "update_expression"}:
                affected = text(data, node.child_by_field_name("left") or node.child_by_field_name("argument"))
                if affected:
                    local[affected] = {"value": affected, "origin": "modified_unknown"}
        return local

    def guard_relationship(self, record, call, target):
        data = self.sources[record["file"]]
        # Only boolean helpers; int return codes need explicit result semantics.
        return_type = text(self.sources[target["file"]], target["node"].child_by_field_name("type"))
        if return_type != "bool":
            return {"check_result_relation": "unknown_non_boolean_return"}
        if_node = next((p for p in parents(call["node"]) if p.type == "if_statement"), None)
        if if_node is None:
            return {"check_result_relation": "not_direct_if_condition", "review_status": "needs_context"}
        condition = if_node.child_by_field_name("condition")
        if condition is None or not (condition.start_byte <= call["node"].start_byte < condition.end_byte):
            return {"check_result_relation": "call_in_branch_not_condition", "review_status": "needs_context"}
        negation = next((p for p in parents(call["node"]) if p.type == "unary_expression" and text(data, p.child_by_field_name("operator")) == "!" and p.start_byte >= condition.start_byte), None)
        if negation is None:
            return {"check_result_relation": "positive_or_complex_condition", "review_status": "needs_context"}

        def terminates(node):
            if node is None:
                return False
            if node.type == "return_statement":
                return True
            if node.type == "compound_statement":
                return any(terminates(c) for c in node.named_children)
            if node.type == "if_statement":
                return terminates(node.child_by_field_name("consequence")) and terminates(node.child_by_field_name("alternative"))
            if node.type == "else_clause":
                return bool(node.named_children) and terminates(node.named_children[0])
            return False
        return {"check_result_relation": "negated_boolean_in_condition", "condition": text(data, condition),
                "consequence_terminates_syntax": terminates(if_node.child_by_field_name("consequence")),
                "review_status": "unassessed", "limitation": "Compound condition feasibility and helper side effects unproven"}

    def trace_permissions(self, entry, max_depth=5, max_states=256):
        if type(max_depth) is not int or not 0 <= max_depth <= 8 or type(max_states) is not int or not 1 <= max_states <= 2048:
            raise ValueError("invalid trace limits")
        roots = self.functions.get(entry["handler"], [])
        output = {"entry": entry, "requirements": [], "call_edges": [], "unresolved": [],
                  "source_fields": [], "success_shortcuts": [], "guard_relationships": [], "authority": "observed_source_constraints_not_normative_policy",
                  "confidence": "unassessed", "validated_vulnerability": 0}
        if len(roots) != 1:
            output["unresolved"].append({"reason": "handler_missing_or_ambiguous"})
            return output
        queue = deque([(roots[0], {}, [entry["handler"]], [], 0)])
        seen = set()
        while queue:
            record, environment, chain, path_conditions, depth = queue.popleft()
            key = (record["name"], record["file"], json.dumps(environment, sort_keys=True), json.dumps(path_conditions, sort_keys=True))
            if key in seen:
                continue
            if len(seen) >= max_states:
                output["unresolved"].append({"reason": "trace_budget_exceeded"})
                break
            seen.add(key)
            data = self.sources[record["file"]]
            if record["parse_status"] != "complete":
                output["unresolved"].append({"function": record["name"], "reason": "partial_parse"})
            for node in walk(record["body"]):
                if node.type == "return_statement" and text(data, node).strip() == "return true;":
                    conditions = self.enclosing_conditions(record, node)
                    output["success_shortcuts"].append({"function": record["name"], "conditions": conditions,
                        "call_chain": chain, "meaning": "source_true_return_not_authorization_verdict", **self.location(record, node)})
            for call in self.calls(record):
                local = self.environment_at(record, call["node"], environment)
                callee, args = call["callee"], call["arguments"]
                location = {k: call[k] for k in ("file", "line", "source_sha256")}
                if "Read" in callee or callee.startswith("READ"):
                    output["source_fields"].append({"callee": callee, "arguments": args, **location})
                if callee.endswith("::VerifyAccessToken") and len(args) >= 2:
                    permission, subject = self.binding(args[1], local), self.binding(args[0], local)
                    output["requirements"].append({"kind": "access_token_permission", "permission": permission,
                        "subject": subject, "call_chain": chain, "conditions": path_conditions+call["conditions"],
                        "path_coverage": "unknown", **location})
                apl_conditions = []
                if callee.endswith("::GetHapTokenInfo"):
                    for statement in walk(record["body"]):
                        if statement.type != "if_statement":
                            continue
                        condition = statement.child_by_field_name("condition")
                        if condition is None:
                            continue
                        for operation in walk(condition):
                            if operation.type == "binary_expression" and text(data, operation.child_by_field_name("operator")) == "&":
                                has_required = any(n.type == "identifier" and text(data, n) == "required" for n in walk(operation))
                                has_apl = any(n.type == "field_identifier" and text(data, n) == "apl" for n in walk(operation))
                                if has_required and has_apl:
                                    apl_conditions.append({"expression": text(data, condition), **self.location(record, condition)})
                if callee.endswith("::GetHapTokenInfo") and "required" in local and apl_conditions:
                    output["requirements"].append({"kind": "application_privilege_constraint",
                        "required": local["required"], "subject": self.binding(args[0], local) if args else {},
                        "call_chain": chain, "conditions": path_conditions+call["conditions"],
                        "apl_guard_syntax": apl_conditions,
                        "path_coverage": "unknown", **location})
                if callee in self.macros:
                    output["call_edges"].append({"caller": record["name"], "callee": callee,
                        "resolution": "source_macro_syntax", "macro_catalog_ref": callee, **location})
                    output["unresolved"].append({"callee": callee, "reason": "macro_full_effects_unknown", **location})
                    continue
                if callee == "std::bind" and len(args) >= 2 and re.fullmatch(r"&[\w:]+", args[0]):
                    target_name = args[0][1:]
                    candidates = self.functions.get(target_name, [])
                    target = candidates[0] if len(candidates) == 1 else None
                    output["call_edges"].append({"caller": record["name"], "callee": callee,
                        "resolved_to": target_name if target else None, "resolution": "bound_callback_syntax_only", **location})
                    output["unresolved"].append({"callee": callee, "reason": "callback_execution_and_identity_context_unknown", **location})
                    if target and depth < max_depth and target_name not in chain:
                        bindings = {name: self.binding(value, local) for name, value in zip(target["parameters"], args[2:])}
                        queue.append((target, bindings, chain+[target_name], path_conditions+call["conditions"]+["deferred_callback_execution_unproven"], depth+1))
                    continue
                target, status = self.resolve(record, callee)
                output["call_edges"].append({"caller": record["name"], "callee": callee,
                    "resolved_to": target["name"] if target else None, "resolution": status, **location})
                if target:
                    if depth == 0:
                        output["guard_relationships"].append({"callee": callee, "resolved_to": target["name"],
                            **self.guard_relationship(record, call, target), **location})
                    if depth >= max_depth or target["name"] in chain:
                        output["unresolved"].append({"callee": callee, "reason": "depth_limit_or_recursion", **location})
                    else:
                        bindings = {name: self.binding(value, local) for name, value in zip(target["parameters"], args)}
                        queue.append((target, bindings, chain+[target["name"]], path_conditions+call["conditions"], depth+1))
                else:
                    output["unresolved"].append({"callee": callee, "reason": status, **location})
                    owner = record["name"].rsplit("::", 1)[0] if "::" in record["name"] else ""
                    overrides = self.override_candidates.get(owner+"::"+callee, []) if re.fullmatch(r"\w+", callee) else []
                    for possible_name in sorted(set(overrides)):
                        possible = self.functions.get(possible_name, [])
                        output["call_edges"].append({"caller": record["name"], "callee": callee,
                            "resolved_to": possible_name, "resolution": "possible_virtual_override_not_definite", **location})
                        if len(possible) == 1 and depth < max_depth and possible_name not in chain:
                            bindings = {name: self.binding(value, local) for name, value in zip(possible[0]["parameters"], args)}
                            queue.append((possible[0], bindings, chain+[possible_name], path_conditions+call["conditions"]+["dynamic_receiver_type_unproven"], depth+1))
        output["coverage"] = "partial" if output["unresolved"] else "complete_syntax_only"
        return output

    def inventory(self):
        return {"repository": self.repository, "commit": self.commit,
                "files": [{"file": path, "sha256": hashlib.sha256(data).hexdigest(),
                           "parsing": "partial" if self.trees[path].root_node.has_error else "complete"}
                          for path, data in sorted(self.sources.items())],
                "entries": [self.trace_permissions(e) for e in self.entries()],
                "macro_catalog": self.macros, "validated_vulnerability": 0,
                "limitations": ["Observed syntax only; service publication, device policy and guard dominance unproven.",
                                "Direct helper binding only; dynamic virtual/function-pointer targets remain unknown.",
                                "Macro common return syntax does not establish full expansion/side effects."]}
