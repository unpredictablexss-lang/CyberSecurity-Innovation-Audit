"""Narrow source-bound candidate for Parcel-carried fd mmap bounds.

This supplementary rule only links a locally declared MessageParcelWarp receiver
to one unique ReadRawData body. It recognizes the fd returned by ReadFileDescriptor,
the same fd passed to mmap, and a same-fd capacity check that exits before mmap.
It does not prove IPC reachability, attacker control, ashmem semantics or impact.
"""
from hashlib import sha256
import re

from tree_sitter import Language, Parser
import tree_sitter_cpp
from .analysis import normalize_syntax

from src.ohscanner.contracts import DetectorFinding, EvidenceObligation, SourceUnit


def _walk(node):
    stack = [node]
    while stack:
        item = stack.pop()
        yield item
        stack.extend(reversed(item.named_children))


def _text(node, source):
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace") if node else ""


def _terminal(text):
    return re.split(r"::|->|\.", text)[-1].strip()


def _functions(units):
    result = []
    for unit in units:
        if unit.language not in ("c", "cpp"):
            continue
        source = unit.text.encode("utf-8")
        tree = Parser(Language(tree_sitter_cpp.language())).parse(normalize_syntax(source))
        if tree.root_node.has_error:
            continue
        for node in _walk(tree.root_node):
            if node.type != "function_definition" or node.has_error:
                continue
            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            signature = _text(declarator, source)
            if body is None or _terminal(signature.split("(", 1)[0]) != "ReadRawData":
                continue
            if "MessageParcelWarp" not in signature:
                continue
            owner_match = re.search(r"([A-Za-z_][\w:]*)::ReadRawData\s*\(", signature)
            if not owner_match or _terminal(owner_match.group(1)) != "MessageParcelWarp":
                continue
            result.append((unit, source, node, body, signature))
    return result


def _fd_mmap(body, source):
    body_text = _text(body, source)
    read = re.search(
        r"\b(?:auto|int|int32_t|int64_t)\s+([A-Za-z_]\w*)\s*=\s*"
        r"[\w.>:-]+\.ReadFileDescriptor\s*\(\s*\)", body_text)
    if not read:
        return None
    fd = read.group(1)
    mmap_call = None
    for node in _walk(body):
        if node.type != "call_expression":
            continue
        callee = _text(node.child_by_field_name("function"), source).replace(" ", "")
        if _terminal(callee) != "mmap":
            continue
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node else []
        if len(args) < 5:
            continue
        if _text(args[4], source).strip() != fd:
            continue
        length = _text(args[1], source).strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", length):
            continue
        mmap_call = (node, length)
        break
    if mmap_call is None:
        return None
    mmap_node, length = mmap_call
    # Credit only a straight-line, explicit failing-condition early return.
    # A macro name, a return somewhere inside an if, or a mutable capacity
    # variable does not establish that the unsafe path is rejected.
    statement = mmap_node
    while statement.parent is not None and statement.parent != body:
        statement = statement.parent
    if (statement.parent != body or statement.type != 'return_statement'
            or list(statement.named_children) != [mmap_node]):
        return fd, length, mmap_node
    prior = [n for n in body.named_children if n.end_byte <= statement.start_byte]
    seen_fd, clean, guarded, capacities = False, True, False, set()
    for item in prior:
        if item.type == 'comment':
            continue
        text = _text(item, source).strip()
        fd_decl = re.fullmatch(
            r'(?:auto|int|int32_t|int64_t)\s+' + re.escape(fd)
            + r'\s*=\s*[\w.>:-]+\.ReadFileDescriptor\s*\(\s*\)\s*;', text)
        if fd_decl:
            if seen_fd:
                clean = False
            seen_fd = True
            continue
        if not seen_fd:
            continue
        cap_decl = re.fullmatch(
            r'(?:auto|int|int32_t|int64_t|ssize_t)\s+([A-Za-z_]\w*)'
            + r'\s*=\s*AshmemGetSize\s*\(\s*' + re.escape(fd) + r'\s*\)\s*;', text)
        if cap_decl and not guarded:
            capacities.add(cap_decl.group(1))
            continue
        if item.type == 'if_statement' and clean and not guarded:
            condition = item.child_by_field_name('condition')
            consequence = item.child_by_field_name('consequence')
            alternative = item.child_by_field_name('alternative')
            cond = re.sub(r'static_cast\s*<[^>]+>\s*\(\s*([A-Za-z_]\w*)\s*\)',
                          r'\1', _text(condition, source))
            cond = re.sub(r'\s+', '', cond).replace('(', '').replace(')', '')
            rejects = any(cond in (
                cap + '<0||' + length + '>' + cap,
                length + '>' + cap + '||' + cap + '<0',
            ) for cap in capacities)
            statements = ([n for n in consequence.named_children if n.type != 'comment']
                          if consequence is not None and consequence.type == 'compound_statement'
                          else [consequence])
            exits = (len(statements) == 1 and statements[0] is not None
                     and statements[0].type == 'return_statement')
            if rejects and exits and alternative is None:
                guarded = True
                continue
        # Assignments, nested control, calls, aliases and unbound macros can
        # invalidate fd/length/capacity or fail to reject the unsafe path.
        clean = False
    return None if seen_fd and clean and guarded else (fd, length, mmap_node)


def detect_fd_backing_findings(units):
    """Return findings at the caller only when receiver type/body binding is unique."""
    implementations = _functions(units)
    targets = [item for item in implementations
               if _terminal(item[4].split("(", 1)[0]) == "ReadRawData"]
    if len(targets) != 1:
        return (), ("FD backing rule skipped: MessageParcelWarp::ReadRawData body is absent or ambiguous.",)
    target = targets[0]
    effect = _fd_mmap(target[3], target[1])
    if effect is None:
        return (), ()
    findings = []
    limitations = []
    for unit in units:
        if unit.language not in ("c", "cpp"):
            continue
        source = unit.text.encode("utf-8")
        tree = Parser(Language(tree_sitter_cpp.language())).parse(normalize_syntax(source))
        if tree.root_node.has_error:
            continue
        for fn in _walk(tree.root_node):
            if fn.type != "function_definition" or fn.has_error:
                continue
            body = fn.child_by_field_name("body")
            if body is None:
                continue
            function_text = _text(fn, source)
            for call in _walk(body):
                if call.type != "call_expression":
                    continue
                callee_node = call.child_by_field_name("function")
                callee = _text(callee_node, source)
                if _terminal(callee) != "ReadRawData" or not ("." in callee or "->" in callee):
                    continue
                receiver = re.split(r"\.|->", callee)[0].strip()
                declaration = re.compile(
                    r"\bMessageParcelWarp\s*(?:\*|&)?\s*"
                    + re.escape(receiver) + r"\b")
                if len(declaration.findall(function_text)) != 1:
                    continue
                findings.append(DetectorFinding(
                    file=unit.path, line=call.start_point[0] + 1,
                    rule_id="ipc.parcel.fd-backing-size",
                    symbol="MessageParcelWarp::ReadRawData", evidence_type="syntax",
                    candidate_cwe="CWE-20", consequence_impact="out_of_bounds_read",
                    consequence_cwe="CWE-125",
                    message=("Candidate locally typed MessageParcelWarp receiver may reach a unique "
                             "ReadRawData body that maps parcel fd " + effect[0] + " using "
                             "requested length " + effect[1] + "; this rule did not establish a same-fd capacity "
                             "check that exits before mmap."),
                    evidence_obligations=(
                        EvidenceObligation("receiver_and_guard_binding",
                            "Resolve receiver/type/overload identity, macros, aliases and all guard paths; unmodeled guards remain unknown."),
                        EvidenceObligation("entry_reachability",
                            "Verify the calling transaction, remote caller and dispatch guards."),
                        EvidenceObligation("fd_origin_and_capacity",
                            "Verify the Parcel-carried descriptor origin/type and actual backing size."),
                        EvidenceObligation("security_impact",
                            "Verify caller control, affected process and concrete confidentiality/integrity/availability effect."),
                    ) + ((EvidenceObligation("parse_completeness_impact",
                            "The shared source parse is partial; review parser errors and surrounding call/control context."),)
                         if unit.parse_status != "complete" else ()), source_sha256=sha256(unit.text.encode("utf-8")).hexdigest(),
                ))
    if not findings:
        limitations.append("FD backing rule saw the unsafe implementation shape but no unique locally typed caller in complete scanned C/C++ files.")
    return tuple(findings), tuple(limitations)
