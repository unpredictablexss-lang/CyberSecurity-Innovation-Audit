"""Bounded proof of the visible LOGE -> CF_LOG_E formatting argument chain.

No macro execution/preprocessing is performed. Unknown/ambiguous branches fail
closed to ordinary candidate analysis. The fallback body is reviewed only at its
exact original source hash; arbitrary CfPrintLog functions are not trusted.
"""
import ast
import re
from .property_keys import guarded_global, walk

CERT_LOG_PATH = 'frameworks/common/v1.0/inc/cf_log.h'
CERT_LOG_SHA256 = '489ea3537091147d5bec365471698f3d5d177dbc86473beb25fd7bc906beccb9'
CERT_LOG_COMMIT = 'e270363a042bf8f0126881c76d1341ad457cc187'
_TERMINAL_IDENTITIES = ('HILOG_ERROR', 'CfPrintLog', 'LOG_CORE', '__FUNCTION__', '__FILE__', '__LINE__', '__VA_ARGS__')


def enclosing_function(node):
    while node is not None:
        if node.type == 'function_definition':
            return node.start_byte
        node = node.parent
    return None


_STRING = r'"(?:\\.|[^"\\])*"'


class LogMacroRoles:
    def __init__(self, flow, format_parser):
        self.flow = flow
        self.format_parser = format_parser
        self.cached = None
        self.checked = False

    def terminal_role(self, definition, flow):
        parameters = flow.text(definition.child_by_field_name('parameters'))
        parameter = re.fullmatch(r'\(\s*([A-Za-z_]\w*)\s*,\s*\.\.\.\s*\)', parameters)
        if not parameter:
            return False
        fmt = re.escape(parameter.group(1))
        body = flow.text(definition.child_by_field_name('value')).strip()
        fallback = (r'CfPrintLog\(\s*"ERROR"\s*,\s*__FILE__\s*,\s*__LINE__\s*,\s*'
                    r'__FUNCTION__\s*,\s*' + fmt + r'\s*,\s*(?:##\s*)?__VA_ARGS__\s*\)')
        if re.fullmatch(fallback, body):
            return flow.u.path == CERT_LOG_PATH and flow.u.sha256 == CERT_LOG_SHA256
        pattern = (r'HILOG_ERROR\(\s*LOG_CORE\s*,\s*'
                   r'(?P<prefix>(?:' + _STRING + r'\s*)*)' + fmt +
                   r'(?P<suffix>(?:\s*' + _STRING + r')*)\s*,\s*'
                   r'(?P<metadata>__FUNCTION__\s*,\s*__LINE__\s*,\s*)?'
                   r'(?:##\s*)?__VA_ARGS__\s*\)')
        match = re.fullmatch(pattern, body)
        if not match:
            return False
        try:
            prefix = ''.join(ast.literal_eval(s) for s in re.findall(_STRING, match.group('prefix')))
            suffix = ''.join(ast.literal_eval(s) for s in re.findall(_STRING, match.group('suffix')))
            slots, count = self.format_parser(prefix)
            _, suffix_count = self.format_parser(suffix)
        except (ValueError, SyntaxError):
            return False
        if suffix_count:
            return False
        if match.group('metadata'):
            return count == 2 and [slot[2] for slot in slots] == ['s', 'u']
        return count == 0

    def resolve(self):
        # Terminal names and implicitly added metadata are looked up at the call
        # site. A cached header proof must not override local aliases/shadows.
        if any(name in self.flow.shadows for name in _TERMINAL_IDENTITIES):
            self.flow.gaps.add('LOGE terminal or implicit metadata is locally shadowed; macro argument proof withheld')
            return None
        if self.checked:
            return self.cached
        self.checked = True
        flow = self.flow
        visible = flow.property_keys.visible_units()
        if visible is None:
            return None
        # Selected transitive/other headers may carry an override even when
        # direct-include name lookup did not add them to the proof graph.
        units = flow.resolver.units if flow.resolver is not None else (flow.u,)
        identities = '|'.join(re.escape(name) for name in _TERMINAL_IDENTITIES)
        if any(re.search(r'^\s*#\s*(?:define|undef)\s+(?:' + identities + r')\b', unit.text, re.M)
               for unit in units):
            flow.gaps.add('LOGE terminal or implicit metadata has a selected-source macro override; proof withheld')
            return None
        visible_paths = {item.u.path for item in visible}
        if any(unit.path not in visible_paths and re.search(
                r'^\s*#\s*(?:define|undef)\s+(?:LOGE|CF_LOG_E)\b', unit.text, re.M) for unit in units):
            flow.gaps.add('LOGE alias definitions exist outside the proven include graph; proof withheld')
            return None
        definitions = {'LOGE': [], 'CF_LOG_E': []}
        for unit_flow in visible:
            text = unit_flow.u.text
            guarded_tokens = '|'.join(re.escape(name) for name in ('LOGE', 'CF_LOG_E') + _TERMINAL_IDENTITIES)
            if re.search(r'^\s*#\s*undef\s+(?:' + guarded_tokens + r')\b', text, re.M):
                return None
            for name in ('LOGE', 'CF_LOG_E', 'HILOG_ERROR', 'CfPrintLog'):
                if name in unit_flow.function_definitions and name != 'CfPrintLog':
                    return None
            for node in walk(unit_flow.tree.root_node):
                if node.type not in ('preproc_def', 'preproc_function_def'):
                    continue
                name = unit_flow.text(node.child_by_field_name('name'))
                if name in _TERMINAL_IDENTITIES:
                    flow.gaps.add('LOGE terminal or implicit metadata has a visible macro override; argument proof withheld')
                    return None
                if name in definitions:
                    definitions[name].append((unit_flow, node))
        aliases = definitions['LOGE']
        if len(aliases) != 1:
            return None
        alias_flow, alias = aliases[0]
        if (alias.type != 'preproc_def' or not guarded_global(alias, alias_flow)
                or alias_flow.text(alias.child_by_field_name('value')).strip() != 'CF_LOG_E'):
            return None
        targets = definitions['CF_LOG_E']
        if len(targets) == 1:
            owner, target = targets[0]
            if not guarded_global(target, owner):
                return None
        elif len(targets) == 2:
            (owner, first), (other, second) = targets
            branch = first.parent
            alternate = branch.child_by_field_name('alternative')
            if (owner is not other or branch.type not in ('preproc_ifdef', 'preproc_if')
                    or alternate is None or alternate.type != 'preproc_else'
                    or second.parent != alternate or not guarded_global(branch, owner)):
                return None
        else:
            return None
        if not all(self.terminal_role(target, owner) for owner, target in targets):
            return None
        self.cached = ' | '.join(
            f'{owner.u.path}:{target.start_point[0]+1} sha256={owner.u.sha256}'
            for owner, target in aliases + targets)
        return self.cached
