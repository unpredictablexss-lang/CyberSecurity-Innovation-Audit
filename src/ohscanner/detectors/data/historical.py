"""Explicit, hash-bound historical profiles; no Catalog or Runner admission change.

The summary is a reviewed one-hop effect of one exact-version function, not a
general call graph. Local syntax candidates remain conditional on request data.
"""
from dataclasses import replace
import hashlib
import re

from src.ohscanner.contracts import DetectorRun, EvidenceObligation
from src.ohscanner.fixture import snapshot_digest
from .models import ExposureSinkModel
from .historical_models import HistoricalSourceModel, historical_model
from .sensitive_exposure import LocalFlow, SensitiveExposureDetector, Flow, BlockResult, walk


class HistoricalSensitiveExposureDetector(SensitiveExposureDetector):
    version = '0.4.0'

    def detect(self, context, units):
        p = self.model.profile
        if snapshot_digest(context.units) != context.request.snapshot_sha256:
            return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                'Historical model context does not match the request snapshot digest.',))
        by_path = {}
        for unit in context.units:
            if unit.path in by_path:
                return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                    'Historical model context contains duplicate source paths.',))
            if hashlib.sha256(unit.text.encode()).hexdigest() != unit.sha256:
                return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                    'Historical model context contains source bytes that do not match the declared hash.',))
            by_path[unit.path] = unit

        seen = set()
        for unit in units:
            if unit.path in seen:
                return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                    'Historical model input contains duplicate source paths.',))
            seen.add(unit.path)
            pinned = by_path.get(unit.path)
            if (pinned is None or unit.language != pinned.language or unit.sha256 != pinned.sha256
                    or unit.text != pinned.text
                    or hashlib.sha256(unit.text.encode()).hexdigest() != unit.sha256):
                return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                    'Historical model input is not an exact source unit from the request snapshot.',))

        if p['target_file'] not in seen:
            return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                'Historical model target source is outside the analyzed scope; absence is not a clean result.',))

        mismatches = []
        for row in p['required_files']:
            u = by_path.get(row['file'])
            if u is None or u.sha256 != row['sha256'] or hashlib.sha256(u.text.encode()).hexdigest() != row['sha256']:
                mismatches.append(row['file'])
        if mismatches:
            return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
                'Historical model evidence missing or mismatched: '+', '.join(mismatches),))
        return super().detect(context, units)

    def make_flow(self, unit):
        return HistoricalLocalFlow(unit, self.model)


class HistoricalLocalFlow(LocalFlow):
    """One exact record member, initialized output and success-edge summary.

    Called directly by research audits only when the public Runner withholds a
    partial file. Such observations must never be labelled production findings.
    """
    def __init__(self, unit, model):
        super().__init__(unit, model)
        self.p = model.profile
        self.sinks = {self.p['sink']: ExposureSinkModel(
            self.p['sink'], self.p['format_index'], self.p.get('default_private', False))}
        self.target = unit.path == self.p['target_file']
        definitions = []
        for node in walk(self.tree.root_node):
            if node.type != 'function_definition':
                continue
            d = node.child_by_field_name('declarator')
            fd = next((x for x in walk(d) if x.type == 'function_declarator'), None) if d else None
            if fd and self.text(fd.child_by_field_name('declarator')) == self.p['summary_function']:
                definitions.append(node)
        self.summary_available = self.target and len(definitions) == 1 and not definitions[0].has_error
        self.gaps.add('Historical profile '+self.p['model_version']+'; conditional request payload, runtime/build/readers unknown')

    @staticmethod
    def unwrap(node):
        while node is not None and node.type in ('parenthesized_expression', 'condition_clause') and len(node.named_children) == 1:
            node = node.named_children[0]
        return node

    def member(self, node):
        node = self.unwrap(node)
        if node is None or node.type != 'field_expression':
            return None
        obj = node.child_by_field_name('argument')
        if obj is None or obj.type != 'identifier':
            return None
        return re.sub(r'\s+', '', self.text(node))

    def expr(self, node, env, types):
        member = self.member(node)
        if member is not None:
            return env.get(member, ())
        if node is not None and node.type == 'subscript_expression':
            self.gaps.add('array element value is not whole string material')
            return ()
        if node is not None and node.type == 'call_expression':
            fn = self.text(node.child_by_field_name('function'))
            if fn in ('strlen', 'cJSON_Parse', self.p['summary_function'], self.p.get('allocator', 'SoftBusCalloc')):
                return ()  # status/length/JSON pointer is not the original string
        return super().expr(node, env, types)

    @staticmethod
    def merge(states):
        result = LocalFlow.merge(states)
        if result is None:
            return None
        live = [s for s in states if s is not None]
        for key in list(result.values):
            if key.startswith(('@allocated:', '@nonnull:')) and not all(s.values.get(key) == (True,) for s in live):
                result.values.pop(key, None)
        return result

    def declaration(self, node, state, fnname):
        names = super().declaration(node, state, fnname)
        typ = self.text(node.child_by_field_name('type'))
        for name in names:
            # Root rebinding invalidates member values from an outer declaration.
            for key in list(state.values):
                if key.startswith((name+'.', name+'->', '@allocated:'+name+'.', '@nonnull:'+name+'.')):
                    state.values.pop(key, None)
            if typ == self.p.get('output_type', 'MsgCryptInfo'):
                state.types[name] = typ
        return names

    @staticmethod
    def restore_scope(state, entry, declared):
        if state is not None:
            for name in declared:
                for key in list(state.values):
                    if key.startswith((name+'.', name+'->', '@allocated:'+name+'.', '@nonnull:'+name+'.')):
                        state.values.pop(key, None)
                for key, value in entry.values.items():
                    if key.startswith((name+'.', name+'->', '@allocated:'+name+'.', '@nonnull:'+name+'.')):
                        state.values[key] = value
        LocalFlow.restore_scope(state, entry, declared)

    def effects(self, node, state, fnname):
        if node is not None and node.type == 'assignment_expression':
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            key = self.member(left)
            if key:
                self.effects(right, state, fnname)
                state.values[key] = self.addstep(self.value(right, state), f'{node.start_point[0]+1} assign {key}')
                state.values.pop('@allocated:'+key, None)
                state.values.pop('@nonnull:'+key, None)
                calls = [x for x in walk(right) if x.type == 'call_expression'] if right else []
                if len(calls) == 1 and self.text(calls[0].child_by_field_name('function')) == self.p.get('allocator', 'SoftBusCalloc') and self.p.get('allocator', 'SoftBusCalloc') not in state.shadows:
                    state.values['@allocated:'+key] = (True,)
                return
        super().effects(node, state, fnname)

    def call(self, node, env, types, fnname):
        fn = self.text(node.child_by_field_name('function'))
        if fn in ('memcpy_s', 'strcpy_s', 'snprintf', 'snprintf_s'):
            self.gaps.add('historical buffer copy/format output status not summarized; output withheld')
            return
        if fn == self.p['sink']:
            if not self.target or fnname != self.p['source_function']:
                return
            if fn in self.shadows:
                self.gaps.add('historical log name locally shadowed')
                return
            args = node.child_by_field_name('arguments').named_children
            syntax = self.p.get('format_syntax', 'secure_c')
            if syntax not in ('secure_c', 'printf'):
                self.gaps.add('unreviewed log format syntax; candidate withheld')
                return
            if len(args) > self.p['format_index']:
                try:
                    fmt = self.literal(args[self.p['format_index']])
                except (ValueError, SyntaxError):
                    fmt = None
                if (fmt is not None and syntax == 'secure_c'
                        and re.search(r'%\{(?:public|private)\}', fmt)):
                    self.gaps.add('HiLog privacy syntax is not a reviewed secure-C SoftBusLog format')
                    return
            # Includes and hash-bound implementation provide model identity;
            # actual compile/link selection is still an evidence obligation.
        before = len(self.findings)
        super().call(node, env, types, fnname)
        for i in range(before, len(self.findings)):
            finding = self.findings[i]
            self.findings[i] = replace(finding, evidence_obligations=finding.evidence_obligations+(
                EvidenceObligation('historical_model', self.p['profile_id']+' / '+self.p['model_version']),
                EvidenceObligation('request_payload', 'Pinned source shows StartVerifySession sends FLAG_REQUEST and PackRequest adds SESSION_KEY; verify this exact path executes in the target product.'),
                EvidenceObligation('message_kind', 'The log runs before FLAG_REPLY dispatch and also sees replies; only the request JSON is evidenced to carry SESSION_KEY.'),
                EvidenceObligation('log_adapter', self.p['sink_semantics']),))

    def guard(self, condition, state):
        condition = self.unwrap(condition)
        if condition is None or condition.type != 'binary_expression':
            return None
        op = self.text(condition.child_by_field_name('operator'))
        if op not in ('==', '!='):
            return None
        left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
        if self.text(right) == 'NULL':
            key = self.member(left)
            if key and state.values.get('@allocated:'+key) == (True,):
                return ('nonnull', key, op == '!=')
        if self.text(right) != self.p['success_constant'] or left is None or left.type != 'call_expression':
            return None
        if self.text(left.child_by_field_name('function')) != self.p['summary_function']:
            return None
        if not self.summary_available:
            self.gaps.add('unique error-free reviewed one-hop summary unavailable')
            return None
        args = left.child_by_field_name('arguments').named_children
        if self.p['summary_parameter'] >= len(args):
            return None
        output = self.text(args[self.p['summary_parameter']])
        match = re.fullmatch(r'&\s*([A-Za-z_]\w*)', output)
        if not match:
            self.gaps.add('one-hop output alias unresolved')
            return None
        root = match.group(1)
        key = root+'.'+self.p['output_member']
        if state.types.get(root) != self.p.get('output_type', 'MsgCryptInfo') or state.values.get('@nonnull:'+key) != (True,):
            self.gaps.add('one-hop output initialization/allocation guard unresolved')
            return None
        return ('source', key, op == '==')

    def statement(self, node, state, fnname):
        if node.type == 'if_statement' and self.target and fnname == self.p['source_function']:
            guarded = self.guard(node.child_by_field_name('condition'), state)
            if guarded:
                kind, key, on_true = guarded
                results = []
                self.gaps.add('reviewed success-edge summary; branch feasibility is unproved and request/reply is not filtered at the log site')
                for truth, field in ((True, 'consequence'), (False, 'alternative')):
                    branch = state.clone()
                    if truth == on_true:
                        if kind == 'nonnull':
                            branch.values['@nonnull:'+key] = (True,)
                        else:
                            branch.values[key] = self.addstep((self.source(
                                self.p['summary_function']+' successful output '+key+' may carry Base64 session key', node),),
                                'reviewed one-hop parameter 2 -> MsgCryptInfo.out')
                    child = node.child_by_field_name(field)
                    results.append(self.statement(child, branch, fnname) if child else BlockResult(branch))
                return BlockResult(self.merge([r.fallthrough_state for r in results]),
                    tuple(e for r in results for e in r.exit_states))
        return super().statement(node, state, fnname)
