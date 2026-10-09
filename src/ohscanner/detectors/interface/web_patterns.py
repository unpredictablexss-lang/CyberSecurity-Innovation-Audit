"""Bounded lexical review patterns, not AST/taint or vulnerability verdicts."""
import re

_TOKEN = re.compile(r"(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|(?P<template>`(?:\\.|[^`\\])*`)|(?P<id>[A-Za-z_$][\w$]*)|(?P<other>.)")


def tokens(text):
    # Preserve original offsets. Strings are single tokens, never executable code.
    return [(m.group(), m.start(), m.lastgroup) for m in _TOKEN.finditer(text)
            if m.lastgroup not in ('space', 'comment')]


def calls(text):
    ts = tokens(text)
    for i in range(2, len(ts)-1):
        if ts[i-1][0] != '.' or ts[i][2] != 'id' or ts[i+1][0] != '(':
            continue
        depth, args = 1, []
        for token in ts[i+2:]:
            if token[0] == '(':
                depth += 1
            elif token[0] == ')':
                depth -= 1
            if depth == 0:
                yield ts[i][0], args, text.count('\n', 0, ts[i][1])+1
                break
            args.append(token)


def review_patterns(text, family):
    found = []
    for name, args, line in calls(text):
        values = [x[0] for x in args]
        first = []
        depth = 0
        for token in args:
            if token[0] == ',' and depth == 0:
                break
            first.append(token)
            depth += token[0] in ('(', '[', '{')
            depth -= token[0] in (')', ']', '}')
        rule = None
        if family == 'bridge' and name == 'runJavaScript' and first:
            if not (len(first) == 1 and first[0][2] == 'string'):
                rule = 'bridge.nonliteral-script'
        elif family == 'url' and name in ('startsWith', 'includes', 'indexOf'):
            if len(first) == 1 and first[0][2] == 'string':
                value = first[0][0][1:-1]
                if value.startswith(('https://', 'http://')) or re.fullmatch(r'[\w-]+(?:\.[\w-]+)+', value):
                    rule = 'url.raw-string-allowlist-review'
        elif family == 'disclosure':
            if name == 'fileAccess' and values == ['true']:
                rule = 'disclosure.local-file-access-enabled'
            elif name == 'mixedMode' and values == ['MixedMode', '.', 'All']:
                rule = 'disclosure.mixed-content-enabled'
        if rule:
            found.append((line, rule))
    return sorted(set(found))


class _WebPatternDetector:
    version = '0.1.0'
    supported_languages = ('js', 'ts', 'arkts')
    required_facts = ()
    family = ''

    def detect(self, context, units):
        from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
        eligible = [u for u in units if u.language in self.supported_languages]
        if not eligible:
            return DetectorRun(self.detector_id, self.version, 'blocked',
                               limitations=('No eligible JS/TS/ArkTS source units.',))
        findings = []
        for unit in eligible:
            if unit.parse_status == 'failed':
                continue
            for line, rule in review_patterns(unit.text, self.family):
                findings.append(DetectorFinding(file=unit.path, line=line, rule_id=rule,
                    message='Lexical review candidate: '+rule+'. API identity, reachable trust boundary and security impact remain unknown.',
                    evidence_type='pattern', evidence_obligations=(
                        EvidenceObligation('api_identity', 'Resolve receiver type and API version; method name alone is insufficient.'),
                        EvidenceObligation('attacker_control', 'Prove attacker-controlled source and reachable operation.'),
                        EvidenceObligation('guards_and_impact', 'Verify origin/URL guards, sanitization, permissions and sensitive data impact.'),
                        EvidenceObligation('frontend_coverage', 'Supply complete JS/ArkTS AST, bindings and required cross-language facts.'),
                    )))
        return DetectorRun(self.detector_id, self.version, 'completed' if any(u.parse_status != 'failed' for u in eligible) else 'blocked',
            analyzed_files=tuple(u.path for u in eligible if u.parse_status != 'failed'),
            findings=tuple(findings), limitations=(
                'Completed means lexical review only; semantic analysis is unavailable pending owner frontend extension.',
                'No AST, taint, CFG, redirect timing, bridge target mapping or proven disclosure.',
                'Not_run/partial source may yield pattern candidates; failed units are withheld.',
                'Regex literals, templates, Unicode/escaped identifiers and malformed source are not fully parsed.',
                'Zero findings is not a safety verdict. Synthetic fixtures are not independent holdout.',
            ))


class BridgeInjectionDetector(_WebPatternDetector):
    detector_id = 'ohscanner.interface.bridge'
    family = 'bridge'


class WebUrlDetector(_WebPatternDetector):
    detector_id = 'ohscanner.interface.url'
    family = 'url'


class SensitiveDisclosureDetector(_WebPatternDetector):
    detector_id = 'ohscanner.interface.disclosure'
    family = 'disclosure'


class WebEngineDetector:
    detector_id = 'ohscanner.interface.engine'
    version = '0.1.0'
    supported_languages = ('c', 'cpp')
    required_facts = ()

    def detect(self, context, units):
        from src.ohscanner.contracts import DetectorRun
        return DetectorRun(self.detector_id, self.version, 'blocked', limitations=(
            'No engine vulnerability algorithm implemented; application configuration cannot prove Chromium/ArkWeb memory corruption.',
            'Need pinned engine revision, downstream backports, native build/AST context and verified vulnerable/fixed/safe pairs.',
            'Engine C/C++ analysis must be coordinated with teammate A and owner; no competing generic bounds detector.',
        ))
