"""Strict first-party Detector adapter for an explicitly opted-in research rule."""
import json
from hashlib import sha1
from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .analysis import analyze_unit
from .exception_guard import analyze_exception_guard
from .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID,
                    EXCEPTION_GUARD_RULE_ID, VERSION)


class ArkRuntimeTypeSafetyDetector:
    detector_id = DETECTOR_ID
    version = VERSION
    model_version = VERSION
    supported_languages = ('cpp',)
    # Owner runner applies this detector only to the exact upstream source path.
    # The adapter still validates repository, commit, Git blob and parser facts.
    required_facts = ()
    ast_scope = 'per_file'

    def select_applicable_units(self, context, units):
        if context.request.repository != self.model.source_repository:
            return ()
        paths = {row[1] for row in (self.model.target_bindings + self.model.exception_guard_bindings)}
        return tuple(unit for unit in units if unit.path in paths)

    def __init__(self, model=None, budget=None):
        self.model = model or RuntimeTypeModel()
        self.budget = budget or AnalysisBudget()

    def detect(self, context, units):
        findings, outcomes, inspected, limitations = [], [], [], []
        failed = False
        bound = {u.path: u.sha256 for u in context.units}
        ast = context.shared_facts.get('ast', {})
        blob_oids = context.shared_facts.get('source_blob_oid', {})
        for unit in sorted(units, key=lambda u: u.path):
            if bound.get(unit.path) != unit.sha256:
                raise ValueError('detector_input_outside_bound_context')
            blocked_snapshot = next((row for row in self.model.blocked_dependency_snapshots
                                     if row[0] == context.request.commit), None)
            if blocked_snapshot is not None:
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(
                    unit.path + ': model dependency snapshot is blocked pending semantic review '
                    + 'tree=' + blocked_snapshot[1]
                    + ' snapshot_sha256=' + blocked_snapshot[2]
                    + ' comparison_manifest_sha256=' + blocked_snapshot[3]
                    + ' model_sha256=' + self.model.digest
                    + ' (' + blocked_snapshot[4] + ')')
                continue
            rule_bindings = []
            type_binding = next((row for row in self.model.target_bindings
                                 if row[0] == context.request.commit and row[1] == unit.path), None)
            exception_binding = next((row for row in self.model.exception_guard_bindings
                                      if row[0] == context.request.commit and row[1] == unit.path), None)
            if type_binding is not None:
                rule_bindings.append((RULE_ID, type_binding))
            if exception_binding is not None:
                rule_bindings.append((EXCEPTION_GUARD_RULE_ID, exception_binding))
            if not rule_bindings:
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': exact upstream repository/commit/path is not in the reviewed model')
                continue
            raw = unit.text.encode('utf-8')
            git_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
            if (context.request.provenance != 'git_object' or context.request.profile_id != 'light-ast'
                    or context.request.repository != self.model.source_repository):
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': pinned upstream Git provenance and light-ast profile are required')
                continue
            if (unit.language not in self.supported_languages
                    or any(unit.sha256 != binding[3] or git_blob != binding[2]
                           for _, binding in rule_bindings)
                    or blob_oids.get(unit.path) != rule_bindings[0][1][2]):
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': target source blob/SHA-256 does not match the version-bound model')
                continue
            ast_entry = ast.get(unit.path)
            if (not isinstance(ast_entry, dict) or ast_entry.get('parse_status') != unit.parse_status
                    or unit.parse_status not in ('complete', 'partial')):
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': shared AST status is missing or inconsistent with the source unit')
                continue
            results = []
            for rule_id, _ in rule_bindings:
                if rule_id == RULE_ID:
                    result = analyze_unit(unit, model=self.model, budget=self.budget,
                                          research_partial=unit.parse_status == 'partial')
                else:
                    result = analyze_exception_guard(
                        unit, creator_name=self.model.exception_guard_creator[0],
                        creator_arity=self.model.exception_guard_creator[1],
                        sink_name=self.model.exception_guard_sink[0],
                        sink_arity=self.model.exception_guard_sink[1],
                        sink_glue_arg=self.model.exception_guard_sink[2],
                        sink_object_arg=self.model.exception_guard_sink[3],
                        caller_names=self.model.exception_guard_callers,
                        caller_types=self.model.exception_guard_caller_types, budget=self.budget)
                results.append((rule_id, result))
            file_outcome = ('complete' if all(result.file_outcome == 'complete' for _, result in results)
                            else 'partial' if any(result.file_outcome in ('complete', 'partial') for _, result in results)
                            else 'not_analyzed' if all(result.file_outcome == 'not_analyzed' for _, result in results)
                            else 'failed')
            outcomes.append((unit.path, file_outcome))
            if file_outcome in ('complete', 'partial'):
                inspected.append(unit.path)
            failed |= any(result.status == 'failed' for _, result in results)
            for rule_id, result in results:
                limitations.extend(unit.path + ': ' + x for x in result.limitations)
                for item in result.observations:
                    if item.kind != 'candidate':
                        continue
                    trace = json.dumps({'target': item.target_identity, 'token_origin': item.token_origin,
                                        'token_line': item.token_line, 'creation_line': item.creation_line,
                                        'generated_path': item.path, 'constraints': item.constraints,
                                        'model_sha256': result.model_digest or self.model.digest,
                                        'function_region': [item.region_start_byte, item.region_end_byte],
                                        'unreviewed_effect_sites': item.effect_sites}, sort_keys=True)
                    if rule_id == EXCEPTION_GUARD_RULE_ID:
                        obligations = (
                            ('exception_path_semantics', 'Verify the builder allocation path can leave a pending exception and the sensitive result use executes before the exception return.'),
                            ('runtime_impact', 'Establish whether the path causes a product crash, corruption or security impact under a reachable runtime condition.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    else:
                        obligations = (
                            ('model_applicability', 'Verify exact symbols, signatures, macros and model semantics in the product build.'),
                            ('runtime_path_feasibility', 'Prove generated path conditions and species return type in the real runtime.'),
                            ('security_impact', 'Establish realistic entry, attacker control and concrete CIA impact.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    if unit.parse_status == 'partial':
                        obligations += (('parse_completeness_impact',
                                         'Partial translation-unit parsing may hide declarations, macros or effects; this finding is local candidate evidence only.'),)
                    findings.append(DetectorFinding(
                        file=unit.path, line=item.line, column=item.column, rule_id=rule_id,
                        message=(
                            'Candidate only: allocation result header is read on a path where the allocation may leave a pending exception. trace=' + trace
                            if rule_id == EXCEPTION_GUARD_RULE_ID else
                            'Candidate only: TypedArray destination and type-token origin differ under '
                            'the bounded species model; generated graph path is symbolic. trace=' + trace
                        ),
                        evidence_type='syntax', candidate_cwe='CWE-843' if rule_id == RULE_ID else None,
                        symbol=item.symbol, source_sha256=unit.sha256,
                        evidence_obligations=tuple(EvidenceObligation(kind, description) for kind, description in obligations),
                    ))
        incomplete = any(state != 'complete' for _, state in outcomes)
        return DetectorRun(self.detector_id, self.version, 'failed' if failed else 'blocked' if incomplete else 'completed',
                           tuple(inspected), tuple(findings), tuple(sorted(set(limitations + [
                               'Narrow local syntax/IR model; no whole-program type or exploitability proof.',
                           ]))), tuple(outcomes))
