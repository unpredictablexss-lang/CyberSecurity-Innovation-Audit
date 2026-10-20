"""Strict first-party Detector adapter for an explicitly opted-in research rule."""
import json
from hashlib import sha1
from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .analysis import analyze_unit, known_case_gap_ids_for_unit
from .exception_guard import analyze_exception_guard
from .receiver_guard import analyze_receiver_guard
from .runtime_exception import analyze_abrupt_exception_propagation
from .size_overflow import analyze_length_index_case_gaps
from .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID,
                    EXCEPTION_GUARD_RULE_ID, RECEIVER_TYPE_GUARD_RULE_ID, VERSION)

ABRUPT_EXCEPTION_RULE_ID = 'ark.runtime.reflect-apply-abrupt-exception-propagation'
NO_RULE_GAP_RULE_ID = 'ark.runtime.known-case-gap-no-security-rule'


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
        paths = {row[1] for row in (self.model.target_bindings + self.model.exception_guard_bindings
                                     + self.model.receiver_guard_bindings)}
        return tuple(unit for unit in units
                     if unit.path in paths or known_case_gap_ids_for_unit(unit))

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
            rule_bindings = []
            type_binding = next((row for row in self.model.target_bindings
                                 if row[0] == context.request.commit and row[1] == unit.path), None)
            exception_binding = next((row for row in self.model.exception_guard_bindings
                                      if row[0] == context.request.commit and row[1] == unit.path), None)
            receiver_binding = next((row for row in self.model.receiver_guard_bindings
                                     if row[0] == context.request.commit and row[1] == unit.path), None)
            if type_binding is not None:
                rule_bindings.append((RULE_ID, type_binding))
            if exception_binding is not None:
                rule_bindings.append((EXCEPTION_GUARD_RULE_ID, exception_binding))
            if receiver_binding is not None:
                rule_bindings.append((RECEIVER_TYPE_GUARD_RULE_ID, receiver_binding))
            gap_ids = known_case_gap_ids_for_unit(unit)
            if not rule_bindings and not gap_ids:
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
                    or blob_oids.get(unit.path) != (rule_bindings[0][1][2] if rule_bindings else git_blob)):
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
                elif rule_id == EXCEPTION_GUARD_RULE_ID:
                    result = analyze_exception_guard(
                        unit, creator_name=self.model.exception_guard_creator[0],
                        creator_arity=self.model.exception_guard_creator[1],
                        sink_name=self.model.exception_guard_sink[0],
                        sink_arity=self.model.exception_guard_sink[1],
                        sink_glue_arg=self.model.exception_guard_sink[2],
                        sink_object_arg=self.model.exception_guard_sink[3],
                        caller_names=self.model.exception_guard_callers,
                        caller_types=self.model.exception_guard_caller_types, budget=self.budget)
                else:
                    result = analyze_receiver_guard(unit, budget=self.budget)
                results.append((rule_id, result))
            if 'IAO7GO' in gap_ids:
                results.append((ABRUPT_EXCEPTION_RULE_ID,
                                analyze_abrupt_exception_propagation(unit)))
            if set(gap_ids) & {'I7W51D', 'IB8BCA'}:
                results.append((NO_RULE_GAP_RULE_ID, analyze_length_index_case_gaps(
                    unit.text, parse_complete=unit.parse_status == 'complete')))
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
                    if rule_id == ABRUPT_EXCEPTION_RULE_ID:
                        obligations = (
                            ('abrupt_completion_semantics', 'Verify Reflect.apply can complete abruptly and the generated result reaches Return without a dominating pending-exception exit.'),
                            ('control_flow_dominance', 'Review the complete generated lowering path and build-specific macros.'),
                            ('runtime_impact', 'Establish concrete runtime impact; this candidate is not a RangeError or boundary-fix claim.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate only in an authorized isolated environment.'),
                        )
                    elif rule_id == EXCEPTION_GUARD_RULE_ID:
                        obligations = (
                            ('exception_path_semantics', 'Verify the builder allocation path can leave a pending exception and the sensitive result use executes before the exception return.'),
                            ('runtime_impact', 'Establish whether the path causes a product crash, corruption or security impact under a reachable runtime condition.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    elif rule_id == RECEIVER_TYPE_GUARD_RULE_ID:
                        obligations = (
                            ('guard_semantics', 'Verify that the runtime type predicate accepts only objects valid for the backing-buffer accessor.'),
                            ('runtime_path_feasibility', 'Establish that attacker-reachable input can reach the unguarded sensitive operation.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('runtime_impact', 'Establish concrete crash, corruption or security impact under an isolated runtime test.'),
                        )
                    else:
                        obligations = (
                            ('model_applicability', 'Verify exact symbols, signatures, macros and model semantics in the product build.'),
                            ('runtime_path_feasibility', 'Prove the destination runtime type on the generated path and its relation to the supplied type token.'),
                            ('security_impact', 'Establish realistic entry, attacker control and concrete CIA impact.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    if unit.parse_status == 'partial':
                        obligations += (('parse_completeness_impact',
                                         'Partial translation-unit parsing may hide declarations, macros or effects; this finding is local candidate evidence only.'),)
                    findings.append(DetectorFinding(
                        file=unit.path, line=item.line, column=item.column, rule_id=rule_id,
                        message=(
                            'Candidate only: Reflect.apply abrupt completion may reach Return without a dominating pending-exception exit. trace=' + trace
                            if rule_id == ABRUPT_EXCEPTION_RULE_ID else
                            'Candidate only: allocation result header is read on a path where the allocation may leave a pending exception. trace=' + trace
                            if rule_id == EXCEPTION_GUARD_RULE_ID else
                            'Candidate only: TypedArray backing-buffer access is reachable without a dominating same-receiver runtime type guard. trace=' + trace
                            if rule_id == RECEIVER_TYPE_GUARD_RULE_ID else
                            'Candidate only: TypedArray destination and type-token origin differ under '
                            'the bounded type-changing creation model; generated graph path is symbolic. trace=' + trace
                        ),
                        evidence_type='syntax',
                        candidate_cwe=('CWE-755' if rule_id == ABRUPT_EXCEPTION_RULE_ID else
                                       'CWE-843' if rule_id == RULE_ID else None),
                        symbol=item.symbol, source_sha256=unit.sha256,
                        evidence_obligations=tuple(EvidenceObligation(kind, description) for kind, description in obligations),
                    ))
        incomplete = any(state != 'complete' for _, state in outcomes)
        return DetectorRun(self.detector_id, self.version, 'failed' if failed else 'blocked' if incomplete else 'completed',
                           tuple(inspected), tuple(findings), tuple(sorted(set(limitations + [
                               'Narrow local syntax/IR model; no whole-program type or exploitability proof.',
                           ]))), tuple(outcomes))
