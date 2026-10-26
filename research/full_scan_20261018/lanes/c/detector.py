"""Strict first-party Detector adapter. The catalog is intentionally unchanged."""
import json
from hashlib import sha1
from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .analysis import analyze_unit
from .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID, VERSION,
                    MODEL_REPOSITORY)

TARGET_SOURCE_PATH = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
FROZEN_MODEL_SHA256 = 'c8ad85c8eb55ee3d83d44266c259b36a2d38ea56997178ad7395073ab5b1eec4'


class ArkRuntimeTypeSafetyDetector:
    detector_id = DETECTOR_ID
    version = VERSION
    model_version = VERSION
    supported_languages = ('cpp',)
    required_facts = ('ast',)
    ast_scope = 'per_file'

    def __init__(self, model=None, budget=None):
        self.model = model or RuntimeTypeModel()
        self.budget = budget or AnalysisBudget()

    def detect(self, context, units):
        findings, outcomes, inspected, limitations = [], [], [], []
        if self.model.version != self.version:
            return self._blocked(units, 'model_version_mismatch')
        if self.model.digest != FROZEN_MODEL_SHA256:
            return self._blocked(units, 'model_digest_mismatch')
        # Matching API spellings in another revision do not satisfy the model.
        identity = context.request
        if identity.provenance != 'git_object':
            return self._blocked(units, 'model_source_provenance_mismatch')
        if identity.repository != MODEL_REPOSITORY:
            return self._blocked(units, 'model_repository_mismatch')
        source_bindings = self.model.bindings_for_commit(identity.commit)
        if not source_bindings:
            return self._blocked(units, 'model_commit_mismatch')
        if not any(path == TARGET_SOURCE_PATH for _, path, _ in source_bindings):
            return self._blocked(units, 'model_target_source_binding_missing')
        if identity.target_id != 'current-component:' + MODEL_REPOSITORY:
            return self._blocked(units, 'model_target_mismatch')
        if any(unit.path != TARGET_SOURCE_PATH for unit in units):
            return self._blocked(units, 'model_target_path_mismatch')
        all_units = {u.path: u for u in context.units}
        blob_oids = context.shared_facts.get('source_blob_oid', {})
        build_blob_oids = context.shared_facts.get('build_config_blob_oid', {})
        for commit, path, expected_oid in source_bindings:
            if path.endswith(('.gn', '.gni')):
                if commit != identity.commit:
                    return self._blocked(units, 'model_dependency_commit_mismatch')
                if build_blob_oids.get(path) != expected_oid:
                    return self._blocked(units, 'required_model_build_source_blob_missing_or_mismatched:' + path)
                continue
            unit = all_units.get(path)
            if commit != identity.commit:
                return self._blocked(units, 'model_dependency_commit_mismatch')
            if unit is None or unit.language != 'cpp':
                return self._blocked(units, 'required_model_source_missing:' + path)
            raw = unit.text.encode('utf-8')
            git_oid = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            if blob_oids.get(path) != expected_oid or git_oid != expected_oid:
                return self._blocked(units, 'required_model_source_blob_mismatch:' + path)
        failed = False
        bound = {u.path: u.sha256 for u in context.units}
        for unit in sorted(units, key=lambda u: u.path):
            if bound.get(unit.path) != unit.sha256:
                raise ValueError('detector_input_outside_bound_context')
            if unit.language not in self.supported_languages or unit.parse_status != 'complete':
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': production requires complete C++ AST')
                continue
            if unit.path not in context.shared_facts.get('ast', {}):
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': missing shared AST eligibility evidence')
                continue
            result = analyze_unit(unit, model=self.model, budget=self.budget)
            outcomes.append((unit.path, result.file_outcome))
            if result.file_outcome in ('complete', 'partial'):
                inspected.append(unit.path)
            failed |= result.status == 'failed'
            limitations.extend(unit.path + ': ' + x for x in result.limitations)
            for item in result.observations:
                if item.kind != 'candidate':
                    continue
                trace = json.dumps({'target': item.target_identity, 'token_origin': item.token_origin,
                                    'token_line': item.token_line, 'creation_line': item.creation_line,
                                    'generated_path': item.path, 'constraints': item.constraints,
                                    'model_sha256': result.model_digest,
                                    'function_region': [item.region_start_byte, item.region_end_byte],
                                    'unreviewed_effect_sites': item.effect_sites}, sort_keys=True)
                findings.append(DetectorFinding(
                    file=unit.path, line=item.line, column=item.column, rule_id=RULE_ID,
                    message='Candidate only: TypedArray destination and type-token origin differ under '
                            'the bounded species model; generated graph path is symbolic. trace=' + trace,
                    evidence_type='syntax', candidate_cwe='CWE-843',
                    symbol=item.symbol, source_sha256=unit.sha256,
                    evidence_obligations=tuple(EvidenceObligation(kind, description) for kind, description in (
                        ('model_applicability', 'Verify exact symbols, signatures, macros and model semantics in the product build.'),
                        ('runtime_path_feasibility', 'Prove generated path conditions and species return type in the real runtime.'),
                        ('security_impact', 'Establish realistic entry, attacker control and concrete CIA impact.'),
                        ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                    )),
                ))
        incomplete = any(state != 'complete' for _, state in outcomes)
        return DetectorRun(self.detector_id, self.version, 'failed' if failed else 'blocked' if incomplete else 'completed',
                           tuple(inspected), tuple(findings), tuple(sorted(set(limitations + [
                               'Narrow local syntax/IR model; no whole-program type or exploitability proof.',
                           ]))), tuple(outcomes))

    def _blocked(self, units, reason):
        rows = tuple(sorted((u.path, 'not_analyzed') for u in units))
        return DetectorRun(self.detector_id, self.version, 'blocked', file_outcomes=rows,
                           limitations=(reason, 'Exact source binding failed; model was not executed.'))
