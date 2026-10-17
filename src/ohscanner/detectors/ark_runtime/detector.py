"""Strict first-party Detector adapter. The catalog is intentionally unchanged."""
import json
from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .analysis import analyze_unit
from .model import AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID, VERSION


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
                                    'model_sha256': result.model_digest}, sort_keys=True)
                findings.append(DetectorFinding(
                    file=unit.path, line=item.line, column=item.column, rule_id=RULE_ID,
                    message='Candidate only: TypedArray destination and type-token origin differ under '
                            'the bounded species model; generated graph path is symbolic. trace=' + trace,
                    evidence_type='syntax', candidate_cwe='CWE-843',
                    symbol=self.model.caller, source_sha256=unit.sha256,
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
