"""Strict first-party Detector adapter for an explicitly opted-in research rule."""
import json
from hashlib import sha1, sha256
from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .analysis import analyze_unit
from .exception_guard import analyze_exception_guard
from .receiver_guard import analyze_receiver_guard
from .runtime_exception import analyze_native_inline_exception_propagation
from .negative_double_length import analyze_negative_double_length
from .size_overflow import (analyze_size_overflow_unit, index_bounds_result,
                            length_narrowing_result)
from .model import (AnalysisBudget, RuntimeTypeModel, DETECTOR_ID, RULE_ID,
                    EXCEPTION_GUARD_RULE_ID, RECEIVER_TYPE_GUARD_RULE_ID,
                    SIZE_OVERFLOW_RULE_ID, LENGTH_NARROWING_RULE_ID,
                    INDEX_BOUNDS_RULE_ID, NATIVE_EXCEPTION_RULE_ID,
                    NEGATIVE_DOUBLE_LENGTH_RULE_ID,
                    RULE_VERSIONS, VERSION)


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
            # Preserve the detector's prior language-scoped behavior outside
            # the exact-source model; those files are recorded not_analyzed.
            return tuple(units)
        paths = {row[1] for row in (
            self.model.target_bindings + self.model.exception_guard_bindings
            + self.model.receiver_guard_bindings + self.model.size_overflow_bindings
            + self.model.length_narrowing_bindings + self.model.index_bounds_bindings
            + self.model.native_exception_bindings + self.model.species_read_width_bindings
            + tuple(row for row in self.model.negative_double_length_bindings
                    if row[1] == 'ecmascript/compiler/common_stubs.cpp'))}
        selected = tuple(unit for unit in units if unit.path in paths)
        # Preserve legacy language-scoped coverage when no modeled target is
        # present; helper-only scans must not silently become not_applicable.
        return selected or tuple(units)

    def __init__(self, model=None, budget=None):
        self.model = model or RuntimeTypeModel()
        self.budget = budget or AnalysisBudget()

    @staticmethod
    def _dependency_error(context, path, expected_blob, expected_sha256=None):
        dependency = next((item for item in context.units if item.path == path), None)
        blob_oids = context.shared_facts.get('source_blob_oid', {})
        ast = context.shared_facts.get('ast', {})
        if dependency is None:
            return 'creator dependency is outside the scanned source scope: ' + path
        raw = dependency.text.encode('utf-8')
        source_digest = sha256(raw).hexdigest()
        actual_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
        ast_entry = ast.get(path)
        if (dependency.language != 'cpp' or dependency.sha256 != source_digest
                or (expected_sha256 is not None and dependency.sha256 != expected_sha256)
                or actual_blob != expected_blob or blob_oids.get(path) != expected_blob):
            return 'creator dependency blob/SHA-256 does not match the version-bound model: ' + path
        if (not isinstance(ast_entry, dict) or ast_entry.get('parse_status') != 'complete'
                or dependency.parse_status != 'complete'):
            return 'creator dependency AST is incomplete: ' + path
        return ''

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
            size_binding = next((row for row in self.model.size_overflow_bindings
                                 if row[0] == context.request.commit and row[1] == unit.path), None)
            length_binding = next((row for row in self.model.length_narrowing_bindings
                                   if row[0] == context.request.commit and row[1] == unit.path), None)
            index_binding = next((row for row in self.model.index_bounds_bindings
                                  if row[0] == context.request.commit and row[1] == unit.path), None)
            native_binding = next((row for row in self.model.native_exception_bindings
                                   if row[0] == context.request.commit and row[1] == unit.path), None)
            negative_double_binding = next((row for row in self.model.negative_double_length_bindings
                                            if row[0] == context.request.commit and row[1] == unit.path
                                            and row[1] == 'ecmascript/compiler/common_stubs.cpp'), None)
            species_binding = next((row for row in self.model.species_read_width_bindings
                                    if row[0] == context.request.commit and row[1] == unit.path), None)
            if type_binding is not None:
                rule_bindings.append((RULE_ID, type_binding))
            if exception_binding is not None:
                rule_bindings.append((EXCEPTION_GUARD_RULE_ID, exception_binding))
            if receiver_binding is not None:
                rule_bindings.append((RECEIVER_TYPE_GUARD_RULE_ID, receiver_binding))
            if size_binding is not None:
                rule_bindings.append((SIZE_OVERFLOW_RULE_ID, size_binding))
            if length_binding is not None:
                rule_bindings.append((LENGTH_NARROWING_RULE_ID, length_binding))
            if index_binding is not None:
                rule_bindings.append((INDEX_BOUNDS_RULE_ID, index_binding))
            if native_binding is not None:
                rule_bindings.append((NATIVE_EXCEPTION_RULE_ID, native_binding))
            if negative_double_binding is not None:
                rule_bindings.append((NEGATIVE_DOUBLE_LENGTH_RULE_ID, negative_double_binding))
            if not rule_bindings:
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': exact upstream repository/commit/path is not in the reviewed model')
                continue
            dependency_error = (next((error for path, blob in self.model.source_dependencies
                                      if (error := self._dependency_error(context, path, blob))), '')
                                if type_binding is not None else '')
            if dependency_error:
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': ' + dependency_error)
                continue
            index_width_evidence = None
            if index_binding is not None:
                evidence_rows = tuple(row for row in self.model.index_bounds_dependencies
                                      if row[0] == context.request.commit)
                if evidence_rows:
                    evidence_errors = tuple(self._dependency_error(context, path, blob, expected_sha)
                                            for _, path, blob, expected_sha in evidence_rows)
                    if not any(evidence_errors):
                        index_width_evidence = '\n'.join(
                            next(item.text for item in context.units if item.path == path)
                            for _, path, _, _ in evidence_rows)
            raw = unit.text.encode('utf-8')
            git_blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
            if (context.request.provenance != 'git_object' or context.request.profile_id != 'light-ast'
                    or context.request.repository != self.model.source_repository):
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': pinned upstream Git provenance and light-ast profile are required')
                continue
            source_hash_mismatch = any(unit.sha256 != binding[3] for _, binding in rule_bindings)
            source_blob_mismatch = blob_oids.get(unit.path) not in {binding[2] for _, binding in rule_bindings}
            if unit.language not in self.supported_languages or source_hash_mismatch or source_blob_mismatch:
                outcomes.append((unit.path, 'not_analyzed'))
                limitations.append(unit.path + ': target source blob/SHA-256 does not match the version-bound model')
                continue
            species_read_width_bound = False
            if (species_binding is not None and type_binding is not None
                    and species_binding == type_binding
                    and unit.path == 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
                    and context.request.repository == self.model.source_repository
                    and context.request.commit == species_binding[0]
                    and unit.sha256 == species_binding[3]
                    and git_blob == species_binding[2]):
                evidence_rows = tuple(row for row in self.model.species_read_width_dependencies
                                      if row[0] == species_binding[0])
                # Require the complete, exact dependency set. Omissions or additions
                # invalidate this narrowly scoped summary and preserve generic unknowns.
                expected_paths = {
                    'ecmascript/compiler/new_object_stub_builder.cpp',
                    'ecmascript/base/typed_array_helper.cpp',
                    'ecmascript/stubs/runtime_stubs.cpp',
                    'ecmascript/js_typed_array.cpp',
                    'ecmascript/builtins/builtins_arraybuffer.cpp',
                    'ecmascript/compiler/builtins/builtins_arraybuffer_stub_builder.cpp',
                }
                if ({row[1] for row in evidence_rows} == expected_paths
                        and len(evidence_rows) == len(expected_paths)):
                    evidence_errors = tuple(self._dependency_error(context, path, blob, expected_sha)
                                            for _, path, blob, expected_sha in evidence_rows)
                    species_read_width_bound = not any(evidence_errors)
                if not species_read_width_bound:
                    limitations.append(unit.path + ': species read-width source evidence is incomplete or mismatched; retaining unknown helper effects')
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
                                          research_partial=unit.parse_status == 'partial',
                                          species_read_width_bound=species_read_width_bound)
                elif rule_id == SIZE_OVERFLOW_RULE_ID:
                    result = analyze_size_overflow_unit(unit, self.model.digest)
                elif rule_id == LENGTH_NARROWING_RULE_ID:
                    result = length_narrowing_result(unit, self.model.digest)
                elif rule_id == INDEX_BOUNDS_RULE_ID:
                    result = index_bounds_result(unit, self.model.digest, index_width_evidence)
                elif rule_id == NATIVE_EXCEPTION_RULE_ID:
                    result = analyze_native_inline_exception_propagation(unit)
                elif rule_id == NEGATIVE_DOUBLE_LENGTH_RULE_ID:
                    result = analyze_negative_double_length(context, self.model)
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
                    rule_version = RULE_VERSIONS.get(rule_id, 'unversioned-rule')
                    trace += ';rule_version=' + rule_version
                    if rule_id == NATIVE_EXCEPTION_RULE_ID:
                        obligations = (
                            ('exception_propagation_semantics', 'Verify the exact pending-exception condition and generated branch return semantics.'),
                            ('runtime_path_feasibility', 'Establish that Reflect.apply inlining can reach the unguarded helper under a realistic call.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    elif rule_id == NEGATIVE_DOUBLE_LENGTH_RULE_ID:
                        obligations = (
                            ('fast_path_representation', 'Verify the compiled runtime can deliver a negative integral TDouble to this constructor fast path; Math.ceil(-1.1) is only a source-supported route.'),
                            ('allocator_observation', 'Measure pointer-width allocation size, allocator success/failure, and stored TypedArray/ByteArray metadata in an isolated build.'),
                            ('indexed_access', 'Verify the exact compiled indexed-read and indexed-write dispatch before asserting any out-of-bounds consequence; the 32-bit later-read hypothesis is second-layer/source-review information only.'),
                            ('runtime_build_selection', 'Bind CommonStub/TypedHCR selection and architecture to an exact local runtime build.'),
                            ('security_impact', 'Establish a concrete runtime impact; this source-bound rule emits only a candidate.'),
                        )
                    elif rule_id == LENGTH_NARROWING_RULE_ID:
                        obligations = (
                            ('integer_conversion_semantics', 'Prove the ToIndex range, signed-to-unsigned conversion and allocation length semantics.'),
                            ('memory_safety_impact', 'Establish whether the narrowed length can cause an undersized allocation or out-of-bounds access.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    elif rule_id == INDEX_BOUNDS_RULE_ID:
                        obligations = (
                            ('index_width_and_bounds', 'Prove index width, overflow behavior and the exact DataView/Atomics bounds comparison.'),
                            ('memory_safety_impact', 'Establish a concrete out-of-bounds witness or retain the result as unknown.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
                        )
                    elif rule_id == SIZE_OVERFLOW_RULE_ID:
                        obligations = (
                            ('integer_range_semantics', 'Prove multiplication width and overflow behavior for both operands.'),
                            ('allocation_and_copy_flow', 'Connect the narrowed product to the exact allocation and copy bound.'),
                            ('product_binding', 'Bind the exact source revision and build configuration to an affected shipped product.'),
                            ('isolated_validation', 'Reproduce and revalidate the fix only in an authorized isolated environment.'),
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
                            'Candidate only: Reflect.apply native-inline result uses exception-sentinel comparison without a proven pending-exception exit. trace=' + trace
                            if rule_id == NATIVE_EXCEPTION_RULE_ID else
                            'Candidate only: exact C1 CommonStub and TypedHCR Float32Array double-length branches lack a nonnegative guard before the allocation helper; runtime behavior and memory impact are unverified. trace=' + trace
                            if rule_id == NEGATIVE_DOUBLE_LENGTH_RULE_ID else
                            'Candidate only: signed 32-bit ToIndex result narrows a TypedArray allocation length. trace=' + trace
                            if rule_id == LENGTH_NARROWING_RULE_ID else
                            'Candidate only: 32-bit DataView/Atomics index arithmetic reaches a local bounds check. trace=' + trace
                            if rule_id == INDEX_BOUNDS_RULE_ID else
                            'Candidate only: narrowed multiplication feeds allocation and copy bounds. trace=' + trace
                            if rule_id == SIZE_OVERFLOW_RULE_ID else
                            'Candidate only: allocation result header is read on a path where the allocation may leave a pending exception. trace=' + trace
                            if rule_id == EXCEPTION_GUARD_RULE_ID else
                            'Candidate only: TypedArray backing-buffer access is reachable without a dominating same-receiver runtime type guard. trace=' + trace
                            if rule_id == RECEIVER_TYPE_GUARD_RULE_ID else
                            'Candidate only: TypedArray destination and type-token origin differ under '
                            'the bounded type-changing creation model; generated graph path is symbolic. trace=' + trace
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
