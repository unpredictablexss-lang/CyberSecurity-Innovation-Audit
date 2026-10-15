'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const {canonicalJson, sha256Utf8} = require('./canonical');
const validator = require('./preflight_validator');

const OUT = __dirname;
const ROOT = path.resolve(OUT, '../../../..');
const GENERATED_AT_UTC = '2026-10-15T07:21:37.416Z';
const PREFIX_SHA256 = '31d53dda3a438c60451865204ba9f68d789e178553156b658c4a11c14547febc';

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(OUT, name), 'utf8'));
}

function writeJson(name, value) {
  fs.writeFileSync(path.join(OUT, name), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeText(name, text) {
  const normalized = text.replace(/\r\n/g, '\n');
  fs.writeFileSync(path.join(OUT, name), normalized.endsWith('\n') ? normalized : `${normalized}\n`, 'utf8');
}

function shaFile(name) {
  return crypto.createHash('sha256').update(fs.readFileSync(path.join(OUT, name))).digest('hex');
}

function frozenRef(name) {
  return {path: name, sha256: shaFile(name)};
}

function gitValue(args) {
  return cp.execFileSync('git', args, {cwd: ROOT, encoding: 'utf8'}).trim();
}

const sealed = readJson('sealed_item_key.json');
const toolContract = readJson('tool_contract.json');
const budget = readJson('budget.json');

const occurrenceByCandidate = new Map();
for (const item of sealed.items) {
  if (!occurrenceByCandidate.has(item.workbench_candidate_id)) occurrenceByCandidate.set(item.workbench_candidate_id, []);
  occurrenceByCandidate.get(item.workbench_candidate_id).push({
    experiment_item_id: item.experiment_item_id,
    review_item_id: item.review_item_id,
    review_scope: item.review_scope,
  });
}
const duplicateCandidates = [...occurrenceByCandidate.entries()]
  .filter(([, occurrences]) => occurrences.length > 1)
  .map(([candidate_id, occurrences]) => ({candidate_id, occurrences}))
  .sort((a, b) => Buffer.compare(Buffer.from(a.candidate_id), Buffer.from(b.candidate_id)));

const statisticalContract = {
  schema_version: 'ohscanner.a-exp-01-statistical-unit-contract-v1',
  experiment_id: 'A-EXP-01',
  generated_at_utc: GENERATED_AT_UTC,
  model_visible: false,
  deletion_permitted: false,
  source: {path: 'sealed_item_key.json', sha256: shaFile('sealed_item_key.json')},
  units: {
    experiment_item_id: {
      definition: 'One immutable review occurrence identified by experiment_item_id; it is the planned run and primary aggregation unit.',
      primary_key: ['experiment_item_id'],
      count: 45,
    },
    scope_occurrence: {
      definition: 'One (workbench_candidate_id, review_scope) occurrence. The same candidate in two scopes is two scope occurrences.',
      primary_key: ['workbench_candidate_id', 'review_scope'],
      count: 45,
    },
    unique_candidate: {
      definition: 'One distinct workbench_candidate_id after deduplicating across every review scope.',
      primary_key: ['workbench_candidate_id'],
      count: 44,
    },
    planned_run: {
      definition: 'One (experiment_item_id, group, repetition) run. Three repetitions produce 135 planned runs per group and 405 total.',
      primary_key: ['experiment_item_id', 'group', 'repetition'],
      per_group_count: 135,
      total_count: 405,
    },
  },
  review_item_count: 45,
  scope_occurrence_count: 45,
  unique_candidate_count: 44,
  scope_counts: {plausible_unproven: 11, holdout: 34},
  cross_scope_duplicate_candidates: duplicateCandidates,
  reporting_rules: [
    'Always report 45 review items/scope occurrences and 44 unique workbench candidates together.',
    'Never describe 45 as the number of unique candidates or as 45 independent unique root causes.',
    'Do not delete or merge either occurrence of a cross-scope duplicate; preserve both review_item_id and experiment_item_id records.',
    'A cross-scope duplicate is permitted only when the two review_scope values differ; a duplicate within one scope is a conflict.',
    'Aggregate planned runs by experiment_item_id and disclose the candidate-level clustering caused by 44 unique candidates.',
    'Do not treat synthetic controls as independent holdout data.',
  ],
  cross_scope_overlap_limitation: 'One workbench candidate occurs in both plausible_unproven and holdout. Scope counts remain 11 and 34, but unique candidate count is 44 and independence must not be claimed at the unique-candidate level.',
};
writeJson('statistical_unit_contract.json', statisticalContract);

const modelBindingSchema = {
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  '$id': 'ohscanner.a-exp-01-model-binding-schema-v1',
  'type': 'object',
  'required': ['schema_version', 'experiment_id', 'binding_id', 'status', 'execution', 'model', 'data_processing', 'pricing', 'approval'],
  'properties': {
    schema_version: {const: 'ohscanner.a-exp-01-model-binding-v1'},
    experiment_id: {const: 'A-EXP-01'},
    binding_id: {type: 'string', minLength: 1},
    status: {enum: ['unbound_execution_blocked', 'bound_pending_execution_authorization', 'bound_execution_authorized']},
    execution: {
      type: 'object',
      required: ['model_calls_executed', 'model_results_generated', 'contract_only'],
      properties: {
        model_calls_executed: {type: 'integer', minimum: 0},
        model_results_generated: {type: 'boolean'},
        contract_only: {type: 'boolean'},
      },
      additionalProperties: false,
    },
    model: {
      type: 'object',
      required: ['provider', 'model_name', 'model_version', 'api_version', 'api_endpoint', 'endpoint_kind'],
      properties: {
        provider: {type: ['string', 'null'], minLength: 1},
        model_name: {type: ['string', 'null'], minLength: 1},
        model_version: {type: ['string', 'null'], minLength: 1},
        api_version: {type: ['string', 'null'], minLength: 1},
        api_endpoint: {type: ['string', 'null'], minLength: 1},
        endpoint_kind: {enum: ['remote_http_api', 'local_runtime', null]},
      },
      additionalProperties: false,
    },
    data_processing: {
      type: 'object',
      required: ['terms_reference', 'terms_version', 'review_status', 'data_classes', 'retention', 'training_use', 'region', 'truth_or_sealed_data_allowed'],
      properties: {
        terms_reference: {type: ['string', 'null']},
        terms_version: {type: ['string', 'null']},
        review_status: {enum: ['not_reviewed', 'approved', 'rejected', null]},
        data_classes: {type: 'array', items: {type: 'string'}},
        retention: {type: ['string', 'null']},
        training_use: {type: ['string', 'null']},
        region: {type: ['string', 'null']},
        truth_or_sealed_data_allowed: {type: ['boolean', null]},
      },
      additionalProperties: false,
    },
    pricing: {
      type: 'object',
      required: ['pricing_record_id', 'currency', 'input_token_unit_price', 'output_token_unit_price', 'effective_from', 'source_reference', 'source_sha256', 'reviewed_by'],
      properties: {
        pricing_record_id: {type: ['string', 'null']},
        currency: {type: ['string', 'null']},
        input_token_unit_price: {type: ['number', 'null'], minimum: 0},
        output_token_unit_price: {type: ['number', 'null'], minimum: 0},
        effective_from: {type: ['string', 'null']},
        source_reference: {type: ['string', 'null']},
        source_sha256: {type: ['string', 'null'], pattern: '^[a-f0-9]{64}$'},
        reviewed_by: {type: ['string', 'null']},
      },
      additionalProperties: false,
    },
    approval: {
      type: 'object',
      required: ['authorizer_id', 'authorizer_role', 'authorization_reference', 'authorized_at', 'execution_authorized'],
      properties: {
        authorizer_id: {type: ['string', 'null']},
        authorizer_role: {type: ['string', 'null']},
        authorization_reference: {type: 'string'},
        authorized_at: {type: ['string', 'null'], format: 'date-time'},
        execution_authorized: {type: 'boolean'},
      },
      additionalProperties: false,
    },
  },
  'allOf': [
    {
      if: {properties: {status: {enum: ['bound_pending_execution_authorization', 'bound_execution_authorized']}}},
      then: {
        required: ['model', 'data_processing', 'pricing', 'approval'],
        properties: {
          model: {
            required: ['provider', 'model_name', 'model_version', 'api_version', 'api_endpoint', 'endpoint_kind'],
            properties: {
              provider: {type: 'string', minLength: 1},
              model_name: {type: 'string', minLength: 1},
              model_version: {type: 'string', minLength: 1},
              api_version: {type: 'string', minLength: 1},
              api_endpoint: {type: 'string', minLength: 1},
            },
          },
          data_processing: {properties: {review_status: {const: 'approved'}, truth_or_sealed_data_allowed: {const: false}}},
          pricing: {
            required: ['pricing_record_id', 'currency', 'input_token_unit_price', 'output_token_unit_price', 'source_reference', 'source_sha256', 'reviewed_by'],
            properties: {source_sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'}},
          },
        },
      },
    },
    {
      if: {properties: {status: {const: 'bound_execution_authorized'}}},
      then: {properties: {approval: {required: ['authorizer_id', 'authorizer_role', 'authorized_at'], properties: {execution_authorized: {const: true}}}}},
    },
  ],
  additionalProperties: false,
};
writeJson('model_binding.schema.json', modelBindingSchema);
const toolAdapterAuthorizationSchema = {
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  '$id': 'ohscanner.a-exp-01-tool-adapter-authorization-schema-v1',
  type: 'object',
  required: ['schema_version', 'experiment_id', 'authorization_id', 'status', 'tool_adapter', 'authorizer', 'authorization_scope', 'tool_whitelist', 'read_only_boundary', 'execution'],
  properties: {
    schema_version: {const: 'ohscanner.a-exp-01-tool-adapter-authorization-v1'},
    experiment_id: {const: 'A-EXP-01'},
    authorization_id: {type: 'string', minLength: 1},
    status: {enum: ['recorded_execution_not_authorized', 'execution_authorized', 'revoked']},
    tool_adapter: {
      type: 'object',
      required: ['adapter_id', 'adapter_version', 'implementation_sha256'],
      properties: {
        adapter_id: {type: 'string', minLength: 1},
        adapter_version: {type: 'string', minLength: 1},
        implementation_sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'},
      },
      additionalProperties: false,
    },
    authorizer: {
      type: 'object',
      required: ['authorizer_id', 'authorizer_role', 'authorization_reference', 'authorized_at'],
      properties: {
        authorizer_id: {type: 'string', minLength: 1},
        authorizer_role: {type: 'string', minLength: 1},
        authorization_reference: {type: 'string', minLength: 1},
        authorized_at: {type: 'string', format: 'date-time'},
      },
      additionalProperties: false,
    },
    authorization_scope: {
      type: 'object',
      required: ['groups', 'experiment_item_scope', 'allowed_operations', 'max_calls_per_item', 'effective_at', 'expires_at', 'revocation_rule'],
      properties: {
        groups: {const: ['R2']},
        experiment_item_scope: {const: 'all_45_frozen_review_items'},
        allowed_operations: {type: 'array', minItems: 1, items: {type: 'string'}},
        max_calls_per_item: {const: 8},
        effective_at: {type: 'string', format: 'date-time'},
        expires_at: {type: 'string', format: 'date-time'},
        revocation_rule: {type: 'string', minLength: 1},
      },
      additionalProperties: false,
    },
    tool_whitelist: {
      type: 'array',
      minItems: 1,
      uniqueItems: true,
      items: {enum: ['fixed_source_excerpt', 'evidence_obligation_query', 'fixed_commit_git_history', 'detector_symbol_parse_summary']},
    },
    read_only_boundary: {
      type: 'object',
      required: ['mode', 'allowed_source', 'denied'],
      properties: {
        mode: {const: 'read_only_allowlist'},
        allowed_source: {type: 'string', minLength: 1},
        denied: {
          type: 'array',
          minItems: 6,
          items: {type: 'string'},
        },
      },
      additionalProperties: false,
    },
    execution: {
      type: 'object',
      required: ['r2_runs_executed', 'execution_authorized', 'preflight_only'],
      properties: {
        r2_runs_executed: {const: 0},
        execution_authorized: {type: 'boolean'},
        preflight_only: {type: 'boolean'},
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
};
writeJson('tool_adapter_authorization.schema.json', toolAdapterAuthorizationSchema);

const adapterImplementationSha = shaFile('tool_contract.json');
const toolAdapterAuthorization = {
  schema_version: 'ohscanner.a-exp-01-tool-adapter-authorization-v1',
  experiment_id: 'A-EXP-01',
  authorization_id: 'A-EXP-01-R2-ADAPTER-AUTH-20261015-01',
  status: 'recorded_execution_not_authorized',
  tool_adapter: {
    adapter_id: 'ohscanner.a-exp-01.read-only-tool-adapter',
    adapter_version: '1.0.0',
    implementation_sha256: adapterImplementationSha,
  },
  authorizer: {
    authorizer_id: 'requesting_user_via_A-EXP-01-PREFLIGHT-UNBLOCK',
    authorizer_role: 'experiment_owner',
    authorization_reference: 'User instruction A-EXP-01-PREFLIGHT-UNBLOCK authorizes contract/schema creation only and explicitly forbids running R0/R1/R2.',
    authorized_at: GENERATED_AT_UTC,
  },
  authorization_scope: {
    groups: ['R2'],
    experiment_item_scope: 'all_45_frozen_review_items',
    allowed_operations: [
      'read frozen local Git-object source excerpts',
      'query frozen EvidenceObligation definitions and statuses',
      'read bounded history for the pinned commit and allowed file',
      'read recorded Detector symbol/parse summaries',
    ],
    max_calls_per_item: 8,
    effective_at: GENERATED_AT_UTC,
    expires_at: '2026-10-16T07:21:37.416Z',
    revocation_rule: 'Any scope, tool version, implementation hash, whitelist, budget, or read-only boundary change invalidates this record and requires a new authorization.',
  },
  tool_whitelist: toolContract.tools.map((tool) => tool.tool_id),
  read_only_boundary: {
    mode: 'read_only_allowlist',
    allowed_source: 'local pinned Git objects and frozen report/evidence records only',
    denied: [
      'shell execution',
      'source execution',
      'network access',
      'file writes',
      'Git mutation',
      'database mutation',
      'historical report edits',
      'candidate/review/confirmed state edits',
    ],
  },
  execution: {
    r2_runs_executed: 0,
    execution_authorized: false,
    preflight_only: true,
  },
};
writeJson('tool_adapter_authorization.json', toolAdapterAuthorization);

const canonicalInputBundleSchema = {
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  '$id': 'ohscanner.a-exp-01-canonical-input-bundle-schema-v1',
  type: 'object',
  required: [
    'bundle_schema_version', 'serialization', 'experiment_id', 'experiment_item_id',
    'group', 'repetition', 'seed', 'prompt', 'candidate', 'evidence_catalog_scope',
    'contract_files', 'input_files',
  ],
  properties: {
    bundle_schema_version: {const: 'ohscanner.a-exp-01-input-bundle-v1'},
    serialization: {const: 'ohscanner.canonical-json-v1'},
    experiment_id: {const: 'A-EXP-01'},
    experiment_item_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
    group: {enum: ['R0', 'R1', 'R2']},
    repetition: {type: 'integer', minimum: 1, maximum: 3},
    seed: {type: 'integer', enum: [20261015, 20261016, 20261017]},
    prompt: {
      type: 'object',
      required: ['path', 'sha256'],
      properties: {path: {type: 'string', minLength: 1}, sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'}},
      additionalProperties: false,
    },
    candidate: {type: 'object'},
    evidence_catalog_scope: {type: 'array', minItems: 1, items: {type: 'object'}},
    contract_files: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['path', 'role', 'sha256'],
        properties: {path: {type: 'string', minLength: 1}, role: {type: 'string', minLength: 1}, sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'}},
        additionalProperties: false,
      },
    },
    input_files: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['path', 'role', 'sha256'],
        properties: {path: {type: 'string', minLength: 1}, role: {type: 'string', minLength: 1}, sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'}},
        additionalProperties: false,
      },
    },
    optional_limitations: {type: 'array', items: {type: 'string'}},
  },
  additionalProperties: false,
};
writeJson('canonical_input_bundle.schema.json', canonicalInputBundleSchema);

const validVectors = [];
const addValid = (name, value, normalize = false) => {
  const canonical = canonicalJson(value, {normalizeInputFiles: normalize});
  validVectors.push({
    name,
    normalize_input_files: normalize,
    value,
    expected_canonical_json: canonical,
    expected_sha256: sha256Utf8(canonical),
  });
};
addValid('object_key_order_is_irrelevant', {zeta: 1, alpha: 'A', 中文: '值', nested: {b: false, a: null}});
addValid('file_order_is_sorted_before_hashing', {
  bundle_schema_version: 'ohscanner.a-exp-01-input-bundle-v1',
  input_files: [
    {path: 'z/last.txt', role: 'source', sha256: '2'.repeat(64)},
    {path: 'a/first.txt', role: 'source', sha256: '1'.repeat(64)},
    {path: 'a/first.txt', role: 'prompt', sha256: '3'.repeat(64)},
  ],
}, true);
addValid('unicode_and_newlines_are_utf8_json', {
  text: '第一行\n第二行\r\n\tTab \u0001 🧪 café',
  composed: 'café',
  decomposed: 'café',
  separators: 'line\u2028paragraph\u2029end',
  bom_as_content: '\ufeffnot-a-file-bom',
});
addValid('numbers_use_ecmascript_json_number_form', {zero: -0, one: 1.0, exponent: 1e2, decimal: 0.1, negative: -2.5});
addValid('missing_optional_field_is_omitted', {required: 'present'});
addValid('explicit_null_is_distinct_from_missing', {required: 'present', optional_limitations: null});

const canonicalTestVectors = {
  schema_version: 'ohscanner.a-exp-01-canonical-hash-test-vectors-v1',
  serialization: 'ohscanner.canonical-json-v1',
  rules: {
    encoding: 'UTF-8 without BOM; SHA-256 is over canonical bytes with no prefix and no trailing newline.',
    object_order: 'Object keys are sorted by UTF-16 code unit order; array order is preserved except input_files, which is sorted by UTF-8 byte order of path, then role, then sha256.',
    unicode: 'Strings must contain Unicode scalar values only; JSON escaping is emitted by the ECMAScript JSON serializer; U+2028/U+2029 and controls are represented in canonical JSON form.',
    numbers: 'Only finite JSON numbers are accepted; -0 normalizes to 0; unsafe integers, NaN, Infinity, bigint and non-JSON numeric spellings are rejected before hashing.',
    newline: 'The canonical byte sequence has no trailing newline; newlines inside strings are escaped.',
    file_order: 'input_files is sorted deterministically before hashing and duplicate file records are rejected.',
    missing_fields: 'Required fields must exist; optional fields are omitted when absent; explicit null is distinct from omission; undefined is rejected.',
  },
  valid_vectors: validVectors,
  invalid_vectors: [
    {name: 'lone_surrogate_rejected', value: {text: '\ud800'}, expected_error_contains: 'lone high surrogate'},
    {name: 'unsafe_integer_rejected', value: {unsafe: Number.MAX_SAFE_INTEGER + 2}, expected_error_contains: 'unsafe integer is rejected'},
    {name: 'missing_input_file_field_rejected', normalize_input_files: true, value: {input_files: [{path: 'a'}]}, expected_error_contains: 'role'},
    {name: 'duplicate_input_file_rejected', normalize_input_files: true, value: {input_files: [{path: 'a', role: 'r', sha256: '1'.repeat(64)}, {path: 'a', role: 'r', sha256: '1'.repeat(64)}]}, expected_error_contains: 'duplicate file record'},
  ],
};
writeJson('canonical_hash.test_vectors.json', canonicalTestVectors);
const evidenceReferenceContract = {
  schema_version: 'ohscanner.a-exp-01-evidence-reference-contract-v1',
  experiment_id: 'A-EXP-01',
  executable_validator: 'preflight_validator.js#validateEvidenceReferences',
  reference_pattern: '^[a-f0-9]{64}$',
  allowed_sources: [
    {
      source: 'supplied_evidence_catalog',
      rule: 'The referenced evidence_id or fact_id must exist in evidence_catalog.json and its experiment_item_id must equal the current run experiment_item_id.',
    },
    {
      source: 'persisted_tool_result',
      rule: 'The referenced ID must be listed in this run persisted_tool_results, which must have persisted=true, a unique persistence_id, a valid artifact_sha256, the current experiment_item_id, and an independent attempt_id/tool_call_id.',
    },
  ],
  denied_sources: [
    'truth labels or truth manifest identifiers',
    'sealed_item_key identifiers',
    'diagnostic IDs',
    'another experiment item catalog entry',
    'another experiment item persisted tool result',
    'forged, malformed, absent, or merely plausible hex IDs',
  ],
  claim_rule: 'Every claim must have at least one evidence_refs entry; each entry is validated independently.',
  failure_policy: {
    completed_run: 'Any illegal reference invalidates the run and requires a failed run record; it cannot remain completed.',
    non_completed_run: 'The output must remain evidence_gate_status=unknown and product_assessment must not be reportable_vulnerability.',
    no_silent_repair: 'The validator never rewrites, substitutes, or removes a reference.',
  },
  dynamic_membership_note: 'JSON Schema can enforce shape and hex syntax only; this executable validator performs catalog, item-scope, persisted-result, and denylist membership checks.',
};
writeJson('evidence_reference_contract.json', evidenceReferenceContract);

const retryAccountingContract = {
  schema_version: 'ohscanner.a-exp-01-retry-accounting-contract-v1',
  experiment_id: 'A-EXP-01',
  scope: 'per_run',
  attempt_identity: {
    attempt_id: 'Globally unique 16-character lowercase hex ID for every provider, tool, or human attempt.',
    logical_id: 'Stable ID for the logical operation being attempted; every retry repeats the same logical_id with a new attempt_id.',
    retry_of_attempt_id: 'Null on the initial attempt; otherwise the exact prior attempt_id. Prior records are never overwritten.',
    required_preservation: ['initial failure', 'retry attempt', 'final result', 'all token/cost/wall observations'],
  },
  r2_budget: {
    retries_max: 1,
    retries_counted_as_new_repetition: false,
    retries_count_toward_tool_calls: true,
    retries_count_toward_token_usage_if_any: true,
    retries_count_toward_cost_if_any: true,
    retries_count_toward_wall_time: true,
    retries_count_toward_tool_output_and_source_bytes: true,
    retries_reset_run_budget: false,
    retries_reset_seed_or_input_bundle: false,
    model_provider_attempts_max: 2,
  },
  budget_effects_by_attempt_kind: {
    human_review: {tool_call: 'not_applicable', token_usage_if_any: 'not_applicable', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'not_applicable'},
    model_provider: {tool_call: 'not_applicable', token_usage_if_any: 'if_used', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'not_applicable'},
    tool: {tool_call: 'always', token_usage_if_any: 'not_applicable', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'always'},
  },
  repetition_rule: 'A retry stays inside the original (experiment_item_id, group, repetition, seed) run. Three repetitions remain three; retries do not create a fourth repetition or replace a failed repetition.',
  usage_rule: 'Token and cost are summed across every attempt. Missing provider usage is unknown, never estimated, and prevents a completed within-budget status.',
  ledger_rule: 'Attempt records and run_ledger records are append-only; failure.retries equals the number of retry_of_attempt_id values.',
  invalidation_rule: 'More than one R2 retry, a reused attempt_id, a missing prior attempt, a mutated prior attempt, or a retry counted as a repetition invalidates the run.',
};
writeJson('retry_accounting_contract.json', retryAccountingContract);

const modelBinding = {
  schema_version: 'ohscanner.a-exp-01-model-binding-v1',
  experiment_id: 'A-EXP-01',
  binding_id: 'A-EXP-01-MODEL-BINDING-PENDING-20261015',
  status: 'unbound_execution_blocked',
  execution: {
    model_calls_executed: 0,
    model_results_generated: false,
    contract_only: true,
  },
  model: {
    provider: null,
    model_name: null,
    model_version: null,
    api_version: null,
    api_endpoint: null,
    endpoint_kind: null,
  },
  data_processing: {
    terms_reference: null,
    terms_version: null,
    review_status: 'not_reviewed',
    data_classes: [],
    retention: null,
    training_use: null,
    region: null,
    truth_or_sealed_data_allowed: false,
  },
  pricing: {
    pricing_record_id: null,
    currency: null,
    input_token_unit_price: null,
    output_token_unit_price: null,
    effective_from: null,
    source_reference: null,
    source_sha256: null,
    reviewed_by: null,
  },
  approval: {
    authorizer_id: null,
    authorizer_role: null,
    authorization_reference: 'A-EXP-01-PREFLIGHT-UNBLOCK defines the contract only; no provider/model execution was authorized.',
    authorized_at: null,
    execution_authorized: false,
  },
  required_before_bound_status: [
    'exact provider/model_name/model_version/api_version/api_endpoint/endpoint_kind',
    'approved data-processing terms, data classes, retention, training use, region, and truth/sealed exclusion',
    'pricing record ID, currency, unit prices, effective date, source reference/hash, and reviewer',
    'authorizer identity/role/reference/time and explicit execution authorization',
  ],
  rule: 'An unbound or pending record validates as a contract but leaves R1/R2 blocked. A bound record must contain every exact value; null placeholders and silent substitutions are invalid.',
};
writeJson('model_binding.template.json', modelBinding);

toolContract.schema_version = 'ohscanner.a-exp-01-tool-contract-v2';
toolContract.authorization.authorization_record = 'tool_adapter_authorization.json';
toolContract.authorization.adapter_contract = 'tool_adapter_authorization.schema.json';
toolContract.authorization.execution_rule = 'R2 remains blocked unless the authorization record is structurally valid and execution.execution_authorized=true.';
toolContract.result_envelope.required = [
  'tool_call_id', 'attempt_id', 'experiment_item_id', 'tool_id', 'tool_version',
  'request', 'request_sha256', 'status', 'persisted', 'persistence_id',
  'artifact_sha256', 'evidence_ids', 'coverage', 'truncation', 'output_bytes', 'elapsed_ms',
];
toolContract.result_envelope.persistence_rule = 'A claim may cite an envelope evidence_id only after the result is persisted with a unique persistence_id, artifact_sha256, current experiment_item_id, and independent attempt_id.';
toolContract.result_envelope.citation_rule = 'Each claim reference must be a supplied-catalog evidence_id/fact_id for the current experiment_item_id or an evidence_id from a persisted tool result for that same item.';
toolContract.retry = {
  contract: 'retry_accounting_contract.json',
  max_retries_per_R2_run: 1,
  every_retry_has_new_attempt_id: true,
  prior_failure_and_final_result_preserved: true,
  retry_counts_toward_tool_calls_tokens_cost_wall_and_bytes: true,
  retry_counts_as_new_repetition: false,
};
writeJson('tool_contract.json', toolContract);

toolAdapterAuthorization.tool_adapter.implementation_sha256 = shaFile('tool_contract.json');
writeJson('tool_adapter_authorization.json', toolAdapterAuthorization);

budget.schema_version = 'ohscanner.a-exp-01-budget-v2';
budget.per_item.R1.retries_max = 0;
budget.per_item.R2.model_provider_attempts_max = 2;
budget.retry_accounting = {
  contract: 'retry_accounting_contract.json',
  scope: 'per_run',
  max_retries_per_R2_run: 1,
  retry_counts_toward_tool_calls: true,
  retry_counts_toward_tokens_if_used: true,
  retry_counts_toward_cost_if_used: true,
  retry_counts_toward_wall_time: true,
  retry_counts_toward_tool_output_and_source_bytes: true,
  retry_counts_as_new_repetition: false,
  retry_resets_budget_or_seed: false,
  prior_attempt_preserved: true,
  separate_attempt_id_required: true,
};
budget.totals.R2_max_model_provider_attempts = budget.totals.runs_per_group * 2;
budget.accounting = 'Count every logical operation attempt, including initial failures and retries. Tool retries count as tool calls; provider retries count as provider attempts and consume any tokens/cost they use; every attempt consumes wall time. Retries never create or replace a repetition. Missing usage remains unknown and cannot be silently estimated.';
writeJson('budget.json', budget);
const runSchema = readJson('run_record.schema.json');
runSchema.$id = 'ohscanner.a-exp-01-run-record-v2';
runSchema.properties.schema_version.const = 'ohscanner.a-exp-01-run-record-v2';
for (const field of ['input_bundle_serialization', 'attempt_log', 'persisted_tool_results']) {
  if (!runSchema.required.includes(field)) runSchema.required.push(field);
}
runSchema.properties.input_bundle_serialization = {const: 'ohscanner.canonical-json-v1'};
runSchema.properties.model.required = [
  'binding_id', 'provider', 'model_name', 'model_version', 'api_version',
  'endpoint_kind', 'api_endpoint', 'data_processing_record_sha256', 'pricing_record_id',
];
Object.assign(runSchema.properties.model.properties, {
  binding_id: {type: ['string', 'null']},
  endpoint_kind: {enum: ['remote_http_api', 'local_runtime', null]},
  api_endpoint: {type: ['string', 'null']},
  data_processing_record_sha256: {type: ['string', 'null'], pattern: '^[a-f0-9]{64}$'},
  pricing_record_id: {type: ['string', 'null']},
});
const toolCallSchema = runSchema.properties.tool_calls.items;
toolCallSchema.required = [...new Set([...toolCallSchema.required, 'attempt_id', 'experiment_item_id'])];
Object.assign(toolCallSchema.properties, {
  attempt_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
  experiment_item_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
});
runSchema.properties.attempt_log = {
  type: 'array',
  minItems: 1,
  items: {
    type: 'object',
    required: [
      'attempt_id', 'ordinal', 'kind', 'logical_id', 'retry_of_attempt_id',
      'run_id', 'experiment_item_id', 'repetition', 'status', 'started_at',
      'ended_at', 'wall_ms', 'usage', 'cost', 'tool_call_id',
      'budget_effects', 'prior_attempt_preserved', 'failure',
    ],
    properties: {
      attempt_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
      ordinal: {type: 'integer', minimum: 1},
      kind: {enum: ['human_review', 'model_provider', 'tool']},
      logical_id: {type: 'string', minLength: 1},
      retry_of_attempt_id: {type: ['string', 'null'], pattern: '^[a-f0-9]{16}$'},
      run_id: {type: 'string', minLength: 1},
      experiment_item_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
      repetition: {type: 'integer', minimum: 1, maximum: 3},
      status: {enum: ['ok', 'failed', 'timed_out', 'budget_exhausted', 'cancelled']},
      started_at: {type: ['string', 'null']},
      ended_at: {type: ['string', 'null']},
      wall_ms: {type: 'integer', minimum: 0},
      usage: {
        type: 'object',
        required: ['input_tokens', 'output_tokens', 'total_tokens', 'provider_usage_raw'],
        properties: {
          input_tokens: {type: ['integer', 'null'], minimum: 0},
          output_tokens: {type: ['integer', 'null'], minimum: 0},
          total_tokens: {type: ['integer', 'null'], minimum: 0},
          provider_usage_raw: {type: ['object', 'null']},
        },
        additionalProperties: false,
      },
      cost: {
        type: 'object',
        required: ['amount', 'currency', 'pricing_record_id', 'computed_by'],
        properties: {
          amount: {type: ['number', 'null'], minimum: 0},
          currency: {type: ['string', 'null']},
          pricing_record_id: {type: ['string', 'null']},
          computed_by: {enum: ['provider', 'pricing_record', 'local_compute_not_costed', 'unknown']},
        },
        additionalProperties: false,
      },
      tool_call_id: {type: ['string', 'null']},
      budget_effects: {
        type: 'object',
        required: ['tool_call', 'token_usage_if_any', 'wall_time', 'repetition', 'source_and_output_bytes'],
        properties: {
          tool_call: {enum: ['always', 'if_used', 'not_applicable']},
          token_usage_if_any: {enum: ['always', 'if_used', 'not_applicable']},
          wall_time: {enum: ['always', 'if_used', 'not_applicable']},
          repetition: {enum: ['always', 'if_used', 'not_applicable', 'never']},
          source_and_output_bytes: {enum: ['always', 'if_used', 'not_applicable']},
        },
        additionalProperties: false,
      },
      prior_attempt_preserved: {type: 'boolean'},
      failure: {type: ['object', 'null']},
    },
    additionalProperties: false,
  },
};
runSchema.properties.persisted_tool_results = {
  type: 'array',
  items: {
    type: 'object',
    required: ['persistence_id', 'tool_call_id', 'attempt_id', 'experiment_item_id', 'persisted', 'artifact_sha256', 'evidence_ids'],
    properties: {
      persistence_id: {type: 'string', minLength: 1},
      tool_call_id: {type: 'string', minLength: 1},
      attempt_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
      experiment_item_id: {type: 'string', pattern: '^[a-f0-9]{16}$'},
      persisted: {const: true},
      artifact_sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'},
      evidence_ids: {type: 'array', minItems: 1, uniqueItems: true, items: {type: 'string', pattern: '^[a-f0-9]{64}$'}},
    },
    additionalProperties: false,
  },
};
writeJson('run_record.schema.json', runSchema);

const outputSchema = readJson('model_output.schema.json');
outputSchema.properties.claims.items.properties.evidence_refs = {
  type: 'array',
  minItems: 1,
  uniqueItems: true,
  items: {type: 'string', pattern: '^[a-f0-9]{64}$'},
};
outputSchema.properties.claims.items.additionalProperties = false;
outputSchema.properties.claims.items.required = ['claim_id', 'kind', 'text', 'evidence_refs'];
outputSchema.properties.reference_validation = {
  type: 'object',
  required: ['validator', 'status'],
  properties: {
    validator: {const: 'preflight_validator.js#validateEvidenceReferences'},
    status: {enum: ['not_run', 'valid', 'invalid']},
    illegal_reference_count: {type: 'integer', minimum: 0},
    policy: {enum: ['not_applicable', 'run_failed', 'remains_unknown']},
  },
  additionalProperties: false,
};
writeJson('model_output.schema.json', outputSchema);

const preflightRecordSchema = {
  '$schema': 'https://json-schema.org/draft/2020-12/schema',
  '$id': 'ohscanner.a-exp-01-preflight-unblock-record-schema-v1',
  type: 'object',
  required: [
    'schema_version', 'record_type', 'record_id', 'experiment_id', 'task_id',
    'generated_at_utc', 'timezone', 'status', 'corrects_record_id', 'checkout',
    'resolutions', 'statistical_units', 'canonical_hash', 'reference_validation',
    'retry_accounting', 'execution_decision', 'group_decisions', 'boundaries',
  ],
  properties: {
    schema_version: {const: 'ohscanner.a-exp-01-preflight-unblock-record-v1'},
    record_type: {enum: ['preflight_unblock', 'preflight_unblock_correction']},
    record_id: {type: 'string', minLength: 1},
    experiment_id: {const: 'A-EXP-01'},
    task_id: {const: 'A-EXP-01-PREFLIGHT-UNBLOCK'},
    generated_at_utc: {type: 'string', format: 'date-time'},
    timezone: {const: 'Asia/Shanghai'},
    status: {enum: ['contract_validation_passed_execution_blocked', 'failed']},
    corrects_record_id: {type: 'string', minLength: 1},
    correction_reason: {type: 'string', minLength: 1},
    checkout: {type: 'object'},
    resolutions: {type: 'object'},
    statistical_units: {type: 'object'},
    canonical_hash: {type: 'object'},
    reference_validation: {type: 'object'},
    retry_accounting: {type: 'object'},
    execution_decision: {
      type: 'object',
      required: ['R0', 'R1', 'R2', 'model_calls', 'r0_r1_r2_runs', 'model_results_generated', 'precision_recall_computed', 'candidate_truth_review_modified'],
      properties: {
        R0: {enum: ['blocked', 'preflight_ready_execution_not_authorized']},
        R1: {enum: ['blocked', 'preflight_ready_execution_not_authorized']},
        R2: {enum: ['blocked', 'preflight_ready_execution_not_authorized']},
        model_calls: {const: 0},
        r0_r1_r2_runs: {const: 0},
        model_results_generated: {const: false},
        precision_recall_computed: {const: false},
        candidate_truth_review_modified: {const: false},
      },
      additionalProperties: false,
    },
    group_decisions: {type: 'object'},
    boundaries: {type: 'object'},
    artifact_manifest_sha256: {type: 'string', pattern: '^[a-f0-9]{64}$'},
    report_hashes: {type: 'object'},
  },
  additionalProperties: false,
};
writeJson('preflight_record.schema.json', preflightRecordSchema);
const statPlan = `# A-EXP-01 统计方法（冻结，未运行）

## 数据边界与统计口径
本包固定 **45 个 review item / 45 个 scope occurrence / 44 个唯一 workbench candidate**。
45 个 review item 由唯一 \`experiment_item_id\` 标识，是 planned run 和主要聚合单位。
scope occurrence 的键是 \`workbench_candidate_id + review_scope\`；唯一 candidate 的键是
\`workbench_candidate_id\`。因此同一 candidate 出现在两个 scope 时仍是 2 个 review item、
2 个 scope occurrence，但只贡献 1 个 unique candidate。

candidate \`1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7\`
分别出现在 \`plausible_unproven\` 和 \`holdout\`。两条记录、两个 \`experiment_item_id\`、
两个 \`review_item_id\` 和两个 scope 都原样保留；不删除、不合并、不改写。
同 scope 内重复 occurrence 是 conflict；跨 scope 重复是已披露的 overlap。
必须同时报告 45 review item 和 44 unique candidate，不能把 45 写成 44 个独立候选，
也不能宣称 unique-candidate 级独立性。

真值集来自 \`truth_set_manifest.json\`，其 \`eligible_for_metrics=false\`、
\`metrics=not_computed\`。当前 product-level truth 只有 safe/unrelated/unknown，且仍有产品入口、
触发、同步和 CIA unknown。本实验不计算 Precision/Recall、FPR/FNR、零误报/零漏报，
也不把 controlled mechanism label 当产品真值。synthetic controls 不是独立 holdout。

## 设计
- R0：OHScanner 固定事实包 + 同标准人工审查；3 次 repetition。
- R1：同一批 review item + 单轮 LLM review；3 次 repetition，temperature=0，
  seeds 20261015/20261016/20261017，tool_calls=0。
- R2：同一批 review item + 有界只读工具 Agent；3 次 repetition，同一 seeds。
- 每组 planned run = 45 × 3 = 135；三组合计 405。retry 留在同一 run/repetition 内，
  不增加 repetition 数，也不替换失败 repetition。
- 所有运行、失败、超时、超预算、unknown、retry 和全部 repetition 都保留，不选最佳一次。

## 主要预注册描述量
1. 合法引用率：有合法 fact_id/evidence_id 的 claims / 全部 claims；非法/缺失引用单列并使
   completed run 失败或保持 unknown。
2. 证据门完整度：六个门项的 met/partial/not_met/unknown 计数和比例。
3. 机制标签与冻结 controlled_mechanism_label 的一致性：只作 descriptive agreement。
4. unknown 保持率：产品级/机制级 unknown 是否保持 unknown，不被强行判 safe/miss。
5. 人工 active time、provider token、实际费用、wall、工具调用/失败/retry、输出字节。
6. 可复现性：同 \`experiment_item_id\` 三次 repetition 的标签、输出 hash、引用集合稳定性。

## 聚合与区间
先按 \`experiment_item_id\` 聚合三次 repetition（保留每次原始记录），再以 45 个 review item
为单位汇总；另披露 44 个 unique candidate 的聚类。比例给 Wilson 95% 区间；
均值/中位数给 bootstrap 95% 区间（10,000 次，seed=20261015）。失败运行按失败/unknown
计入分母，不删除；缺失 provider usage/cost 记 unknown，不估算。
`;
writeText('statistical_plan.md', statPlan);

const freezeReport = `# A-EXP-01 R0/R1/R2 实验冻结与执行前门禁报告

状态：\`frozen_pre_experiment\`；结构 preflight 通过，执行门仍为 \`blocked\`。
本包没有模型调用、R0/R1/R2 运行、实验结果或 Precision/Recall。

## 已冻结且未改写
- 数据集：45 个 review item（11 plausible_unproven + 34 holdout）/ 45 个 scope occurrence /
  44 个唯一 workbench candidate。跨 scope 重复 candidate 两条记录都保留。
- 目标身份：五个固定组件的 repository/commit/git_tree/scope manifest/plan SHA。
- Detector：\`ohscanner.cpp.shared_ptr_race\` / \`0.4.0\` /
  \`ohcpp-shared-ptr-race-candidate-001\` / \`light-ast\`。
- Prompt、candidate、truth、review、历史诊断 ID、报告字节和 review 记录没有重写。

## 执行前门禁
- \`model_binding.schema.json\` 与 \`model_binding.template.json\` 完整定义 provider、model、
  exact version、API version/endpoint、data-processing、pricing 和 approval；
  当前记录仍是 \`unbound_execution_blocked\`，所以 R1/R2 blocked。
- \`tool_adapter_authorization.schema.json\` 与 \`tool_adapter_authorization.json\` 记录
  adapter 版本/实现 hash、授权人、范围、4 项工具白名单和只读边界。
  当前 \`execution_authorized=false\`，所以 R2 blocked；缺记录或越界同样 fail closed。
- \`statistical_unit_contract.json\` 固定 45/45/44 口径和已知跨 scope overlap。
- \`canonical_input_bundle.schema.json\`、\`canonical.js\` 和固定 test vectors 定义
  \`input_bundle_sha256\` 的 canonical byte serialization。
- \`evidence_reference_contract.json\` 与 \`preflight_validator.js\` 对 claim 引用做
  catalog/item/persisted-tool-result/denylist 成员校验；非法引用使 completed run 失败，
  或让非 completed 输出保持 unknown。
- \`retry_accounting_contract.json\` 固定 retry 的独立 attempt ID、预算影响和 append-only 规则。

## 统计与预算
- 每组 45 × 3 = 135 planned run；同时报告 45 review item 和 44 unique candidate。
- R2 每 run 最多 8 次工具调用、64 KiB 输出、300 秒 wall、1 次 retry。
- retry 占工具调用、实际 token/费用、wall 和输出/源码字节；不占新 repetition；
  不重置预算/seed/input bundle；首次失败与最终结果都保留。
- 不计算 Precision/Recall，不把 synthetic controls 当独立 holdout。

## 可执行入口
- \`node preflight_validator.js --check\`
- \`node preflight_validator.js --require-ready\`（当前应 exit 1，因为执行未授权）
- \`node preflight_validator.js --validate-run <run.json>\`
- \`node preflight_validator.js --hash-bundle <bundle.json>\`
- \`node --test preflight_tests.js\`
- \`node verify_freeze.js\`
`;
writeText('FREEZE_REPORT.md', freezeReport);
const modelBindingCheck = validator.validateModelBinding(modelBinding);
const authorizationCheck = validator.validateToolAdapterAuthorization(toolAdapterAuthorization, toolContract);
const statisticalCheck = validator.validateStatisticalUnits(sealed, statisticalContract);
const canonicalCheck = validator.validateCanonicalTestVectors(path.join(OUT, 'canonical_hash.test_vectors.json'));
const schemaNames = [
  'model_binding.schema.json', 'tool_adapter_authorization.schema.json',
  'canonical_input_bundle.schema.json', 'evidence_reference_contract.json',
  'retry_accounting_contract.json', 'preflight_record.schema.json',
  'run_record.schema.json', 'model_output.schema.json',
];
const schemaParse = {};
for (const name of schemaNames) {
  readJson(name);
  schemaParse[name] = 'passed';
}
const structuralErrors = [
  ...modelBindingCheck.errors,
  ...authorizationCheck.errors,
  ...statisticalCheck.errors,
  ...canonicalCheck.errors,
];
if (structuralErrors.length) throw new Error(`structural preflight failed: ${structuralErrors.join('; ')}`);

const decisions = {
  R0: 'preflight_ready_execution_not_authorized',
  R1: 'blocked',
  R2: 'blocked',
  overall: 'blocked',
};
const gitStatus = cp.execFileSync('git', ['status', '--porcelain=v1'], {cwd: ROOT, encoding: 'utf8'});
const dirtyLines = gitStatus.split(/\r?\n/).filter((line) => line !== '');
const checkout = {
  repository: gitValue(['remote', 'get-url', 'origin']),
  branch: gitValue(['branch', '--show-current']),
  head: gitValue(['rev-parse', 'HEAD']),
  tree: gitValue(['rev-parse', 'HEAD^{tree}']),
  remote_tracking_ref: gitValue(['rev-parse', '--abbrev-ref', 'HEAD@{upstream}']),
  dirty: dirtyLines.length > 0,
  dirty_entry_count: dirtyLines.length,
  dirty_status_sha256: crypto.createHash('sha256').update(gitStatus, 'utf8').digest('hex'),
  observed_at_utc: GENERATED_AT_UTC,
};

const resolutions = {
  model_binding_contract: {
    status: 'resolved_contract_complete_execution_still_blocked',
    schema: 'model_binding.schema.json',
    record: 'model_binding.template.json',
    contract_complete: modelBindingCheck.contract_complete,
    exact_fields: ['provider', 'model_name', 'model_version', 'api_version', 'api_endpoint', 'endpoint_kind', 'data_processing', 'pricing', 'approval'],
    bound: modelBindingCheck.bound,
    execution_authorized: modelBindingCheck.execution_authorized,
    model_calls_executed: 0,
  },
  r2_tool_adapter_authorization: {
    status: 'resolved_record_present_execution_still_blocked',
    schema: 'tool_adapter_authorization.schema.json',
    record: 'tool_adapter_authorization.json',
    record_present: authorizationCheck.record_present,
    structurally_valid: authorizationCheck.valid,
    adapter_version: toolAdapterAuthorization.tool_adapter.adapter_version,
    authorizer_id: toolAdapterAuthorization.authorizer.authorizer_id,
    authorization_scope: toolAdapterAuthorization.authorization_scope,
    tool_whitelist: toolAdapterAuthorization.tool_whitelist,
    read_only_boundary: toolAdapterAuthorization.read_only_boundary,
    execution_authorized: authorizationCheck.execution_authorized,
    r2_runs_executed: 0,
    fail_closed_rule: 'Missing, invalid, expired, out-of-scope, non-whitelisted, or non-read-only authorization keeps R2 blocked.',
  },
  cross_scope_duplicate_candidate: {
    status: 'resolved_by_statistical_unit_contract_without_deletion',
    candidate_id: duplicateCandidates[0].candidate_id,
    review_items: 45,
    scope_occurrences: 45,
    unique_candidates: 44,
    occurrences: duplicateCandidates[0].occurrences,
    records_deleted: 0,
    review_or_scope_records_modified: false,
  },
  canonical_input_bundle_hash: {
    status: 'resolved',
    serialization: 'ohscanner.canonical-json-v1',
    schema: 'canonical_input_bundle.schema.json',
    implementation: 'canonical.js',
    test_vectors: 'canonical_hash.test_vectors.json',
    covers: ['key order', 'Unicode scalar values', 'numbers', 'newlines', 'input file order', 'missing fields versus null'],
  },
  fact_evidence_reference_validator: {
    status: 'resolved_executable_fail_closed_validator',
    contract: 'evidence_reference_contract.json',
    validator: 'preflight_validator.js#validateEvidenceReferences',
    allowed_sources: ['supplied evidence catalog for current experiment_item_id', 'persisted tool result for current experiment_item_id'],
    denied: ['truth/sealed/diagnostic identifiers', 'other item', 'forged ID'],
    invalid_reference_policy: 'completed run fails; otherwise output remains unknown and cannot be reportable',
  },
  r2_retry_accounting: {
    status: 'resolved',
    contract: 'retry_accounting_contract.json',
    retries_max_per_run: 1,
    separate_attempt_id_required: true,
    counts_toward_tool_call: true,
    counts_toward_tokens_if_used: true,
    counts_toward_cost_if_used: true,
    counts_toward_wall_time: true,
    counts_toward_tool_output_and_source_bytes: true,
    counts_as_new_repetition: false,
    preserves_initial_failure_and_final_result: true,
    overwrites_prior_log: false,
  },
};

const validationReport = {
  schema_version: 'ohscanner.a-exp-01-preflight-validation-report-v1',
  experiment_id: 'A-EXP-01',
  task_id: 'A-EXP-01-PREFLIGHT-UNBLOCK',
  generated_at_utc: GENERATED_AT_UTC,
  status: 'contract_validation_passed_execution_blocked',
  checkout,
  structural_validation: {
    status: 'passed',
    errors: [],
    schema_parse: schemaParse,
    model_binding_contract_complete: true,
    tool_adapter_authorization_record_present: true,
    canonical_test_vectors_passed: true,
    statistical_counts: {
      review_items: statisticalCheck.observed.review_items,
      scope_occurrences: statisticalCheck.observed.scope_occurrences,
      unique_candidates: statisticalCheck.observed.unique_candidates,
      scope_counts: statisticalCheck.observed.scope_counts,
      cross_scope_duplicate_candidates: statisticalCheck.observed.cross_scope_duplicate_candidates,
    },
  },
  decisions,
  execution_blockers: [
    'model binding contract is complete but no exact provider/model/version/endpoint/data-processing/pricing record is bound',
    'R2 adapter authorization record exists but execution_authorized=false',
    'user explicitly prohibited R0/R1/R2 execution and real model calls in this task',
  ],
  verification_commands: [
    'node preflight_validator.js --check',
    'node preflight_validator.js --require-ready',
    'node --test preflight_tests.js',
    'node verify_freeze.js',
  ],
  boundaries: {
    model_calls: 0,
    r0_r1_r2_runs: 0,
    model_results_generated: false,
    precision_recall_computed: false,
    candidate_truth_review_or_diagnostic_ids_modified: false,
    synthetic_controls_treated_as_independent_holdout: false,
    push_merge_or_ready: false,
  },
};
writeJson('preflight_validation_report.json', validationReport);

const decisionMarkdown = `# A-EXP-01 preflight blocked/ready 决策报告

生成时间：${GENERATED_AT_UTC}（Asia/Shanghai 记录见 run_ledger）。

## 总结

- 结构 preflight：**passed**。
- 执行决策：**blocked**。
- 模型调用：**0**；R0/R1/R2 运行：**0**；实验结果：**0**。
- Precision/Recall：**未计算**；candidate/truth/review/diagnostic ID：**未修改**。

| 组 | 决策 | 原因 |
|---|---|---|
| R0 | preflight ready，execution not authorized | 门禁结构通过；本任务明确禁止运行 R0 |
| R1 | blocked | binding 契约完整，但 exact model record 未绑定且 execution 未授权 |
| R2 | blocked | 除 R1 条件外，adapter 授权记录虽已存在，但 \`execution_authorized=false\` |

## 六项处理

1. 模型绑定：\`model_binding.schema.json\` 已定义 provider/model/version/API endpoint/
   data-processing/pricing/approval；模板保留 null 占位并保持 \`unbound_execution_blocked\`，
   不伪造真实 Provider。
2. R2 授权：\`tool_adapter_authorization.json\` 已记录 adapter 版本/实现 hash、授权人、
   R2-only 范围、4 项白名单和只读/拒绝边界；执行授权为 false，R2 继续 blocked。
3. 跨 scope 重复：保留两条 review/scope 记录，报告 **45 review items、45 scope occurrences、
   44 unique candidates**；同 scope 重复才判 conflict。
4. canonical hash：\`ohscanner.canonical-json-v1\` 处理键顺序、Unicode、数字、换行、
   input file 排序、缺失字段与 null；固定 vectors 由 \`canonical.js\` 验证。
5. 引用：\`preflight_validator.js\` 只接受当前 item 的 supplied catalog 或已持久化 tool result；
   truth/sealed/other item/forged ID 使 completed run 失败，否则保持 unknown。
6. retry：独立 attempt ID；计 tool call、实际 token/费用、wall、输出/源码字节；
   不计新 repetition；首次失败与最终结果 append-only 保留。

## 仍未满足的执行条件

- 选择并批准真实 model/provider/exact version/API endpoint、data-processing 与 pricing 记录。
- 由有权人员把 model binding 与 R2 adapter authorization 改为执行授权。
- 用户明确授权运行 R0/R1/R2。

在此之前 \`node preflight_validator.js --require-ready\` 必须 exit 1。
`;
writeText('PREFLIGHT_DECISION.md', decisionMarkdown);

const frozenFiles = {
  initial_candidate_set: frozenRef('initial_candidate_set.json'),
  evidence_catalog: frozenRef('evidence_catalog.json'),
  sealed_item_key: frozenRef('sealed_item_key.json'),
  prompt_r1: frozenRef('prompt_r1.md'),
  prompt_r2: frozenRef('prompt_r2.md'),
  tool_contract: frozenRef('tool_contract.json'),
  budget: frozenRef('budget.json'),
  human_review_form: frozenRef('human_review_form.md'),
  human_review_form_schema: frozenRef('human_review_form.schema.json'),
  model_output_schema: frozenRef('model_output.schema.json'),
  run_record_schema: frozenRef('run_record.schema.json'),
  model_binding_template: frozenRef('model_binding.template.json'),
  model_binding_schema: frozenRef('model_binding.schema.json'),
  tool_adapter_authorization: frozenRef('tool_adapter_authorization.json'),
  tool_adapter_authorization_schema: frozenRef('tool_adapter_authorization.schema.json'),
  statistical_plan: frozenRef('statistical_plan.md'),
  statistical_unit_contract: frozenRef('statistical_unit_contract.json'),
  canonical_input_bundle_schema: frozenRef('canonical_input_bundle.schema.json'),
  canonical_hash_test_vectors: frozenRef('canonical_hash.test_vectors.json'),
  evidence_reference_contract: frozenRef('evidence_reference_contract.json'),
  retry_accounting_contract: frozenRef('retry_accounting_contract.json'),
  preflight_record_schema: frozenRef('preflight_record.schema.json'),
};

const experimentManifest = readJson('experiment_manifest.json');
experimentManifest.schema_version = 'ohscanner.a-exp-01-freeze-manifest-v2';
experimentManifest.frozen_files = frozenFiles;
experimentManifest.statistical_units = {
  path: 'statistical_unit_contract.json',
  review_items: 45,
  scope_occurrences: 45,
  unique_candidates: 44,
  planned_runs_per_group: 135,
  cross_scope_duplicate_disclosed: true,
};
experimentManifest.input_bundle = {
  schema: 'canonical_input_bundle.schema.json',
  serialization: 'ohscanner.canonical-json-v1',
  implementation: 'canonical.js',
  hash_field: 'input_bundle_sha256',
  test_vectors: 'canonical_hash.test_vectors.json',
};
experimentManifest.evidence_reference_gate = {
  contract: 'evidence_reference_contract.json',
  executable_validator: 'preflight_validator.js#validateEvidenceReferences',
  invalid_policy: 'completed run fails or non-completed output remains unknown',
};
experimentManifest.retry_accounting = {
  contract: 'retry_accounting_contract.json',
  schema: 'run_record.schema.json',
  ledger: 'run_ledger.jsonl',
  append_only: true,
  r2_retries_max: 1,
  retry_counts_as_new_repetition: false,
};
experimentManifest.run_logging.schema = 'run_record.schema.json';
experimentManifest.execution_gate = {
  status: 'structural_preflight_passed_execution_blocked',
  structural_validation: 'passed',
  R0: decisions.R0,
  R1: decisions.R1,
  R2: decisions.R2,
  required: [
    'bound exact model/provider/version/API endpoint/data-processing/pricing record',
    'execution-authorized R2 tool adapter record',
    'explicit user authorization for R0/R1/R2 execution',
    'canonical input bundle hash and legal evidence reference validation',
    'append-only retry attempt accounting',
  ],
};
writeJson('experiment_manifest.json', experimentManifest);
const artifactFiles = [
  'experiment_manifest.json', 'initial_candidate_set.json', 'evidence_catalog.json',
  'sealed_item_key.json', 'prompt_r1.md', 'prompt_r2.md', 'tool_contract.json',
  'budget.json', 'human_review_form.md', 'human_review_form.schema.json',
  'model_output.schema.json', 'run_record.schema.json',
  'model_binding.template.json', 'model_binding.schema.json',
  'tool_adapter_authorization.json', 'tool_adapter_authorization.schema.json',
  'statistical_plan.md', 'statistical_unit_contract.json',
  'canonical_input_bundle.schema.json', 'canonical_hash.test_vectors.json',
  'evidence_reference_contract.json', 'retry_accounting_contract.json',
  'preflight_record.schema.json', 'preflight_validation_report.json',
  'PREFLIGHT_DECISION.md', 'FREEZE_REPORT.md',
  'canonical.js', 'preflight_validator.js', 'preflight_tests.js',
  'preflight_unblock.js', 'build_freeze.js', 'verify_freeze.js',
];
const artifactManifest = {
  schema_version: 'ohscanner.a-exp-01-artifact-manifest-v2',
  experiment_id: 'A-EXP-01',
  generated_date: '2026-10-15',
  hash_algorithm: 'sha256',
  files: Object.fromEntries(artifactFiles.map((name) => [name, shaFile(name)])),
  excluded_self: 'artifact_manifest.json',
  append_only_ledger: {
    path: 'run_ledger.jsonl',
    reason: 'The ledger is append-only and must not be frozen as a mutable whole-file hash.',
    initial_prefix_record_count: 2,
    initial_prefix_bytes: 16427,
    initial_prefix_sha256: PREFIX_SHA256,
    allowed_record_schemas: [
      'ohscanner.a-exp-01-preflight-record-v1',
      'ohscanner.a-exp-01-preflight-correction-v1',
      'ohscanner.a-exp-01-preflight-unblock-record-v1',
      'ohscanner.a-exp-01-run-record-v2',
    ],
    run_records_before_execution: 0,
  },
  historical_records_modified: false,
  candidate_truth_review_modified: false,
};
writeJson('artifact_manifest.json', artifactManifest);

const artifactManifestSha = shaFile('artifact_manifest.json');
const ledgerPath = path.join(OUT, 'run_ledger.jsonl');
const ledgerText = fs.readFileSync(ledgerPath, 'utf8');
const ledgerLines = ledgerText.split('\n').filter((line) => line !== '');
const prefix = ledgerLines.slice(0, 2).map((line) => `${line}\n`).join('');
if (sha256Utf8(prefix) !== PREFIX_SHA256 || ledgerLines.length < 2) {
  throw new Error('historical two-record ledger prefix is missing or modified; refusing append');
}

const unblockRecord = {
  schema_version: 'ohscanner.a-exp-01-preflight-unblock-record-v1',
  record_type: 'preflight_unblock',
  record_id: 'A-EXP-01-PREFLIGHT-UNBLOCK-20261015-01',
  experiment_id: 'A-EXP-01',
  task_id: 'A-EXP-01-PREFLIGHT-UNBLOCK',
  generated_at_utc: GENERATED_AT_UTC,
  timezone: 'Asia/Shanghai',
  status: 'contract_validation_passed_execution_blocked',
  corrects_record_id: 'A-EXP-01-PREFLIGHT-20261015',
  checkout,
  resolutions,
  statistical_units: {
    review_items: 45,
    scope_occurrences: 45,
    unique_candidates: 44,
    planned_runs_per_group: 135,
    planned_runs_total: 405,
    cross_scope_duplicate_candidates: duplicateCandidates,
    records_deleted: 0,
    review_scope_records_modified: false,
  },
  canonical_hash: {
    serialization: 'ohscanner.canonical-json-v1',
    schema: 'canonical_input_bundle.schema.json',
    implementation: 'canonical.js',
    test_vectors: 'canonical_hash.test_vectors.json',
    valid_vectors: canonicalCheck.valid_count,
    invalid_vectors: canonicalCheck.invalid_count,
    validation_status: 'passed',
  },
  reference_validation: {
    contract: 'evidence_reference_contract.json',
    executable_validator: 'preflight_validator.js#validateEvidenceReferences',
    allowed_sources: ['supplied evidence catalog scoped to current experiment_item_id', 'persisted tool result scoped to current experiment_item_id'],
    illegal_reference_policy: 'completed run fails; otherwise output remains unknown and cannot be reportable',
    validation_status: 'implemented_fail_closed',
  },
  retry_accounting: {
    contract: 'retry_accounting_contract.json',
    attempt_id_required: true,
    retries_max_per_R2_run: 1,
    counts_toward_tool_call: true,
    counts_toward_tokens_if_used: true,
    counts_toward_cost_if_used: true,
    counts_toward_wall_time: true,
    counts_toward_tool_output_and_source_bytes: true,
    counts_as_new_repetition: false,
    preserves_initial_failure_and_final_result: true,
    append_only: true,
  },
  execution_decision: {
    R0: decisions.R0,
    R1: decisions.R1,
    R2: decisions.R2,
    model_calls: 0,
    r0_r1_r2_runs: 0,
    model_results_generated: false,
    precision_recall_computed: false,
    candidate_truth_review_modified: false,
  },
  group_decisions: {
    R0: {preflight: 'ready', execution: 'not_authorized', reason: 'structural gate passed; task forbids running R0'},
    R1: {preflight: 'blocked', execution: 'not_authorized', reason: 'model binding contract complete but exact binding/execution authorization absent'},
    R2: {preflight: 'blocked', execution: 'not_authorized', reason: 'model binding absent and adapter execution_authorized=false'},
    overall: 'blocked',
  },
  boundaries: {
    model_calls: 0,
    r0_r1_r2_runs: 0,
    model_results_generated: false,
    precision_recall_computed: false,
    candidate_modified: false,
    truth_modified: false,
    historical_review_modified: false,
    diagnostic_id_modified: false,
    synthetic_controls_treated_as_independent_holdout: false,
    push_merge_or_ready: false,
  },
  artifact_manifest_sha256: artifactManifestSha,
  report_hashes: {
    'preflight_validation_report.json': shaFile('preflight_validation_report.json'),
    'PREFLIGHT_DECISION.md': shaFile('PREFLIGHT_DECISION.md'),
    'FREEZE_REPORT.md': shaFile('FREEZE_REPORT.md'),
  },
};
readJson('preflight_record.schema.json');
const recordJson = JSON.stringify(unblockRecord);
const existing = ledgerLines.find((line) => {
  try {
    return JSON.parse(line).record_id === unblockRecord.record_id;
  } catch {
    return false;
  }
});
if (existing) {
  if (existing !== recordJson) {
    const existingCorrections = ledgerLines.filter((line) => {
      try {
        return JSON.parse(line).record_type === 'preflight_unblock_correction';
      } catch {
        return false;
      }
    });
    if (existingCorrections.length > 0) throw new Error('preflight correction already exists with different content; append another versioned correction instead of rewriting');
    const correction = {
      ...unblockRecord,
      record_type: 'preflight_unblock_correction',
      record_id: 'A-EXP-01-PREFLIGHT-UNBLOCK-20261015-CORRECTION-01',
      corrects_record_id: unblockRecord.record_id,
      correction_reason: 'Corrects the stale artifact/report hashes after the executable retry-attempt linkage validator was fixed; the original record remains append-only preserved.',
    };
    fs.appendFileSync(ledgerPath, `${JSON.stringify(correction)}\n`, 'utf8');
  }
} else {
  if (ledgerLines.length !== 2) {
    throw new Error(`expected exactly two historical ledger records before append, found ${ledgerLines.length}; refusing append`);
  }
  fs.appendFileSync(ledgerPath, `${recordJson}\n`, 'utf8');
}

console.log(JSON.stringify({
  status: 'generated',
  artifact_manifest_sha256: artifactManifestSha,
  ledger_record_id: unblockRecord.record_id,
  decisions,
  model_calls: 0,
  runs: 0,
}, null, 2));
