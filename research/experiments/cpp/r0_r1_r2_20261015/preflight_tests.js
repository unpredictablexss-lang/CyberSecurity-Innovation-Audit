'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const {canonicalJson, hashInputBundle} = require('./canonical');
const validator = require('./preflight_validator');

const PACKAGE = __dirname;
const data = validator.loadPackage(PACKAGE);

test('canonical JSON ignores object key order but preserves array order', () => {
  assert.equal(
    canonicalJson({b: 2, a: [{y: 2, x: 1}, 3]}),
    canonicalJson({a: [{x: 1, y: 2}, 3], b: 2}),
  );
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test('input file enumeration order does not change input_bundle_sha256', () => {
  const base = {
    bundle_schema_version: 'ohscanner.a-exp-01-input-bundle-v1',
    serialization: 'ohscanner.canonical-json-v1',
    input_files: [
      {path: 'b.txt', role: 'source', sha256: 'b'.repeat(64)},
      {path: 'a.txt', role: 'source', sha256: 'a'.repeat(64)},
    ],
  };
  const reversed = {...base, input_files: [...base.input_files].reverse()};
  assert.equal(hashInputBundle(base).input_bundle_sha256, hashInputBundle(reversed).input_bundle_sha256);
});

test('canonical JSON is stable for Unicode and escaped newlines', () => {
  const text = '中文\nline\r\n\t🧪 café';
  assert.equal(canonicalJson({text}), canonicalJson({text}));
  assert.match(canonicalJson({text}), /\\n/);
  assert.equal(Buffer.from(canonicalJson({text}), 'utf8')[0], 0x7b);
});

test('number canonicalization normalizes -0 and rejects unsafe integers', () => {
  assert.equal(canonicalJson({n: -0}), canonicalJson({n: 0}));
  assert.throws(() => canonicalJson({n: Number.MAX_SAFE_INTEGER + 2}), /unsafe integer/);
  assert.throws(() => canonicalJson({n: NaN}), /NaN and Infinity/);
});

test('missing optional fields omit cleanly while null remains distinct and undefined fails', () => {
  assert.equal(canonicalJson({required: 'x'}), canonicalJson({required: 'x'}));
  assert.notEqual(canonicalJson({required: 'x'}), canonicalJson({required: 'x', optional: null}));
  assert.throws(() => canonicalJson({bad: undefined}), /undefined/);
});

test('fixed canonical hash vectors all match', () => {
  const result = validator.validateCanonicalTestVectors(path.join(PACKAGE, 'canonical_hash.test_vectors.json'));
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
  assert.ok(result.valid_count >= 6);
  assert.equal(result.invalid_count, 4);
});

test('statistical units report 45 review items, 45 occurrences and 44 unique candidates', () => {
  const result = validator.validateStatisticalUnits(data.sealed, data.statisticalContract);
  assert.deepEqual(result.errors, []);
  assert.equal(result.observed.review_items, 45);
  assert.equal(result.observed.scope_occurrences, 45);
  assert.equal(result.observed.unique_candidates, 44);
  assert.equal(result.observed.cross_scope_duplicate_candidates.length, 1);
  assert.equal(
    result.observed.cross_scope_duplicate_candidates[0].candidate_id,
    '1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7',
  );
  assert.deepEqual(
    result.observed.cross_scope_duplicate_candidates[0].occurrences.map((row) => row.review_scope).sort(),
    ['holdout', 'plausible_unproven'],
  );
});

test('same-scope duplicate occurrence is a conflict and is rejected', () => {
  const conflicting = JSON.parse(JSON.stringify(data.sealed));
  const source = conflicting.items[0];
  const replacement = {
    ...source,
    experiment_item_id: 'ffffffffffffffff',
    review_item_id: `${source.workbench_candidate_id}:plausible`,
    review_scope: source.review_scope,
  };
  conflicting.items[conflicting.items.length - 1] = replacement;
  const result = validator.validateStatisticalUnits(conflicting, data.statisticalContract);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes('duplicate candidate/scope occurrence')));
});

test('model binding contract is complete while unbound and blocks execution', () => {
  const result = validator.validateModelBinding(data.modelBinding);
  assert.deepEqual(result.errors, []);
  assert.equal(result.contract_complete, true);
  assert.equal(result.bound, false);
  assert.equal(result.execution_authorized, false);
});

test('a model binding missing an exact API endpoint is invalid when bound', () => {
  const bound = JSON.parse(JSON.stringify(data.modelBinding));
  Object.assign(bound, {
    status: 'bound_execution_authorized',
    model: {
      provider: 'fixture-provider',
      model_name: 'fixture-model',
      model_version: '2026-10-01',
      api_version: '2026-10-01',
      api_endpoint: 'https://example.invalid/v1',
      endpoint_kind: 'remote_http_api',
    },
    data_processing: {
      terms_reference: 'fixture-dpa',
      terms_version: '1',
      review_status: 'approved',
      data_classes: ['frozen_source_excerpt'],
      retention: '30d',
      training_use: 'disabled',
      region: 'test-region',
      truth_or_sealed_data_allowed: false,
    },
    pricing: {
      pricing_record_id: 'fixture-price',
      currency: 'USD',
      input_token_unit_price: 0.001,
      output_token_unit_price: 0.002,
      effective_from: '2026-10-15',
      source_reference: 'fixture-pricing',
      source_sha256: '1'.repeat(64),
      reviewed_by: 'fixture-reviewer',
    },
    approval: {
      authorizer_id: 'fixture-owner',
      authorizer_role: 'experiment_owner',
      authorization_reference: 'fixture-authorization',
      authorized_at: '2026-10-15T07:21:37.416Z',
      execution_authorized: true,
    },
    execution: {model_calls_executed: 0, model_results_generated: false, contract_only: false},
  });
  const valid = validator.validateModelBinding(bound);
  assert.equal(valid.valid, true);
  assert.equal(valid.execution_authorized, true);

  delete bound.model.api_endpoint;
  const missing = validator.validateModelBinding(bound);
  assert.equal(missing.valid, false);
  assert.ok(missing.errors.some((error) => error.includes('api_endpoint')));
});

test('R2 adapter authorization record is present but execution stays blocked', () => {
  const result = validator.validateToolAdapterAuthorization(data.authorization, data.toolContract);
  assert.deepEqual(result.errors, []);
  assert.equal(result.record_present, true);
  assert.equal(result.valid, true);
  assert.equal(result.execution_authorized, false);
  assert.deepEqual(data.authorization.tool_whitelist.sort(), [
    'detector_symbol_parse_summary',
    'evidence_obligation_query',
    'fixed_commit_git_history',
    'fixed_source_excerpt',
  ].sort());
});

test('missing or non-whitelisted R2 authorization fails closed', () => {
  const missing = validator.validateToolAdapterAuthorization({}, data.toolContract);
  assert.equal(missing.valid, false);
  assert.equal(missing.record_present, false);

  const altered = JSON.parse(JSON.stringify(data.authorization));
  altered.tool_whitelist = ['fixed_source_excerpt'];
  const mismatch = validator.validateToolAdapterAuthorization(altered, data.toolContract);
  assert.equal(mismatch.valid, false);
  assert.ok(mismatch.errors.some((error) => error.includes('exactly match')));
});

test('claim references accept only current-item catalog IDs', () => {
  const current = data.evidence.items[0];
  const result = validator.validateEvidenceReferences({
    experimentItemId: current.experiment_item_id,
    claims: [{claim_id: 'c1', evidence_refs: [current.evidence_id, current.fact_id]}],
    evidenceCatalog: data.evidence,
    persistedToolResults: [],
    deniedIdentifiers: validator.buildDeniedIdentifiers(data.sealed, data.truth),
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
  assert.equal(result.illegal_reference_count, 0);
});

test('forged, other-item and sealed/truth identifiers are rejected', () => {
  const current = data.evidence.items[0];
  const other = data.evidence.items[1];
  const denied = validator.buildDeniedIdentifiers(data.sealed, data.truth);
  const cases = [
    ['forged', 'f'.repeat(64)],
    ['other_item', other.evidence_id],
    ['sealed_candidate', data.sealed.items[0].workbench_candidate_id],
  ];
  for (const [name, reference] of cases) {
    const result = validator.validateEvidenceReferences({
      experimentItemId: current.experiment_item_id,
      claims: [{claim_id: name, evidence_refs: [reference]}],
      evidenceCatalog: data.evidence,
      persistedToolResults: [],
      deniedIdentifiers: denied,
    });
    assert.equal(result.valid, false, name);
    assert.equal(result.illegal_reference_count, 1, name);
  }
});

test('a persisted current-item tool result is a legal citation source', () => {
  const current = data.evidence.items[0];
  const evidenceId = 'a'.repeat(64);
  const result = validator.validateEvidenceReferences({
    experimentItemId: current.experiment_item_id,
    claims: [{claim_id: 'tool', evidence_refs: [evidenceId]}],
    evidenceCatalog: data.evidence,
    persistedToolResults: [{
      persistence_id: 'persistence-fixture-001',
      tool_call_id: 'tool-call-fixture-001',
      attempt_id: '1111111111111111',
      experiment_item_id: current.experiment_item_id,
      persisted: true,
      artifact_sha256: 'b'.repeat(64),
      evidence_ids: [evidenceId],
    }],
    deniedIdentifiers: validator.buildDeniedIdentifiers(data.sealed, data.truth),
  });
  assert.deepEqual(result.errors, []);
  assert.equal(result.checked[0].source, 'persisted_tool_result');
});

function toolAttempt(id, toolCallId, retryOf, status) {
  return {
    attempt_id: id,
    ordinal: retryOf ? 2 : 1,
    kind: 'tool',
    logical_id: 'logical-tool-001',
    retry_of_attempt_id: retryOf,
    run_id: 'run-fixture-001',
    experiment_item_id: data.evidence.items[0].experiment_item_id,
    repetition: 1,
    status,
    started_at: '2026-10-15T07:21:37.416Z',
    ended_at: '2026-10-15T07:21:38.416Z',
    wall_ms: 1000,
    usage: {input_tokens: null, output_tokens: null, total_tokens: null, provider_usage_raw: null},
    cost: {amount: 0, currency: null, pricing_record_id: null, computed_by: 'local_compute_not_costed'},
    tool_call_id: toolCallId,
    budget_effects: {
      tool_call: 'always',
      token_usage_if_any: 'not_applicable',
      wall_time: 'always',
      repetition: 'never',
      source_and_output_bytes: 'always',
    },
    prior_attempt_preserved: Boolean(retryOf),
    failure: status === 'ok' ? null : {failure_code: 'fixture_timeout'},
  };
}

function toolCall(id, attemptId) {
  return {
    tool_call_id: id,
    attempt_id: attemptId,
    experiment_item_id: data.evidence.items[0].experiment_item_id,
    tool_id: 'fixed_source_excerpt',
    tool_version: '1.0.0',
    request: {fixture: true},
    request_sha256: 'c'.repeat(64),
    status: id === 'tool-call-001' ? 'timed_out' : 'ok',
    evidence_ids: [],
    coverage: {},
    truncation: {},
    output_bytes: 0,
    elapsed_ms: 1000,
    failure: id === 'tool-call-001' ? {failure_code: 'fixture_timeout'} : null,
  };
}

function retryRun(overrides = {}) {
  return {
    schema_version: 'ohscanner.a-exp-01-run-record-v2',
    run_id: 'run-fixture-001',
    experiment_id: 'A-EXP-01',
    group: 'R2',
    repetition: 1,
    seed: 20261015,
    experiment_item_id: data.evidence.items[0].experiment_item_id,
    input_bundle_sha256: 'd'.repeat(64),
    input_bundle_serialization: 'ohscanner.canonical-json-v1',
    prompt_sha256: 'e'.repeat(64),
    status: 'completed',
    model: {},
    sampling: {},
    usage: {},
    cost: {},
    timing: {started_at: null, ended_at: null, wall_ms: 2000, active_ms: 2000},
    tool_calls: [toolCall('tool-call-001', '2222222222222222'), toolCall('tool-call-002', '3333333333333333')],
    attempt_log: [
      toolAttempt('2222222222222222', 'tool-call-001', null, 'timed_out'),
      toolAttempt('3333333333333333', 'tool-call-002', '2222222222222222', 'ok'),
    ],
    persisted_tool_results: [],
    output: {status: 'valid_json', payload: null, output_sha256: null},
    failure: {status: 'none', failure_code: null, message: null, retries: 1, timed_out: false, budget_exhausted: false},
    integrity: {
      ground_truth_visible: false,
      self_eval_used_as_truth: false,
      historical_records_modified: false,
      candidate_id_modified: false,
      confirmed_status_modified: false,
    },
    ...overrides,
  };
}

test('R2 retry has independent attempt IDs, preserves both attempts, and does not create a repetition', () => {
  const run = retryRun();
  const result = validator.validateRetryAccounting(run, data.budget);
  assert.deepEqual(result.errors, []);
  assert.equal(result.valid, true);
  assert.equal(result.retry_count, 1);
  assert.equal(result.attempt_count, 2);
  assert.equal(result.tool_call_count, 2);
  assert.deepEqual(run.attempt_log.map((attempt) => attempt.status), ['timed_out', 'ok']);
  assert.equal(run.attempt_log[0].repetition, 1);
  assert.equal(run.attempt_log[1].repetition, 1);
  assert.equal(run.attempt_log[1].retry_of_attempt_id, run.attempt_log[0].attempt_id);
  assert.equal(result.counts.retry_counts_as_new_repetition, false);
  assert.equal(result.counts.retry_counts_toward_tool_call, true);
  assert.equal(result.counts.retry_counts_toward_tokens_if_used, true);
  assert.equal(result.counts.retry_counts_toward_wall_time, true);
});

test('reused attempt IDs or a retry counted as a repetition fail validation', () => {
  const reused = retryRun();
  reused.attempt_log[1].attempt_id = reused.attempt_log[0].attempt_id;
  assert.equal(validator.validateRetryAccounting(reused, data.budget).valid, false);

  const repetition = retryRun();
  repetition.attempt_log[1].repetition = 2;
  const result = validator.validateRetryAccounting(repetition, data.budget);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes('repetition must match run')));
});

test('illegal claim references invalidate a completed run without mutating the payload', () => {
  const current = data.evidence.items[0];
  const payload = {
    schema_version: 'ohscanner.a-exp-01-model-output-v1',
    experiment_item_id: current.experiment_item_id,
    mechanism_label: 'unknown',
    product_assessment: 'unknown',
    evidence_gate_status: 'unknown',
    claims: [{claim_id: 'bad', kind: 'hypothesis', text: 'fixture', evidence_refs: ['f'.repeat(64)]}],
    missing_evidence: [],
    recommended_probes: [],
    limitations: [],
  };
  const run = retryRun({output: {status: 'valid_json', payload, output_sha256: '1'.repeat(64)}});
  const result = validator.validateRunRecord(run, {
    evidenceCatalog: data.evidence,
    sealed: data.sealed,
    truth: data.truth,
    budget: data.budget,
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((error) => error.includes('completed run cannot contain illegal evidence references')));
  assert.equal(payload.evidence_gate_status, 'unknown');
  assert.equal(payload.product_assessment, 'unknown');
});

test('ledger preserves its two historical records and contains no experiment run records', () => {
  const result = validator.validateLedger(path.join(PACKAGE, 'run_ledger.jsonl'));
  assert.equal(result.prefix_sha256, '31d53dda3a438c60451865204ba9f68d789e178553156b658c4a11c14547febc');
  assert.deepEqual(result.errors, []);
  assert.ok(result.record_count >= 2);
});

test('package structural preflight passes while execution remains blocked', () => {
  const result = validator.runPackagePreflight(PACKAGE);
  assert.deepEqual(result.errors, []);
  assert.equal(result.ok, true);
  assert.equal(result.execution_ready, false);
  assert.equal(result.decisions.overall, 'blocked');
  assert.equal(result.decisions.R0, 'preflight_ready_execution_not_authorized');
  assert.equal(result.decisions.R1, 'blocked');
  assert.equal(result.decisions.R2, 'blocked');
  assert.equal(result.boundaries.model_calls, 0);
  assert.equal(result.boundaries.r0_r1_r2_runs, 0);
});