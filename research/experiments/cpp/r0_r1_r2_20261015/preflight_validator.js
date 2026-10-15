'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {canonicalJson, hashInputBundle, sha256Utf8} = require('./canonical');

const PACKAGE_DIR = __dirname;
const HEX64 = /^[a-f0-9]{64}$/;
const HEX16 = /^[a-f0-9]{16}$/;
const RUN_SCHEMA = 'ohscanner.a-exp-01-run-record-v2';

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function isIsoDateTime(value) {
  return isNonEmptyString(value) && Number.isFinite(Date.parse(value));
}

function validateModelBinding(binding) {
  const errors = [];
  const requiredTop = [
    'schema_version', 'experiment_id', 'binding_id', 'status', 'execution',
    'model', 'data_processing', 'pricing', 'approval',
  ];
  for (const field of requiredTop) {
    if (!Object.prototype.hasOwnProperty.call(binding || {}, field)) errors.push(`missing binding field: ${field}`);
  }
  if (!binding || binding.schema_version !== 'ohscanner.a-exp-01-model-binding-v1') errors.push('invalid model binding schema_version');
  if (!binding || binding.experiment_id !== 'A-EXP-01') errors.push('invalid model binding experiment_id');
  const allowedStatuses = new Set([
    'unbound_execution_blocked',
    'bound_pending_execution_authorization',
    'bound_execution_authorized',
  ]);
  if (!allowedStatuses.has(binding && binding.status)) errors.push('invalid model binding status');

  const modelFields = ['provider', 'model_name', 'model_version', 'api_version', 'api_endpoint', 'endpoint_kind'];
  const processingFields = [
    'terms_reference', 'terms_version', 'review_status', 'data_classes', 'retention',
    'training_use', 'region', 'truth_or_sealed_data_allowed',
  ];
  const pricingFields = [
    'pricing_record_id', 'currency', 'input_token_unit_price', 'output_token_unit_price',
    'effective_from', 'source_reference', 'source_sha256', 'reviewed_by',
  ];
  const approvalFields = ['authorizer_id', 'authorizer_role', 'authorization_reference', 'authorized_at', 'execution_authorized'];
  for (const [name, fields] of [['model', modelFields], ['data_processing', processingFields], ['pricing', pricingFields], ['approval', approvalFields]]) {
    const section = binding && binding[name];
    if (!section || typeof section !== 'object' || Array.isArray(section)) {
      errors.push(`binding.${name} must be an object`);
      continue;
    }
    for (const field of fields) {
      if (!Object.prototype.hasOwnProperty.call(section, field)) errors.push(`missing binding.${name}.${field}`);
    }
  }
  if (!binding || !binding.execution || typeof binding.execution !== 'object') {
    errors.push('binding.execution must be an object');
  } else {
    for (const field of ['model_calls_executed', 'model_results_generated', 'contract_only']) {
      if (!Object.prototype.hasOwnProperty.call(binding.execution, field)) errors.push(`missing binding.execution.${field}`);
    }
    if (binding.execution.model_calls_executed !== 0) errors.push('binding.execution.model_calls_executed must remain 0 in preflight');
    if (binding.execution.model_results_generated !== false) errors.push('binding.execution.model_results_generated must remain false');
  }

  const bound = binding && (binding.status === 'bound_pending_execution_authorization' || binding.status === 'bound_execution_authorized');
  if (bound) {
    for (const field of modelFields) if (!isNonEmptyString(binding.model[field])) errors.push(`bound model.${field} must be non-empty`);
    for (const field of processingFields) {
      if (field === 'data_classes') {
        if (!Array.isArray(binding.data_processing[field]) || binding.data_processing[field].length === 0) errors.push('bound data_processing.data_classes must be non-empty');
      } else if (field === 'truth_or_sealed_data_allowed') {
        if (binding.data_processing[field] !== false) errors.push('truth/sealed data transmission must be false');
      } else if (!isNonEmptyString(binding.data_processing[field])) {
        errors.push(`bound data_processing.${field} must be non-empty`);
      }
    }
    if (binding.data_processing.review_status !== 'approved') errors.push('bound data processing review must be approved');
    for (const field of ['pricing_record_id', 'currency', 'source_reference', 'source_sha256', 'reviewed_by']) {
      if (!isNonEmptyString(binding.pricing[field])) errors.push(`bound pricing.${field} must be non-empty`);
    }
    if (typeof binding.pricing.input_token_unit_price !== 'number' || binding.pricing.input_token_unit_price < 0) errors.push('bound pricing.input_token_unit_price must be a non-negative number');
    if (typeof binding.pricing.output_token_unit_price !== 'number' || binding.pricing.output_token_unit_price < 0) errors.push('bound pricing.output_token_unit_price must be a non-negative number');
    if (!HEX64.test(binding.pricing.source_sha256 || '')) errors.push('bound pricing.source_sha256 must be lowercase SHA-256');
    for (const field of ['authorizer_id', 'authorizer_role', 'authorization_reference']) {
      if (!isNonEmptyString(binding.approval[field])) errors.push(`bound approval.${field} must be non-empty`);
    }
    if (!isIsoDateTime(binding.approval.authorized_at)) errors.push('bound approval.authorized_at must be ISO-8601');
  }
  const executionAuthorized = Boolean(binding && binding.approval && binding.approval.execution_authorized === true && binding.status === 'bound_execution_authorized');
  return {
    errors,
    valid: errors.length === 0,
    contract_complete: errors.length === 0,
    bound,
    execution_authorized: executionAuthorized,
  };
}

function validateToolAdapterAuthorization(authorization, toolContract) {
  const errors = [];
  const required = [
    'schema_version', 'experiment_id', 'authorization_id', 'status', 'tool_adapter',
    'authorizer', 'authorization_scope', 'tool_whitelist', 'read_only_boundary',
    'execution',
  ];
  for (const field of required) {
    if (!Object.prototype.hasOwnProperty.call(authorization || {}, field)) errors.push(`missing authorization field: ${field}`);
  }
  if (!authorization || authorization.schema_version !== 'ohscanner.a-exp-01-tool-adapter-authorization-v1') errors.push('invalid authorization schema_version');
  if (!authorization || authorization.experiment_id !== 'A-EXP-01') errors.push('invalid authorization experiment_id');
  const allowedStatuses = new Set([
    'recorded_execution_not_authorized',
    'execution_authorized',
    'revoked',
  ]);
  if (!allowedStatuses.has(authorization && authorization.status)) errors.push('invalid authorization status');

  const adapter = authorization && authorization.tool_adapter;
  if (!adapter || typeof adapter !== 'object') errors.push('authorization.tool_adapter must be an object');
  else {
    for (const field of ['adapter_id', 'adapter_version', 'implementation_sha256']) {
      if (!isNonEmptyString(adapter[field])) errors.push(`authorization.tool_adapter.${field} must be non-empty`);
    }
    if (adapter.implementation_sha256 && !HEX64.test(adapter.implementation_sha256)) errors.push('tool adapter implementation_sha256 must be SHA-256');
  }

  const authorizer = authorization && authorization.authorizer;
  if (!authorizer || typeof authorizer !== 'object') errors.push('authorization.authorizer must be an object');
  else {
    for (const field of ['authorizer_id', 'authorizer_role', 'authorization_reference', 'authorized_at']) {
      if (!isNonEmptyString(authorizer[field])) errors.push(`authorization.authorizer.${field} must be non-empty`);
    }
    if (authorizer.authorized_at && !isIsoDateTime(authorizer.authorized_at)) errors.push('authorization.authorizer.authorized_at must be ISO-8601');
  }

  const expectedTools = Array.isArray(toolContract && toolContract.tools) ? toolContract.tools.map((tool) => tool.tool_id).sort() : [];
  const whitelist = authorization && Array.isArray(authorization.tool_whitelist) ? [...authorization.tool_whitelist].sort() : null;
  if (!whitelist || JSON.stringify(whitelist) !== JSON.stringify(expectedTools)) {
    errors.push('authorization.tool_whitelist must exactly match the frozen tool contract');
  }

  const scope = authorization && authorization.authorization_scope;
  if (!scope || typeof scope !== 'object') errors.push('authorization.authorization_scope must be an object');
  else {
    if (!Array.isArray(scope.groups) || scope.groups.join(',') !== 'R2') errors.push('authorization scope must apply only to R2');
    if (scope.experiment_item_scope !== 'all_45_frozen_review_items') errors.push('authorization item scope must be all_45_frozen_review_items');
    if (scope.max_calls_per_item !== 8) errors.push('authorization max_calls_per_item must be 8');
    if (!Array.isArray(scope.allowed_operations) || scope.allowed_operations.length === 0) errors.push('authorization allowed_operations must be non-empty');
  }

  const boundary = authorization && authorization.read_only_boundary;
  if (!boundary || typeof boundary !== 'object') errors.push('authorization.read_only_boundary must be an object');
  else {
    if (boundary.mode !== 'read_only_allowlist') errors.push('authorization read-only mode mismatch');
    for (const denial of ['shell execution', 'source execution', 'network access', 'file writes', 'Git mutation', 'database mutation']) {
      if (!Array.isArray(boundary.denied) || !boundary.denied.includes(denial)) errors.push(`authorization read-only boundary must deny: ${denial}`);
    }
    if (!isNonEmptyString(boundary.allowed_source)) errors.push('authorization allowed_source must be non-empty');
  }

  const execution = authorization && authorization.execution;
  if (!execution || typeof execution !== 'object') errors.push('authorization.execution must be an object');
  else {
    if (execution.r2_runs_executed !== 0) errors.push('authorization.execution.r2_runs_executed must remain 0 in preflight');
    if (typeof execution.execution_authorized !== 'boolean') errors.push('authorization.execution.execution_authorized must be boolean');
  }

  const authorized = Boolean(authorization && authorization.status === 'execution_authorized' && authorization.execution && authorization.execution.execution_authorized === true);
  return {
    errors,
    valid: errors.length === 0,
    record_present: Boolean(authorization && authorization.authorization_id),
    execution_authorized: authorized,
  };
}
function utf8Compare(a, b) {
  return Buffer.compare(Buffer.from(String(a), 'utf8'), Buffer.from(String(b), 'utf8'));
}

function validateStatisticalUnits(sealed, contract) {
  const errors = [];
  const items = sealed && Array.isArray(sealed.items) ? sealed.items : [];
  const seenExperimentIds = new Set();
  const seenScopeOccurrences = new Set();
  const candidateCounts = new Map();
  const occurrenceByCandidate = new Map();

  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    for (const field of ['experiment_item_id', 'review_item_id', 'workbench_candidate_id', 'review_scope']) {
      if (!isNonEmptyString(item && item[field])) errors.push(`sealed.items[${index}].${field} must be non-empty`);
    }
    if (item && !HEX16.test(item.experiment_item_id)) errors.push(`sealed.items[${index}].experiment_item_id must be 16 lowercase hex characters`);
    if (item && !HEX64.test(item.workbench_candidate_id)) errors.push(`sealed.items[${index}].workbench_candidate_id must be lowercase SHA-256`);
    if (!item) continue;
    if (seenExperimentIds.has(item.experiment_item_id)) errors.push(`duplicate experiment_item_id: ${item.experiment_item_id}`);
    seenExperimentIds.add(item.experiment_item_id);
    const scopeKey = `${item.workbench_candidate_id}\u0000${item.review_scope}`;
    if (seenScopeOccurrences.has(scopeKey)) errors.push(`duplicate candidate/scope occurrence: ${item.workbench_candidate_id} in ${item.review_scope}`);
    seenScopeOccurrences.add(scopeKey);
    candidateCounts.set(item.workbench_candidate_id, (candidateCounts.get(item.workbench_candidate_id) || 0) + 1);
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
    .sort((a, b) => utf8Compare(a.candidate_id, b.candidate_id));

  const observed = {
    review_items: items.length,
    unique_experiment_items: seenExperimentIds.size,
    scope_occurrences: seenScopeOccurrences.size,
    unique_candidates: candidateCounts.size,
    cross_scope_duplicate_candidates: duplicateCandidates,
    scope_counts: items.reduce((accumulator, item) => {
      const key = item.review_scope || '<missing>';
      accumulator[key] = (accumulator[key] || 0) + 1;
      return accumulator;
    }, {}),
  };

  if (observed.review_items !== 45) errors.push(`review item count must be 45, got ${observed.review_items}`);
  if (observed.unique_experiment_items !== 45) errors.push(`unique experiment item count must be 45, got ${observed.unique_experiment_items}`);
  if (observed.scope_occurrences !== 45) errors.push(`scope occurrence count must be 45, got ${observed.scope_occurrences}`);
  if (observed.unique_candidates !== 44) errors.push(`unique candidate count must be 44, got ${observed.unique_candidates}`);
  if (observed.scope_counts.plausible_unproven !== 11) errors.push('plausible_unproven review item count must remain 11');
  if (observed.scope_counts.holdout !== 34) errors.push('holdout review item count must remain 34');

  if (!contract || contract.schema_version !== 'ohscanner.a-exp-01-statistical-unit-contract-v1') errors.push('invalid statistical unit contract schema_version');
  else {
    if (contract.review_item_count !== 45 || contract.scope_occurrence_count !== 45 || contract.unique_candidate_count !== 44) {
      errors.push('statistical unit contract counts must be 45 review items, 45 scope occurrences, 44 unique candidates');
    }
    const contractDuplicates = JSON.stringify(contract.cross_scope_duplicate_candidates || []);
    if (contractDuplicates !== JSON.stringify(duplicateCandidates)) errors.push('statistical unit contract duplicate candidates do not match sealed records');
    if (contract.model_visible !== false) errors.push('statistical unit contract must not be model-visible');
    if (contract.deletion_permitted !== false) errors.push('statistical unit contract must forbid deleting duplicate scope occurrences');
  }

  return {errors, valid: errors.length === 0, observed};
}

function buildDeniedIdentifiers(sealed, truth) {
  const denied = new Set();
  const addValue = (value) => {
    if (typeof value === 'string' && HEX64.test(value)) denied.add(value);
  };
  for (const item of (sealed && sealed.items) || []) {
    addValue(item.workbench_candidate_id);
    addValue(item.experiment_item_id);
    addValue(item.diagnostic_id);
  }
  const walk = (value) => {
    if (Array.isArray(value)) {
      for (const child of value) walk(child);
      return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === 'string' && /(^|_)(diagnostic_id|workbench_candidate_id|experiment_item_id)$/.test(key)) addValue(child);
      walk(child);
    }
  };
  walk(truth || {});
  return denied;
}

function validateEvidenceReferences({
  experimentItemId,
  claims,
  evidenceCatalog,
  persistedToolResults = [],
  deniedIdentifiers = new Set(),
}) {
  const errors = [];
  const catalogById = new Map();
  const catalogItems = evidenceCatalog && Array.isArray(evidenceCatalog.items) ? evidenceCatalog.items : [];
  for (const entry of catalogItems) {
    for (const field of ['evidence_id', 'fact_id']) {
      const id = entry && entry[field];
      if (!isNonEmptyString(id) || !HEX64.test(id)) {
        errors.push(`catalog entry has invalid ${field}`);
        continue;
      }
      if (catalogById.has(id)) errors.push(`duplicate catalog reference id: ${id}`);
      catalogById.set(id, entry);
    }
  }

  const persistedById = new Map();
  for (let index = 0; index < persistedToolResults.length; index += 1) {
    const result = persistedToolResults[index];
    if (!result || typeof result !== 'object') {
      errors.push(`persistedToolResults[${index}] must be an object`);
      continue;
    }
    if (result.persisted !== true) errors.push(`persistedToolResults[${index}] must have persisted=true`);
    if (!isNonEmptyString(result.persistence_id)) errors.push(`persistedToolResults[${index}].persistence_id must be non-empty`);
    if (!isNonEmptyString(result.tool_call_id)) errors.push(`persistedToolResults[${index}].tool_call_id must be non-empty`);
    if (!isNonEmptyString(result.attempt_id)) errors.push(`persistedToolResults[${index}].attempt_id must be non-empty`);
    if (!HEX64.test(result.artifact_sha256 || '')) errors.push(`persistedToolResults[${index}].artifact_sha256 must be SHA-256`);
    if (result.experiment_item_id !== experimentItemId) errors.push(`persistedToolResults[${index}] belongs to another experiment item`);
    if (!Array.isArray(result.evidence_ids) || result.evidence_ids.length === 0) errors.push(`persistedToolResults[${index}].evidence_ids must be non-empty`);
    for (const id of result.evidence_ids || []) {
      if (!HEX64.test(id)) errors.push(`persistedToolResults[${index}] has malformed evidence id`);
      else if (persistedById.has(id)) errors.push(`duplicate persisted evidence id: ${id}`);
      else persistedById.set(id, result);
    }
  }

  const claimList = Array.isArray(claims) ? claims : [];
  const checked = [];
  if (claimList.length === 0) errors.push('at least one claim is required for reference validation');
  for (let claimIndex = 0; claimIndex < claimList.length; claimIndex += 1) {
    const claim = claimList[claimIndex];
    const refs = claim && Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    if (refs.length === 0) errors.push(`claims[${claimIndex}].evidence_refs must be non-empty`);
    for (const reference of refs) {
      const row = {claim_index: claimIndex, claim_id: claim && claim.claim_id, reference, legal: false, source: null, errors: []};
      if (!isNonEmptyString(reference) || !HEX64.test(reference)) {
        row.errors.push('malformed_id');
        errors.push(`claims[${claimIndex}] has malformed evidence reference`);
      } else if (deniedIdentifiers.has(reference)) {
        row.errors.push('truth_sealed_or_nonreference_identifier');
        errors.push(`claims[${claimIndex}] references a truth/sealed/diagnostic identifier: ${reference}`);
      } else if (catalogById.has(reference)) {
        const entry = catalogById.get(reference);
        if (entry.experiment_item_id !== experimentItemId) {
          row.errors.push('other_experiment_item');
          errors.push(`claims[${claimIndex}] references another experiment item: ${reference}`);
        } else {
          row.legal = true;
          row.source = 'supplied_evidence_catalog';
        }
      } else if (persistedById.has(reference)) {
        const result = persistedById.get(reference);
        if (result.experiment_item_id !== experimentItemId) {
          row.errors.push('other_experiment_item_tool_result');
          errors.push(`claims[${claimIndex}] references another experiment item tool result: ${reference}`);
        } else {
          row.legal = true;
          row.source = 'persisted_tool_result';
        }
      } else {
        row.errors.push('not_in_supplied_catalog_or_persisted_tool_result');
        errors.push(`claims[${claimIndex}] has an unknown/forged evidence reference: ${reference}`);
      }
      checked.push(row);
    }
  }
  return {
    valid: errors.length === 0,
    errors,
    checked,
    legal_reference_count: checked.filter((row) => row.legal).length,
    illegal_reference_count: checked.filter((row) => !row.legal).length,
  };
}
function validateRetryAccounting(run, budget) {
  const errors = [];
  const attempts = run && Array.isArray(run.attempt_log) ? run.attempt_log : null;
  if (!attempts) {
    errors.push('attempt_log is required');
    return {valid: false, errors, retry_count: 0};
  }
  const toolCalls = run && Array.isArray(run.tool_calls) ? run.tool_calls : [];
  const seenAttemptIds = new Set();
  const seenToolAttemptIds = new Set();
  const seenToolCallIds = new Set();
  let retryCount = 0;
  const expectedBudgetEffects = {
    human_review: {tool_call: 'not_applicable', token_usage_if_any: 'not_applicable', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'not_applicable'},
    model_provider: {tool_call: 'not_applicable', token_usage_if_any: 'if_used', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'not_applicable'},
    tool: {tool_call: 'always', token_usage_if_any: 'not_applicable', wall_time: 'always', repetition: 'never', source_and_output_bytes: 'always'},
  };

  for (let index = 0; index < attempts.length; index += 1) {
    const attempt = attempts[index];
    const pointer = `attempt_log[${index}]`;
    if (!attempt || typeof attempt !== 'object') {
      errors.push(`${pointer} must be an object`);
      continue;
    }
    for (const field of ['attempt_id', 'kind', 'logical_id', 'run_id', 'experiment_item_id', 'repetition', 'status', 'wall_ms', 'budget_effects', 'prior_attempt_preserved']) {
      if (!Object.prototype.hasOwnProperty.call(attempt, field)) errors.push(`${pointer}.${field} is required`);
    }
    if (!isNonEmptyString(attempt.attempt_id) || !HEX16.test(attempt.attempt_id)) errors.push(`${pointer}.attempt_id must be 16 lowercase hex characters`);
    if (seenAttemptIds.has(attempt.attempt_id)) errors.push(`${pointer}.attempt_id must be globally unique: ${attempt.attempt_id}`);
    seenAttemptIds.add(attempt.attempt_id);
    if (attempt.run_id !== run.run_id) errors.push(`${pointer}.run_id must match run`);
    if (attempt.experiment_item_id !== run.experiment_item_id) errors.push(`${pointer}.experiment_item_id must match run`);
    if (attempt.repetition !== run.repetition) errors.push(`${pointer}.repetition must match run`);
    if (!expectedBudgetEffects[attempt.kind]) errors.push(`${pointer}.kind is invalid`);
    else {
      const expected = expectedBudgetEffects[attempt.kind];
      for (const [field, value] of Object.entries(expected)) {
        if (!attempt.budget_effects || attempt.budget_effects[field] !== value) {
          errors.push(`${pointer}.budget_effects.${field} must be ${value}`);
        }
      }
    }
    if (typeof attempt.wall_ms !== 'number' || attempt.wall_ms < 0) errors.push(`${pointer}.wall_ms must be a non-negative number`);
    if (attempt.retry_of_attempt_id !== null && attempt.retry_of_attempt_id !== undefined) {
      retryCount += 1;
      if (!isNonEmptyString(attempt.retry_of_attempt_id)) errors.push(`${pointer}.retry_of_attempt_id must be null or non-empty`);
      if (attempt.prior_attempt_preserved !== true) errors.push(`${pointer}.prior_attempt_preserved must be true for retries`);
      const prior = attempts.find((candidate) => candidate.attempt_id === attempt.retry_of_attempt_id);
      if (!prior) errors.push(`${pointer}.retry_of_attempt_id does not exist`);
      else {
        if (prior.kind !== attempt.kind) errors.push(`${pointer} retry kind differs from prior attempt`);
        if (prior.logical_id !== attempt.logical_id) errors.push(`${pointer} retry logical_id differs from prior attempt`);
        if (prior.attempt_id === attempt.attempt_id) errors.push(`${pointer} cannot retry itself`);
      }
    } else if (attempt.retry_of_attempt_id !== undefined && attempt.retry_of_attempt_id !== null) {
      errors.push(`${pointer}.retry_of_attempt_id must be null for an initial attempt`);
    }
    if (attempt.kind === 'tool') {
      if (!isNonEmptyString(attempt.tool_call_id)) errors.push(`${pointer}.tool_call_id is required for tool attempts`);
      if (seenToolCallIds.has(attempt.tool_call_id)) errors.push(`${pointer}.tool_call_id must be unique`);
      seenToolCallIds.add(attempt.tool_call_id);
      seenToolAttemptIds.add(attempt.attempt_id);
    }
  }

  const declaredRetries = run.failure && Number.isInteger(run.failure.retries) ? run.failure.retries : null;
  if (declaredRetries !== retryCount) errors.push(`failure.retries (${declaredRetries}) must equal retry attempt count (${retryCount})`);
  const r2MaxRetries = budget && budget.per_item && budget.per_item.R2 ? budget.per_item.R2.retries_max : null;
  if (run.group === 'R2' && typeof r2MaxRetries === 'number' && retryCount > r2MaxRetries) {
    errors.push(`R2 retry count ${retryCount} exceeds max ${r2MaxRetries}`);
  }
  if (run.group === 'R2') {
    const toolMax = budget && budget.per_item && budget.per_item.R2 ? budget.per_item.R2.tool_calls_max : null;
    if (typeof toolMax === 'number' && toolCalls.length > toolMax) errors.push(`R2 tool call count ${toolCalls.length} exceeds ${toolMax}`);
    const toolAttempts = attempts.filter((attempt) => attempt.kind === 'tool').length;
    if (toolAttempts !== toolCalls.length) errors.push('every tool call must have exactly one independent tool attempt record');
    for (const call of toolCalls) {
      if (!isNonEmptyString(call.attempt_id)) errors.push(`tool_calls ${call.tool_call_id} is missing attempt_id`);
      else if (!seenToolAttemptIds.has(call.attempt_id)) errors.push(`tool_calls ${call.tool_call_id} attempt_id is not in attempt_log`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    retry_count: retryCount,
    attempt_count: attempts.length,
    tool_call_count: toolCalls.length,
    counts: {
      retry_counts_toward_tool_call: true,
      retry_counts_toward_tokens_if_used: true,
      retry_counts_toward_wall_time: true,
      retry_counts_as_new_repetition: false,
      prior_attempt_preserved: true,
    },
  };
}

function validateRunRecord(run, {evidenceCatalog, sealed, truth, budget}) {
  const errors = [];
  const required = [
    'schema_version', 'run_id', 'experiment_id', 'group', 'repetition', 'seed',
    'experiment_item_id', 'input_bundle_sha256', 'input_bundle_serialization',
    'prompt_sha256', 'status', 'model', 'sampling', 'usage', 'cost', 'timing',
    'tool_calls', 'attempt_log', 'persisted_tool_results', 'output', 'failure', 'integrity',
  ];
  for (const field of required) if (!Object.prototype.hasOwnProperty.call(run || {}, field)) errors.push(`run record missing ${field}`);
  if (run && run.schema_version !== RUN_SCHEMA) errors.push(`run record schema_version must be ${RUN_SCHEMA}`);
  if (run && run.experiment_id !== 'A-EXP-01') errors.push('run experiment_id must be A-EXP-01');
  if (run && !['R0', 'R1', 'R2'].includes(run.group)) errors.push('invalid run group');
  if (run && !HEX64.test(run.input_bundle_sha256 || '')) errors.push('input_bundle_sha256 must be SHA-256');
  if (run && run.input_bundle_serialization !== 'ohscanner.canonical-json-v1') errors.push('input_bundle_serialization must be ohscanner.canonical-json-v1');
  if (run && !HEX16.test(run.experiment_item_id || '')) errors.push('experiment_item_id must be 16 lowercase hex characters');

  const retry = run && budget ? validateRetryAccounting(run, budget) : {valid: false, errors: ['missing run or budget']};
  errors.push(...retry.errors);

  const payload = run && run.output ? run.output.payload : null;
  const referenceValidation = payload ? validateEvidenceReferences({
    experimentItemId: run.experiment_item_id,
    claims: payload.claims,
    evidenceCatalog,
    persistedToolResults: run.persisted_tool_results || [],
    deniedIdentifiers: buildDeniedIdentifiers(sealed, truth),
  }) : {valid: true, errors: [], illegal_reference_count: 0};
  if (payload) errors.push(...referenceValidation.errors);

  if (payload && referenceValidation.illegal_reference_count > 0) {
    if (run.status === 'completed') {
      errors.push('a completed run cannot contain illegal evidence references; status must fail');
    } else if (payload.evidence_gate_status !== 'unknown' || payload.product_assessment === 'reportable_vulnerability') {
      errors.push('a non-completed run with illegal references must remain evidence_gate_status=unknown and cannot be reportable');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    retry_accounting: retry,
    reference_validation: referenceValidation,
  };
}

function validateCanonicalTestVectors(vectorsFile) {
  const errors = [];
  const document = readJson(vectorsFile);
  if (document.schema_version !== 'ohscanner.a-exp-01-canonical-hash-test-vectors-v1') errors.push('invalid canonical test vector schema_version');
  for (const vector of document.valid_vectors || []) {
    const canonical = canonicalJson(vector.value, {normalizeInputFiles: Boolean(vector.normalize_input_files)});
    const hash = sha256Utf8(canonical);
    if (canonical !== vector.expected_canonical_json) errors.push(`canonical mismatch: ${vector.name}`);
    if (hash !== vector.expected_sha256) errors.push(`hash mismatch: ${vector.name}`);
  }
  for (const vector of document.invalid_vectors || []) {
    let threw = false;
    let message = '';
    try {
      canonicalJson(vector.value, {normalizeInputFiles: Boolean(vector.normalize_input_files)});
    } catch (error) {
      threw = true;
      message = error.message;
    }
    if (!threw) errors.push(`invalid vector did not reject: ${vector.name}`);
    if (vector.expected_error_contains && !message.includes(vector.expected_error_contains)) {
      errors.push(`invalid vector error mismatch: ${vector.name}: ${message}`);
    }
  }
  return {valid: errors.length === 0, errors, valid_count: (document.valid_vectors || []).length, invalid_count: (document.invalid_vectors || []).length};
}

function validateLedger(ledgerFile) {
  const errors = [];
  const text = fs.readFileSync(ledgerFile, 'utf8');
  const lines = text.split('\n').filter((line) => line !== '');
  const records = [];
  for (let index = 0; index < lines.length; index += 1) {
    try {
      records.push(JSON.parse(lines[index]));
    } catch (error) {
      errors.push(`ledger line ${index + 1} is invalid JSON: ${error.message}`);
    }
  }
  const prefix = lines.slice(0, 2).map((line) => `${line}\n`).join('');
  const prefixHash = sha256Utf8(prefix);
  if (prefixHash !== '31d53dda3a438c60451865204ba9f68d789e178553156b658c4a11c14547febc') {
    errors.push('the first two historical preflight ledger records were modified');
  }
  if (lines.length > 0 && !text.endsWith('\n')) errors.push('run_ledger.jsonl must end with LF newline');
  const runRecords = records.filter((record) => record.schema_version === RUN_SCHEMA || record.record_type === 'run');
  if (runRecords.length !== 0) errors.push('preflight ledger must not contain experiment run records');
  const preflightUnblock = records.filter((record) => record.record_type === 'preflight_unblock');
  const preflightCorrections = records.filter((record) => record.record_type === 'preflight_unblock_correction');
  if (preflightUnblock.length > 1) errors.push('preflight unblock record must be append-only and unique');
  if (preflightCorrections.length > 1) errors.push('preflight unblock correction must be append-only and unique');
  for (const record of records) {
    if (record.execution_decision && record.execution_decision.model_calls !== 0) errors.push(`${record.record_id || '<unknown>'} reports model_calls != 0`);
  }
  return {valid: errors.length === 0, errors, record_count: records.length, records, prefix_sha256: prefixHash};
}
function validateArtifactManifest(packageDir) {
  const errors = [];
  const manifest = readJson(path.join(packageDir, 'artifact_manifest.json'));
  for (const [name, expected] of Object.entries(manifest.files || {})) {
    const file = path.join(packageDir, name);
    if (!fs.existsSync(file)) {
      errors.push(`missing artifact: ${name}`);
      continue;
    }
    const actual = sha256File(file);
    if (actual !== expected) errors.push(`artifact hash mismatch: ${name}: ${actual} != ${expected}`);
  }
  if (Object.prototype.hasOwnProperty.call(manifest.files || {}, 'run_ledger.jsonl')) errors.push('run_ledger.jsonl must be append-only metadata, not a fixed artifact hash');
  if (!manifest.append_only_ledger || !HEX64.test(manifest.append_only_ledger.initial_prefix_sha256 || '')) errors.push('artifact manifest append_only_ledger metadata is missing');
  return {valid: errors.length === 0, errors, file_count: Object.keys(manifest.files || {}).length, manifest};
}

function loadPackage(packageDir = PACKAGE_DIR) {
  return {
    packageDir,
    experimentManifest: readJson(path.join(packageDir, 'experiment_manifest.json')),
    artifactManifest: readJson(path.join(packageDir, 'artifact_manifest.json')),
    initial: readJson(path.join(packageDir, 'initial_candidate_set.json')),
    evidence: readJson(path.join(packageDir, 'evidence_catalog.json')),
    sealed: readJson(path.join(packageDir, 'sealed_item_key.json')),
    budget: readJson(path.join(packageDir, 'budget.json')),
    toolContract: readJson(path.join(packageDir, 'tool_contract.json')),
    modelBinding: readJson(path.join(packageDir, 'model_binding.template.json')),
    authorization: readJson(path.join(packageDir, 'tool_adapter_authorization.json')),
    statisticalContract: readJson(path.join(packageDir, 'statistical_unit_contract.json')),
    truth: readJson(path.resolve(packageDir, '../../../evidence/cpp/independent_truth_review_20261015/truth_set_manifest.json')),
  };
}

function runPackagePreflight(packageDir = PACKAGE_DIR) {
  const errors = [];
  const warnings = [];
  const checks = {};
  let data;
  try {
    data = loadPackage(packageDir);
  } catch (error) {
    return {ok: false, execution_ready: false, errors: [`failed to load package: ${error.message}`], warnings, checks};
  }

  checks.artifact_manifest = validateArtifactManifest(packageDir);
  errors.push(...checks.artifact_manifest.errors);

  for (const name of [
    'model_binding.schema.json', 'tool_adapter_authorization.schema.json',
    'statistical_unit_contract.json', 'canonical_input_bundle.schema.json',
    'canonical_hash.test_vectors.json', 'evidence_reference_contract.json',
    'retry_accounting_contract.json', 'preflight_record.schema.json',
  ]) {
    try {
      readJson(path.join(packageDir, name));
      checks[`schema_parse:${name}`] = true;
    } catch (error) {
      checks[`schema_parse:${name}`] = false;
      errors.push(`${name} does not parse: ${error.message}`);
    }
  }

  checks.model_binding = validateModelBinding(data.modelBinding);
  errors.push(...checks.model_binding.errors);
  checks.tool_adapter_authorization = validateToolAdapterAuthorization(data.authorization, data.toolContract);
  errors.push(...checks.tool_adapter_authorization.errors);
  checks.statistical_units = validateStatisticalUnits(data.sealed, data.statisticalContract);
  errors.push(...checks.statistical_units.errors);
  checks.canonical_vectors = validateCanonicalTestVectors(path.join(packageDir, 'canonical_hash.test_vectors.json'));
  errors.push(...checks.canonical_vectors.errors);
  checks.ledger = validateLedger(path.join(packageDir, 'run_ledger.jsonl'));
  errors.push(...checks.ledger.errors);
  if (checks.ledger.valid) {
    const decisionRecords = checks.ledger.records.filter((record) => record.record_type === 'preflight_unblock' || record.record_type === 'preflight_unblock_correction');
    const latestDecision = decisionRecords[decisionRecords.length - 1];
    if (latestDecision) {
      if (latestDecision.artifact_manifest_sha256 !== sha256File(path.join(packageDir, 'artifact_manifest.json'))) errors.push('latest preflight decision artifact_manifest_sha256 is stale');
      for (const [name, expected] of Object.entries(latestDecision.report_hashes || {})) {
        if (!fs.existsSync(path.join(packageDir, name)) || sha256File(path.join(packageDir, name)) !== expected) errors.push(`latest preflight decision report hash is stale: ${name}`);
      }
    }
  }

  if (data.initial.item_count !== 45 || data.initial.items.length !== 45) errors.push('initial candidate set must contain 45 review items');
  if (data.evidence.item_count !== 45 || data.evidence.items.length !== 45) errors.push('evidence catalog must contain 45 review items');
  if (data.sealed.item_count !== 45 || data.sealed.items.length !== 45) errors.push('sealed key must contain 45 review items');
  if (data.budget.per_item.R2.retries_max !== 1) errors.push('R2 retries_max must be 1');
  if (!data.budget.retry_accounting || data.budget.retry_accounting.retry_counts_as_new_repetition !== false) errors.push('retry must not count as a new repetition');

  const structuralOk = errors.length === 0;
  const r0Ready = structuralOk;
  const r1Ready = structuralOk && checks.model_binding.execution_authorized;
  const r2Ready = structuralOk && checks.model_binding.execution_authorized && checks.tool_adapter_authorization.execution_authorized;
  const executionReady = r0Ready && r1Ready && r2Ready;

  const executionBlockers = [];
  if (!checks.model_binding.bound) executionBlockers.push('an exact model/provider/version/API endpoint/data-processing/pricing record is contract-defined but not bound');
  else if (!checks.model_binding.execution_authorized) executionBlockers.push('the model binding record is not execution-authorized');
  if (!checks.tool_adapter_authorization.record_present) executionBlockers.push('R2 tool adapter authorization record is absent');
  else if (!checks.tool_adapter_authorization.execution_authorized) executionBlockers.push('R2 tool adapter authorization record is present but execution is not authorized');
  if (!executionReady) executionBlockers.push('the user has not authorized R0/R1/R2 execution in this preflight task');

  return {
    ok: structuralOk,
    execution_ready: executionReady,
    errors,
    warnings,
    checks,
    counts: checks.statistical_units && checks.statistical_units.observed ? checks.statistical_units.observed : null,
    decisions: {
      R0: r0Ready ? 'preflight_ready_execution_not_authorized' : 'blocked',
      R1: r1Ready ? 'preflight_ready_execution_not_authorized' : 'blocked',
      R2: r2Ready ? 'preflight_ready_execution_not_authorized' : 'blocked',
      overall: executionReady ? 'ready_execution_authorized' : 'blocked',
    },
    execution_blockers: executionBlockers,
    boundaries: {
      model_calls: 0,
      r0_r1_r2_runs: 0,
      model_results_generated: false,
      precision_recall_computed: false,
      candidate_truth_review_modified: false,
      synthetic_controls_treated_as_holdout: false,
    },
  };
}

function parseArguments(argv) {
  const options = {mode: 'check'};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--check') options.mode = 'check';
    else if (argument === '--require-ready') options.mode = 'require-ready';
    else if (argument === '--validate-run') {
      options.mode = 'validate-run';
      options.runFile = argv[++index];
    } else if (argument === '--hash-bundle') {
      options.mode = 'hash-bundle';
      options.bundleFile = argv[++index];
    } else if (argument === '--package-dir') {
      options.packageDir = argv[++index];
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(JSON.stringify({status: 'failed', errors: [error.message]}, null, 2));
    process.exit(2);
  }
  const packageDir = options.packageDir || PACKAGE_DIR;
  if (options.mode === 'hash-bundle') {
    try {
      const bundle = readJson(options.bundleFile);
      const result = hashInputBundle(bundle);
      console.log(JSON.stringify({status: 'passed', ...result}, null, 2));
    } catch (error) {
      console.error(JSON.stringify({status: 'failed', errors: [error.message]}, null, 2));
      process.exit(1);
    }
    return;
  }
  if (options.mode === 'validate-run') {
    try {
      const data = loadPackage(packageDir);
      const run = readJson(options.runFile);
      const result = validateRunRecord(run, {
        evidenceCatalog: data.evidence,
        sealed: data.sealed,
        truth: data.truth,
        budget: data.budget,
      });
      console.log(JSON.stringify({status: result.valid ? 'passed' : 'failed', ...result}, null, 2));
      process.exit(result.valid ? 0 : 1);
    } catch (error) {
      console.error(JSON.stringify({status: 'failed', errors: [error.message]}, null, 2));
      process.exit(1);
    }
  }
  const result = runPackagePreflight(packageDir);
  const output = {
    status: result.ok ? 'passed' : 'failed',
    execution_decision: result.decisions && result.decisions.overall,
    structural_validation: result.ok ? 'passed' : 'failed',
    ...result,
  };
  console.log(JSON.stringify(output, null, 2));
  if (!result.ok) process.exit(1);
  if (options.mode === 'require-ready' && !result.execution_ready) process.exit(1);
}

module.exports = {
  buildDeniedIdentifiers,
  loadPackage,
  runPackagePreflight,
  validateArtifactManifest,
  validateCanonicalTestVectors,
  validateEvidenceReferences,
  validateLedger,
  validateModelBinding,
  validateRetryAccounting,
  validateRunRecord,
  validateStatisticalUnits,
  validateToolAdapterAuthorization,
  main,
};

if (require.main === module) main();
