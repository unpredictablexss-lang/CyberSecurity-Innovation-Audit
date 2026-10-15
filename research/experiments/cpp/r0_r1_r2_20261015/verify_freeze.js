'use strict';

const validator = require('./preflight_validator');

const requireReady = process.argv.includes('--require-ready');
const result = validator.runPackagePreflight(__dirname);
const output = {
  status: result.ok ? 'passed' : 'failed',
  structural_validation: result.ok ? 'passed' : 'failed',
  execution_decision: result.decisions && result.decisions.overall,
  decisions: result.decisions,
  errors: result.errors,
  execution_blockers: result.execution_blockers,
  boundaries: result.boundaries,
};
console.log(JSON.stringify(output, null, 2));
if (!result.ok) process.exit(1);
if (requireReady && !result.execution_ready) process.exit(1);