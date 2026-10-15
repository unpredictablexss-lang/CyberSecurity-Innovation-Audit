'use strict';

const crypto = require('crypto');

function fail(message) {
  throw new Error(message);
}

function assertJsonStringValue(value, pointer) {
  if (typeof value !== 'string') fail(`${pointer}: expected string`);
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail(`${pointer}: lone high surrogate is not a Unicode scalar value`);
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${pointer}: lone low surrogate is not a Unicode scalar value`);
    }
  }
}

function canonicalNumber(value, pointer) {
  if (typeof value !== 'number') fail(`${pointer}: expected number`);
  if (!Number.isFinite(value)) fail(`${pointer}: NaN and Infinity are not valid JSON numbers`);
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) fail(`${pointer}: unsafe integer is rejected before canonical hashing`);
  if (Object.is(value, -0)) return '0';
  return String(value);
}

function sortObjectKeys(keys) {
  return [...keys].sort((a, b) => {
    if (a === b) return 0;
    return a < b ? -1 : 1;
  });
}

function canonicalize(value, pointer = '$') {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string') {
    assertJsonStringValue(value, pointer);
    return JSON.stringify(value);
  }
  if (type === 'number') return canonicalNumber(value, pointer);
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'undefined') fail(`${pointer}: undefined is not representable; omit optional fields explicitly or use null`);
  if (type === 'bigint') fail(`${pointer}: bigint is rejected; use a safe JSON integer`);
  if (type === 'function' || type === 'symbol') fail(`${pointer}: ${type} is not valid JSON`);
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonicalize(item, `${pointer}[${index}]`)).join(',')}]`;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${pointer}: only plain JSON objects are allowed`);
  }
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string') fail(`${pointer}: symbol keys are not allowed`);
    if (Object.prototype.hasOwnProperty.call(value, key) && value[key] === undefined) {
      fail(`${pointer}.${key}: explicit undefined is not allowed; omit the field or use null`);
    }
  }
  const parts = sortObjectKeys(keys).map((key) => {
    const child = canonicalize(value[key], `${pointer}.${key}`);
    return `${JSON.stringify(key)}:${child}`;
  });
  return `{${parts.join(',')}}`;
}

function utf8ByteCompare(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function fileEntryCompare(a, b) {
  const pathOrder = utf8ByteCompare(String(a.path), String(b.path));
  if (pathOrder !== 0) return pathOrder;
  const roleOrder = utf8ByteCompare(String(a.role || ''), String(b.role || ''));
  if (roleOrder !== 0) return roleOrder;
  return utf8ByteCompare(String(a.sha256 || ''), String(b.sha256 || ''));
}

function normalizeInputBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) fail('$.input_files: input bundle must be a plain object');
  const clone = JSON.parse(JSON.stringify(bundle));
  if (!Array.isArray(clone.input_files)) fail('$.input_files: required array is missing');
  const seen = new Set();
  for (let index = 0; index < clone.input_files.length; index += 1) {
    const entry = clone.input_files[index];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) fail(`$.input_files[${index}]: expected object`);
    for (const field of ['path', 'role', 'sha256']) {
      if (typeof entry[field] !== 'string' || entry[field] === '') {
        fail(`$.input_files[${index}].${field}: required non-empty string`);
      }
    }
    const key = `${entry.path}\u0000${entry.role}\u0000${entry.sha256}`;
    if (seen.has(key)) fail(`$.input_files[${index}]: duplicate file record`);
    seen.add(key);
  }
  clone.input_files.sort(fileEntryCompare);
  return clone;
}

function canonicalJson(value, options = {}) {
  const normalized = options.normalizeInputFiles ? normalizeInputBundle(value) : value;
  return canonicalize(normalized);
}

function sha256Utf8(text) {
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function hashInputBundle(bundle) {
  const canonical = canonicalJson(bundle, {normalizeInputFiles: true});
  return {
    serialization: 'ohscanner.canonical-json-v1',
    canonical_json: canonical,
    input_bundle_sha256: sha256Utf8(canonical),
    input_file_count: bundle && Array.isArray(bundle.input_files) ? bundle.input_files.length : 0,
  };
}

module.exports = {
  canonicalJson,
  canonicalize,
  hashInputBundle,
  normalizeInputBundle,
  sha256Utf8,
};