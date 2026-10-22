import test from 'node:test';
import assert from 'node:assert/strict';
import { identifierType, identifierLabel } from '../src/features/workbench/identifierTypes.js';

test('weakness identifiers have readable types independent of vulnerability confirmation', () => {
  assert.equal(identifierLabel('CWE-476'), 'CWE-476 · 空指针解引用');
  assert.equal(identifierType('CWE-416'), '释放后使用');
  assert.equal(identifierType('CWE-787'), '越界写入');
});
test('libpng CVE labels use their own checked types, not a generic null pointer finding', () => {
  assert.equal(identifierLabel('CVE-2026-46675'), 'CVE-2026-46675 · 释放后使用');
  assert.equal(identifierType('CVE-2026-33636'), 'ARM NEON 调色板越界访问');
});
test('unknown or absent identifiers do not inherit a type or CVE from adjacent findings', () => {
  assert.equal(identifierType('CVE-2099-99999'), '类型待核对');
  assert.equal(identifierType('CWE-999999'), '类型待核对');
  assert.equal(identifierType(null), '类型待核对');
});
