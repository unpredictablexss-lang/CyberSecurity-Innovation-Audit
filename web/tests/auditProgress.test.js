import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { auditProgress } from '../src/features/workbench/auditProgress.js';
const job = { status: 'completed_with_limitations', report_sha256: 'a'.repeat(64), spec: { audit_mode: 'standard_review' } };
const phase = (total, counts) => ({ operation_count: total, ...counts });

test('scan completion does not complete an ongoing deep investigation', () => {
  const view = auditProgress(job, { state: 'in_progress', triage_progress: { pending_count: 6 }, batches: [{
    r1_progress: phase(22, { completed_with_limitations_count: 22 }),
    r2_progress: phase(6, { running_count: 1, queued_count: 5 }),
  }] });
  assert.equal(view.label, '正在深入追查'); assert.equal(view.poll, true);
  assert.equal(view.phases[0].completed, 22);
  assert.match(view.phases[1].text, /已完成 0\/6 条 · 运行中 1 条 · 排队 5 条/);
});
test('initial analysis and a queued deep phase have distinct labels', () => {
  const summary = { state: 'in_progress', batches: [{ r1_progress: phase(3, { running_count: 1, queued_count: 2 }) }] };
  assert.equal(auditProgress(job, summary).label, '正在初步分析');
  summary.batches[0] = { r2_progress: phase(1, { queued_count: 1 }) };
  assert.equal(auditProgress(job, summary).label, '深入追查排队中');
});
test('waiting between initial and deep phases continues polling', () => {
  const view = auditProgress(job, { state: 'in_progress', triage_progress: { r2_waiting_count: 1 }, batches: [] });
  assert.equal(view.label, '正在准备下一步 AI 调查'); assert.equal(view.poll, true);
});
test('missing AI response never turns a finished scan into a finished intelligent audit', () => {
  const view = auditProgress(job, null);
  assert.equal(view.poll, true); assert.match(view.label, /正在核对 AI 进度/); assert.deepEqual(view.phases, []);
  assert.equal(auditProgress(job, { state: 'unrecognized' }).poll, true);
});
test('limited results count as finished analyses and stay visibly limited', () => {
  const view = auditProgress(job, { state: 'completed_with_limitations', batches: [{
    r1_progress: phase(3, { completed_count: 1, completed_with_limitations_count: 2 }),
  }] });
  assert.equal(view.poll, false); assert.equal(view.phases[0].completed, 3);
  assert.match(view.label, /有限制/); assert.match(view.phases[0].text, /2 条有限制/);
});
test('failures and stopped operations are not counted as completed analyses', () => {
  const view = auditProgress(job, { state: 'partially_completed', batches: [{
    r2_progress: phase(5, { completed_count: 1, failed_count: 3, timed_out_count: 1, blocked_count: 1, cancelled_count: 1 }),
  }] });
  assert.equal(view.phases[0].completed, 1); assert.equal(view.phases[0].failed, 3);
  assert.match(view.label, /部分完成/); assert.equal(view.poll, false);
});
test('revocation while an operation is still running shows stopping', () => {
  const view = auditProgress(job, { state: 'stopped', authorization: { revoked: true }, triage_progress: { pending_count: 1 } });
  assert.equal(view.label, '正在停止 AI 调查'); assert.equal(view.poll, true);
  assert.equal(auditProgress(job, { state: 'cancelled' }).label, 'AI 调查已停止');
});
test('multiple audit endpoints keep their phase counts separate and aggregate correctly', () => {
  const view = auditProgress(job, { state: 'in_progress', batches: [
    { r1_progress: phase(2, { completed_count: 2 }), r2_progress: phase(1, { running_count: 1 }) },
    { r1_progress: phase(3, { completed_with_limitations_count: 3 }), r2_progress: phase(2, { queued_count: 2 }) },
  ] });
  assert.equal(view.phases[0].completed, 5); assert.equal(view.phases[0].total, 5);
  assert.equal(view.phases[1].total, 3); assert.equal(view.phases[1].queued, 2);
});
test('static and failed-before-report tasks keep their own terminal behavior', () => {
  assert.equal(auditProgress({ ...job, spec: { audit_mode: 'static_only' } }).poll, false);
  assert.equal(auditProgress({ ...job, status: 'failed', report_sha256: null }).poll, false);
  assert.equal(auditProgress({ ...job, status: 'running', report_sha256: null }).label, '正在静态扫描');
});
test('detail polling follows overall progress rather than static completion', () => {
  const source = readFileSync(new URL('../src/pages/JobDetail.tsx', import.meta.url), 'utf8');
  assert.match(source, /!auditProgress\(j, latestTriage\)\.poll/);
  assert.doesNotMatch(source, /if \(terminal\.has\(j\.status\) && timer\)/);
});
