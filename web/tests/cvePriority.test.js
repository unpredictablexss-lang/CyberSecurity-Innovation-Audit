import test from 'node:test';
import assert from 'node:assert/strict';
import { disclosedCves, prioritizeDisclosedCves, prioritizeWithRiskEvidence, loadCandidatePages } from '../src/features/workbench/cvePriority.js';

test('a CVE at the end moves ahead without changing its confidence or severity', () => {
  const ordinary = { id:'ordinary',candidate_cwe:'CWE-476' };
  const cve = Object.freeze({ id:'known',symbol:'CVE-2026-46675', risk_tier:'further_validation',severity:'medium' });
  assert.deepEqual(prioritizeDisclosedCves([ordinary,cve]), [cve,ordinary]);
  assert.equal(cve.risk_tier,'further_validation'); assert.equal(cve.severity,'medium');
  assert.deepEqual(disclosedCves(ordinary),[]);
});
test('human evidence stays ahead and refuted CVE rows are not promoted', () => {
  const ordinary={id:'a'}, cve={symbol:'CVE-2026-33636'}, verified={risk_tier:'high_confidence_candidate'};
  const refuted={symbol:'CVE-2026-46675',review_status:'refuted'};
  assert.deepEqual(prioritizeDisclosedCves([ordinary,refuted,cve,verified]),[verified,cve,ordinary,refuted]);
});
test('pagination occurs after loading and sorting all candidate pages', async () => {
  const rows=Array.from({length:205},(_,i)=>({id:String(i)}));
  rows[204].symbol='CVE-2026-46675';
  const calls=[];
  const result=await loadCandidatePages(async path=>{
    calls.push(path); const start=Number(new URL('http://test'+path).searchParams.get('offset'));
    return {total:rows.length,items:rows.slice(start,start+200)};
  },'/findings?q=test');
  assert.equal(result.items[0].id,'204'); assert.equal(calls.length,2); assert.equal(result.total,205);
});
test('incomplete or changed pages are not silently presented as a complete sorted list', async () => {
  await assert.rejects(loadCandidatePages(async()=>({total:2,items:[]}),'/findings'),/分页读取中断/);
});

test('confidence ordering applies across arbitrary repositories, including unknown CVE sources', () => {
  const high={id:'high',repository:'repo-A',risk_tier:'high_confidence_candidate',severity:'low'};
  const pending={id:'pending',repository:'repo-B',risk_tier:'further_validation'};
  const unknown={id:'unknown',repository:'repo-C',risk_tier:'unknown_source_binding',symbol:'CVE-2026-46675',severity:'critical'};
  const low={id:'low',repository:'repo-D',risk_tier:'low_priority_manual'};
  assert.deepEqual(prioritizeDisclosedCves([unknown,low,pending,high]),[high,pending,unknown,low]);
});
test('finding lists use source-bound risk tiers and retain original diagnostics unchanged', () => {
  const rows=[Object.freeze({id:'a',symbol:'CVE-2026-46675'}),Object.freeze({id:'b',candidate_cwe:'CWE-476'})];
  const risks=[{candidate_id:'a',risk_tier:'unknown_source_binding'},{candidate_id:'b',risk_tier:'high_confidence_candidate'}];
  assert.deepEqual(prioritizeWithRiskEvidence(rows,risks),[rows[1],rows[0]]);
  assert.equal(rows[0].risk_tier,undefined);
});
test('same-confidence rows use CVE then severity, with stable ties', () => {
  const a={risk_tier:'further_validation',severity:'medium'},b={risk_tier:'further_validation',severity:'high'},
    c={risk_tier:'further_validation',symbol:'CVE-2026-46675',severity:'low'};
  assert.deepEqual(prioritizeDisclosedCves([a,b,c]),[c,b,a]);
});
