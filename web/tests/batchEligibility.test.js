import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { batchEligibility } from '../src/features/audits/batchEligibility.js';
const row=(id,eligible=true)=>({candidate_id:id,preview:{agent_execution:{eligible,reason:'需要人工或运行时验证'}}});

test('a batch of source-ineligible CVE candidates is visibly blocked before submission',()=>{
  const result=batchEligibility({candidate_count:3,blocked_candidate_ids:['a','b','c'],candidates:[row('a',false),row('b',false),row('c',false)]});
  assert.equal(result.eligible,false); assert.equal(result.blocked.length,3);
  assert.match(result.reason,/3 条候选暂不能启动/); assert.equal(result.blocked[0].reason,'需要人工或运行时验证');
});
test('mixed eligibility does not silently remove a selected candidate',()=>{
  const result=batchEligibility({candidate_count:2,candidates:[row('a'),row('b',false)]});
  assert.equal(result.eligible,false); assert.deepEqual(result.blocked.map(x=>x.id),['b']);
});
test('server blocked ids take precedence even if a child preview is missing',()=>{
  assert.equal(batchEligibility({candidate_count:1,blocked_candidate_ids:['missing'],candidates:[row('a')]}).eligible,false);
});
test('empty, incomplete, and unknown execution eligibility cannot enable the confirmation button',()=>{
  for(const preview of [null,{candidate_count:0,candidates:[]},{candidate_count:2,candidates:[row('a')]},{candidate_count:1,candidates:[{candidate_id:'a'}]}]){
    assert.equal(batchEligibility(preview).eligible,false);
  }
});
test('fully eligible previews still permit the existing explicit disclosure and consent flow',()=>{
  assert.equal(batchEligibility({candidate_count:2,blocked_candidate_ids:[],candidates:[row('a'),row('b')]}).eligible,true);
});
test('task modal retains submit errors near the confirmation controls and prevents duplicate requests',()=>{
  const source=readFileSync(new URL('../src/pages/JobDetail.tsx',import.meta.url),'utf8');
  assert.match(source,/if \(batchSubmitting.current\) return/);
  assert.match(source,/!batchEligible.eligible/);
  assert.match(source,/AI 调查未确认创建，请核对后处理/);
  assert.match(source,/setBatchSubmissionApproved\(false\)/);
});
