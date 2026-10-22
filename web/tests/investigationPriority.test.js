import test from "node:test";
import assert from "node:assert/strict";
import { topInvestigationGroups, selectedInvestigationCandidates } from "../src/features/audits/investigationPriority.js";
const group = (id, eligible=true, auto=true) => ({group_id:id,auto_select:auto,representative:{candidate_id:id,eligible,auto_select:auto},members:[{candidate_id:id,eligible}]});
test("top selection respects configured deep cap and excludes failed or deferred groups",()=>{
 const rows=[group("failed",false,false),group("defer",true,false),...Array.from({length:8},(_,i)=>group(String(i)))];
 assert.deepEqual(topInvestigationGroups(rows,30,6),["0","1","2","3","4","5"]);
 assert.deepEqual(topInvestigationGroups(rows,6,null),[]);
 assert.deepEqual(topInvestigationGroups(rows,2,6),["0","1"]);
});
test("one representative per group and explicit alternate member can be chosen",()=>{
 const a=group("a");a.members.push({candidate_id:"b",eligible:true});
 assert.deepEqual(selectedInvestigationCandidates([a],["a"],{a:"b"}),["b"]);
});
test("stale selections and newly ineligible members are not submitted",()=>{
 assert.deepEqual(selectedInvestigationCandidates([group("a",false)],["a","old"]),[]);
 assert.deepEqual(selectedInvestigationCandidates([group("a")],["a"],{a:"missing"}),[]);
});
test("selection deduplicates candidates and never repeats one from two groups",()=>{
 const a=group("a"),b={...group("b"),representative:a.representative,members:a.members};
 assert.deepEqual(topInvestigationGroups([a,b],6,6),["a"]);
 assert.deepEqual(selectedInvestigationCandidates([a,b],["a","b"]),["a"]);
});
