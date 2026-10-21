import test from "node:test";
import assert from "node:assert/strict";
import { buildEvidenceGraphView } from "../src/features/cases/evidenceGraphViewModel.js";

test("evidence graph view summarizes fixed-source trace without claiming semantic proof", () => {
  const view = buildEvidenceGraphView({
    binding: { repository: "openharmony/sample", commit: "a".repeat(40), candidate_id: "candidate-1" },
    nodes: [
      { id: "stage:primary_source_triage", node_type: "workflow_stage", stage_id: "primary_source_triage", status: "accepted" },
      { id: "stage:independent_skeptic", node_type: "workflow_stage", stage_id: "independent_skeptic", status: "completed" },
      { id: "evidence:ev-1", node_type: "fixed_source_evidence", evidence_id: "ev-1", evidence_kind: "source_code", status: "available",
        source_binding: { files: [{ file: "src/auth.cpp", start_line: 42, end_line: 44, binding_status: "bound" }] } },
    ],
    edges: [
      { edge_id: "edge-1", source: "stage:primary_source_triage", target: "evidence:ev-1", type: "validated_citation_reference", semantic_support: "unverified_by_machine", file: "src/auth.cpp", line_start: 42, line_end: 44 },
      { edge_id: "edge-2", source: "stage:independent_skeptic", target: "evidence:ev-1", type: "counterevidence_candidate_reference", semantic_support: "unverified_by_machine" },
    ],
    unresolved_references: [],
    interpretation_boundary: "引用语义尚未验证。",
    product_state: "candidate",
    validated_vulnerability: 0,
  });

  assert.equal(view.statusLabel, "调查阶段已完成");
  assert.equal(view.binding.repository, "openharmony/sample");
  assert.equal(view.citations.length, 2);
  assert.equal(view.citations[0].location, "src/auth.cpp:42–44");
  assert.equal(view.citations[0].semanticSupport, "unverified_by_machine");
  assert.equal(view.productState, "candidate");
  assert.equal(view.validatedVulnerability, 0);
  assert.match(view.boundary, /尚未验证/);
});

test("incomplete stages and unbound references remain visible as incomplete", () => {
  const view = buildEvidenceGraphView({
    nodes: [{ id: "stage:independent_skeptic", node_type: "workflow_stage", stage_id: "independent_skeptic", status: "incomplete" }],
    edges: [],
    unresolved_references: [{ stage_id: "independent_skeptic", file: "src/unknown.cpp", reason: "citation_not_bound_to_available_fixed_source_lines" }],
    product_state: "candidate",
  });
  assert.equal(view.complete, false);
  assert.equal(view.statusLabel, "有引用待核对");
  assert.equal(view.unresolved[0].file, "src/unknown.cpp");
  assert.equal(buildEvidenceGraphView(null), null);
});
