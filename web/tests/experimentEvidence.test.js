import test from "node:test";
import assert from "node:assert/strict";
import {
  experimentHoldoutPresentation,
  validationScopePresentation,
} from "../src/features/audits/experimentEvidence.js";

test("missing holdout remains explicitly unknown", () => {
  assert.deepEqual(experimentHoldoutPresentation(null), {
    state: "unknown",
    label: "独立 Holdout：unknown",
    reason: "没有冻结独立样本与人工真值清单。",
  });
});

test("component harness is never presented as product validation", () => {
  const view = validationScopePresentation({
    scope: "component_harness",
    input_manifest_state: "verified_input_manifest",
    validation_gate: "passed",
    reachability_status: "unknown",
  });
  assert.equal(view.state, "component_harness");
  assert.equal(view.label, "组件 Harness（非产品验证）");
});

test("product-level label requires both a verified input manifest and reachability", () => {
  assert.equal(validationScopePresentation({
    scope: "product_level",
    input_manifest_state: "unknown",
    reachability_status: "verified",
  }).state, "unknown");
  assert.equal(validationScopePresentation({
    scope: "product_level",
    input_manifest_state: "verified_input_manifest",
    reachability_status: "unknown",
  }).state, "unknown");
  assert.equal(validationScopePresentation({
    scope: "product_level",
    input_manifest_state: "verified_input_manifest",
    reachability_status: "verified",
  }).state, "product_level");
});
