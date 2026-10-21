export function experimentHoldoutPresentation(holdout) {
  if (!holdout || holdout.state !== "available") {
    return {
      state: "unknown",
      label: "独立 Holdout：unknown",
      reason: holdout?.reason || "没有冻结独立样本与人工真值清单。",
    };
  }
  return { state: "available", label: "独立 Holdout：已登记", reason: holdout.reason || "" };
}

export function validationScopePresentation(run) {
  if (run?.scope === "component_harness") {
    return { state: "component_harness", label: "组件 Harness（非产品验证）" };
  }
  if (run?.scope === "product_level"
      && run?.input_manifest_state === "verified_input_manifest"
      && run?.reachability_status === "verified") {
    return { state: "product_level", label: "产品级验证" };
  }
  return { state: "unknown", label: "unknown" };
}
