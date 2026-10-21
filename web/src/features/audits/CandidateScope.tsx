import React, { useCallback, useEffect, useState } from "react";
import { Alert, Button, Space, Typography } from "antd";
import { api } from "../../api";
import { candidateBatchLimit } from "./model";

export function useCandidateScope() {
  const [policy, setPolicy] = useState<any>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try {
      const value = await api("/agent/triage-policy");
      setPolicy(value.policy); setError("");
    } catch (reason) { setPolicy(null); setError(String(reason)); }
  }, []);
  useEffect(() => {
    void load();
    const focus = () => { void load(); };
    window.addEventListener("focus", focus);
    return () => window.removeEventListener("focus", focus);
  }, [load]);
  return { policy, error, reload: load };
}

export default function CandidateScope() {
  const { policy, error, reload } = useCandidateScope();
  return <Alert className="section-gap" type={error ? "warning" : "info"} showIcon
    message="候选范围统一读取系统设置"
    description={<Space direction="vertical">
      <Typography.Text>{error || (policy
        ? `每个固定版本：初步分析最多 ${candidateBatchLimit(policy, "single_shot")} 条候选，深入追查最多 ${candidateBatchLimit(policy, "tool_agent")} 条候选。自动归并流程按候选组计算。`
        : "正在读取候选范围；授权预览会再次核对当前策略。")}</Typography.Text>
      <Typography.Text>设置修改后须重新预览；历史任务保留原授权范围。</Typography.Text>
      <Space><Typography.Link href="#/settings/policy">修改候选范围</Typography.Link>
        <Button size="small" onClick={() => void reload()}>重新读取</Button></Space>
    </Space>} />;
}
