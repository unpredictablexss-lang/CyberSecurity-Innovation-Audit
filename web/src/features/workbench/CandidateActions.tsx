import React from "react";
import { Button, Space } from "antd";
import { go } from "../../components";
export default function CandidateActions({ job, candidate }: { job: any; candidate: any }) {
  const query = new URLSearchParams({ job_id: job.id, candidate_id: candidate.id, repository_id: job.repository_id });
  return <Space wrap className="section-gap">
    <Button onClick={() => go("/investigations?" + query)}>只读调查此候选</Button>
    <Button onClick={() => go("/audits/versions?" + query)}>检查其他版本</Button>
    <Button onClick={() => go("/poc?" + query)}>进入受控验证</Button>
  </Space>;
}
