import React from "react";
import { Button, Space } from "antd";
import { go } from "../../components";
export default function CandidateActions({ job, candidate }: { job: any; candidate: any }) {
  const query = new URLSearchParams({ job_id: job.id, candidate_id: candidate.id, repository_id: job.repository_id });
  return <Space wrap className="section-gap">
    <Button onClick={() => go("/investigations?" + query)}>查看候选线索</Button>
    <Button onClick={() => go("/audits/versions?" + query)}>比较其他版本</Button>
    <Button onClick={() => go("/poc?" + query)}>验证候选</Button>
  </Space>;
}
