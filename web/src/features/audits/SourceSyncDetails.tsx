import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Descriptions, Space, Spin, Tag, Typography } from "antd";
import { api } from "../../api";
import { go, Hash, State } from "../../components";
import { sourceSyncSummary } from "./sourceSyncProgress";
import SourceSyncBatchDetails from "./SourceSyncBatchDetails";

const { Text } = Typography;
const scanTerminal = new Set([
  "completed", "completed_with_limitations", "failed", "timed_out", "interrupted", "cancelled",
]);

type OperationRecord = Record<string, any>;

export default function SourceSyncDetails({ operation }: { operation: OperationRecord }) {
  return operation?.kind === "source_sync_batch"
    ? <SourceSyncBatchDetails operation={operation} />
    : <SingleSourceSyncDetails operation={operation} />;
}

function SingleSourceSyncDetails({ operation }: { operation: OperationRecord }) {
  const scanId = operation?.result?.scan_job_id || "";
  const [scanState, setScanState] = useState<{ id: string; job: any; loading: boolean; error: string }>({
    id: "", job: null, loading: false, error: "",
  });

  useEffect(() => {
    if (!scanId) {
      setScanState({ id: "", job: null, loading: false, error: "" });
      return;
    }
    let active = true;
    let pending = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    setScanState({ id: scanId, job: null, loading: true, error: "" });

    const load = async () => {
      if (pending) return;
      pending = true;
      try {
        const job = await api("/scans/" + scanId);
        if (!active) return;
        setScanState({ id: scanId, job, loading: false, error: "" });
        if (scanTerminal.has(job.status) && timer) clearInterval(timer);
      } catch (error) {
        if (!active) return;
        setScanState((current) => current.id === scanId
          ? { ...current, loading: false, error: String(error) }
          : current);
      } finally {
        pending = false;
      }
    };

    void load();
    timer = setInterval(() => void load(), 2500);
    return () => {
      active = false;
      if (timer) clearInterval(timer);
    };
  }, [scanId]);

  const scanJob = scanState.id === scanId ? scanState.job : null;
  const scanLoad = scanState.id === scanId ? scanState : { loading: Boolean(scanId), error: "" };
  const summary = sourceSyncSummary(operation, scanJob, scanLoad);

  return <Card size="small" className="section-gap" title="源码同步与扫描进度">
    <Descriptions bordered size="small" column={{ xs: 1, sm: 1, md: 2 }}>
      <Descriptions.Item label="仓库">{summary.repository}</Descriptions.Item>
      <Descriptions.Item label="源码同步">
        <Space wrap><Tag>{summary.syncLabel}</Tag><State value={summary.syncStatus} /></Space>
      </Descriptions.Item>
      <Descriptions.Item label="同步后 HEAD">
        {summary.localHead ? <Hash value={summary.localHead} /> : "同步完成后显示"}
      </Descriptions.Item>
      <Descriptions.Item label="远端分支 / 标签">
        {summary.remoteRefCount == null ? "同步完成后显示" : summary.remoteRefCount + " 个"}
      </Descriptions.Item>
      <Descriptions.Item label="固定扫描提交">
        {!summary.scanId ? "未请求扫描" : summary.scanCommit ? <Hash value={summary.scanCommit} /> : "正在固定版本"}
      </Descriptions.Item>
      <Descriptions.Item label="静态扫描">
        {!summary.scanId ? "未请求扫描" : summary.scanStatus === "loading"
          ? <Space><Spin size="small" />读取任务状态</Space>
          : summary.scanStatus === "unavailable"
            ? <Tag color="orange">状态暂不可用</Tag>
            : <Space wrap><State value={summary.scanStatus} />{summary.scanReportAvailable && <Tag color="green">静态报告已生成</Tag>}</Space>}
      </Descriptions.Item>
    </Descriptions>
    {summary.syncError && <Alert className="section-gap" type="error" showIcon
      message="源码同步失败" description={summary.syncError} />}
    {summary.scanError && <Alert className="section-gap" type="warning" showIcon
      message="暂时无法读取静态扫描状态" description="同步结果仍已保存；可刷新页面或打开扫描任务查看最新状态。" />}
    {summary.scanId
      ? <Button className="section-gap" type="primary" onClick={() => go("/tasks/" + summary.scanId)}>
          {summary.scanReportAvailable ? "查看静态扫描结果" : "查看静态扫描进度"}
        </Button>
      : operation.status === "completed" || operation.status === "completed_with_limitations"
        ? <Text className="section-gap" type="secondary">本次操作只同步了源码，没有请求扫描。</Text>
        : null}
    {summary.limitations.length > 0 && <Alert className="section-gap" type="info" showIcon
      message="任务说明" description={summary.limitations.join(" ")} />}
  </Card>;
}
