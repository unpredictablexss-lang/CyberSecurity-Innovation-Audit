import React, { useEffect, useState } from "react";
import { Alert, Button, Card, Descriptions, Space, Table, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { go, Hash } from "../../components";
import { sourceSyncBatchRetryAction, sourceSyncBatchRows } from "./sourceSyncProgress";

const { Text } = Typography;
const scanTerminal = new Set(["completed", "completed_with_limitations", "failed", "timed_out", "interrupted", "cancelled"]);
const syncLabels: Record<string, string> = {
  queued: "等待同步", running: "正在同步", completed: "同步完成",
  completed_with_limitations: "已同步（有待处理项）", failed: "同步失败",
  timed_out: "同步超时", interrupted: "同步中断", cancelled: "已取消",
  not_started: "尚未开始", skipped_duplicate: "重复项已跳过",
};
const scanLabels: Record<string, string> = {
  not_requested: "未请求扫描", not_started: "等待同步", queued: "等待扫描",
  running: "扫描中", completed: "扫描完成", completed_with_limitations: "扫描完成（有待处理项）",
  failed: "扫描失败", timed_out: "扫描超时", interrupted: "扫描中断", cancelled: "扫描已取消",
  unavailable: "状态暂不可用",
};
const syncColor: Record<string, string> = {
  completed: "green", completed_with_limitations: "orange", failed: "red",
  timed_out: "red", cancelled: "default", skipped_duplicate: "default",
};
const scanColor: Record<string, string> = {
  completed: "green", completed_with_limitations: "orange", failed: "red",
  timed_out: "red", cancelled: "default", unavailable: "orange",
};

type Props = { operation: Record<string, any> };

export default function SourceSyncBatchDetails({ operation }: Props) {
  const initialRows = sourceSyncBatchRows(operation);
  const scanIds = [...new Set(initialRows.map((row: any) => row.scanJobId).filter(Boolean))].sort();
  const scanKey = scanIds.join(",");
  const [scanJobs, setScanJobs] = useState<Record<string, any>>({});
  const [scanError, setScanError] = useState("");
  const [retrying, setRetrying] = useState<number | null>(null);
  const [retryError, setRetryError] = useState("");

  useEffect(() => {
    if (!scanKey) {
      setScanJobs({});
      setScanError("");
      return;
    }
    let active = true;
    let pending = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    const ids = scanKey.split(",");
    const refresh = async () => {
      if (pending) return;
      pending = true;
      try {
        const results = await Promise.all(ids.map(async (id) => {
          try { return { id, job: await api("/scans/" + id), error: "" }; }
          catch (error) { return { id, job: null, error: String(error) }; }
        }));
        if (!active) return;
        const next: Record<string, any> = {};
        for (const row of results) if (row.job) next[row.id] = row.job;
        setScanJobs(next);
        setScanError(results.find((row) => row.error)?.error || "");
        if (results.every((row) => row.job && scanTerminal.has(row.job.status)) && timer) clearInterval(timer);
      } finally { pending = false; }
    };
    void refresh();
    timer = setInterval(() => void refresh(), 2500);
    return () => { active = false; if (timer) clearInterval(timer); };
  }, [scanKey]);

  const rows = sourceSyncBatchRows(operation, scanJobs);
  const summary = operation?.result?.summary || {};
  const retry = async (row: any) => {
    const original = operation?.spec?.repositories?.[row.index - 1];
    if (!original) return;
    setRetrying(row.index);
    setRetryError("");
    try {
      const request = {
        repository: original.name, url: original.url,
        timeout_seconds: original.timeout_seconds, scan_after_sync: original.scan_after_sync,
        revision: original.revision, include_paths: original.include_paths,
        detector_ids: original.detector_ids, audit_mode: "static_only",
        scan_timeout_seconds: original.scan_timeout_seconds, memory_mb: original.memory_mb,
      };
      const created = await api("/operations/source-sync/batch", { repositories: [request] });
      message.success("已为该仓库创建重试任务");
      go("/tasks/operations/" + created.id);
    } catch (error) { setRetryError(String(error)); }
    finally { setRetrying(null); }
  };

  return <Card size="small" className="section-gap" title="批量同步进度">
    <Descriptions bordered size="small" column={{ xs: 1, sm: 2, md: 4 }}>
      <Descriptions.Item label="本批仓库">{summary.requested ?? rows.length}</Descriptions.Item>
      <Descriptions.Item label="已同步">{summary.succeeded ?? rows.filter((row: any) => ["completed", "completed_with_limitations"].includes(row.status)).length}</Descriptions.Item>
      <Descriptions.Item label="失败">{summary.failed ?? rows.filter((row: any) => row.status === "failed").length}</Descriptions.Item>
      <Descriptions.Item label="未开始">{summary.not_started ?? rows.filter((row: any) => row.status === "not_started").length}</Descriptions.Item>
    </Descriptions>
    {retryError && <Alert className="section-gap" type="error" showIcon message="重试任务未创建" description={retryError} />}
    {scanError && <Alert className="section-gap" type="warning" showIcon message="部分扫描状态暂不可用" description="同步记录仍已保存；可稍后刷新或打开对应任务查看。" />}
    {operation?.status === "cancelled" && <Alert className="section-gap" type="info" showIcon
      message="批次已取消" description="已完成的仓库结果会保留；尚未开始的仓库没有被同步，已排队但未完成的扫描也已请求取消。" />}
    <Table<any> className="section-gap" size="small" rowKey="index" dataSource={rows} pagination={{ pageSize: 8 }}
      scroll={{ x: 950 }} columns={[
        { title: "仓库", dataIndex: "repository", fixed: "left", width: 210 },
        { title: "同步", dataIndex: "status", width: 150, render: (value: string) =>
          <Tag color={syncColor[value] || "default"}>{syncLabels[value] || "状态未知"}</Tag> },
        { title: "同步后提交", dataIndex: "localHead", width: 190, render: (value: string | null) => value ? <Hash value={value} /> : "—" },
        { title: "扫描", dataIndex: "scanStatus", width: 160, render: (value: string, row: any) => <Space direction="vertical" size={2}>
          <Tag color={scanColor[value] || "default"}>{scanLabels[value] || "状态未知"}</Tag>
          {row.scanCommit && <Hash value={row.scanCommit} />}
        </Space> },
        { title: "说明", dataIndex: "error", render: (value: string, row: any) =>
          value ? <Text type="danger">{value}</Text> : row.duplicateOf ? <Text type="secondary">与第 {row.duplicateOf} 项相同，已跳过重复同步。</Text> : "—" },
        { title: "操作", fixed: "right", width: 150, render: (_: unknown, row: any) => {
          const retryAction = sourceSyncBatchRetryAction(row);
          return retryAction
            ? <Button size="small" loading={retrying === row.index} disabled={retrying !== null} onClick={() => void retry(row)}>
                {retryAction === "sync" ? "重试同步" : "重新同步并扫描"}
              </Button>
            : row.scanJobId ? <Button size="small" onClick={() => go("/tasks/" + row.scanJobId)}>查看扫描</Button> : "—";
        } },
      ]} locale={{ emptyText: "暂无仓库同步记录" }} />
    <Text type="secondary">批次按仓库顺序执行，最多 8 个；同步失败会继续处理后续仓库。重复项只执行一次。扫描任务固定各自的提交和文件树。</Text>
  </Card>;
}
