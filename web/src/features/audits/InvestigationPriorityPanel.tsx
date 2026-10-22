import React, { useEffect, useState } from "react";
import { Alert, Button, InputNumber, List, Select, Space, Table, Tag, Typography } from "antd";
import { api } from "../../api";
import { go } from "../../components";
import ChineseNarrative from "../cases/ChineseNarrative";
import { topInvestigationGroups, selectedInvestigationCandidates } from "./investigationPriority.js";
const { Text } = Typography;
const assessmentLabels: Record<string,string> = {likely_true_positive:"倾向真实候选", likely_false_positive:"倾向误报", needs_more_evidence:"需要更多证据", unknown:"尚不明确"};
const colors: Record<string,string> = {investigate:"red", supplement:"blue", human_review:"purple", defer:"default", incomplete:"error", pending:"processing"};

export default function InvestigationPriority({ jobId, active, refreshKey, limit, enabled, onInvestigate, onEvidence }: {
  jobId: string; active: boolean; refreshKey: number; limit: number | null; enabled: boolean;
  onInvestigate: (candidateIds: string[]) => void; onEvidence: (row: any) => void;
}) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [representatives, setRepresentatives] = useState<Record<string,string>>({});
  const [count, setCount] = useState<number | null>(null);
  const [filter, setFilter] = useState("all");
  const [revision, setRevision] = useState(0);
  useEffect(() => { setData(null); setSelected([]); setRepresentatives({}); setError(""); }, [jobId]);
  useEffect(() => {
    if (!active) return;
    let live = true;
    async function load() {
      setLoading(true);
      try {
        const value = await api("/scans/" + jobId + "/investigation-priority");
        if (live) { setData(value); setError(""); }
      } catch (reason) { if (live) setError(String(reason)); }
      finally { if (live) setLoading(false); }
    }
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => { live = false; clearInterval(timer); };
  }, [jobId, active, refreshKey, revision]);
  const groups = data?.groups || [];
  const ids = selectedInvestigationCandidates(groups, selected, representatives);
  const wanted = count ?? limit ?? 1;
  const shown = groups.filter((group: any) => filter === "all" || (filter === "recommended" ? group.auto_select : group.members.some((item: any) => item.priority === "incomplete")));
  return <Space direction="vertical" size="middle" style={{width:"100%"}}>
    <Text type="secondary">优先看已有源码线索、仍可通过追查补齐关键证据的候选；静态危害等级仅辅助排序。每组选一条代表进入深入追查，不将相似分组当作同一漏洞根因。</Text>
    {error && <Alert type="error" showIcon message="调查排名读取失败" description={error} />}
    <Space wrap>
      <Tag>候选 {data?.counts?.candidates ?? "—"} 条 / 相似分组 {data?.counts?.groups ?? "—"} 组</Tag>
      <Tag color="blue">初判有效 {data?.counts?.analyzed ?? "—"}</Tag>
      <Tag color="error">初判未完成 {data?.counts?.incomplete ?? "—"}</Tag>
      <Tag>处理中 {data?.counts?.pending ?? "—"}</Tag>
      <Button loading={loading} onClick={() => setRevision(value => value + 1)}>刷新排名</Button>
    </Space>
    <Space wrap>
      <Select aria-label="调查排名筛选" value={filter} onChange={setFilter} style={{width:180}} options={[
        {value:"all",label:"全部候选组"},{value:"recommended",label:"可推荐深入追查"},{value:"incomplete",label:"含初判未完成"}]} />
      <Text>优先勾选前</Text><InputNumber aria-label="优先勾选组数" min={1} max={Math.max(1, limit ?? 1)} precision={0} value={wanted} onChange={setCount} disabled={limit === null || limit < 1}/><Text>组</Text>
      <Button disabled={limit === null || limit < 1 || !!error || !groups.some((group: any) => group.auto_select)} onClick={() => { const keys = topInvestigationGroups(groups, wanted, limit); setFilter("recommended"); setRepresentatives(Object.fromEntries(groups.filter((group: any) => keys.includes(group.group_id)).map((group: any) => [group.group_id, group.representative.candidate_id]))); setSelected(keys); }}>一键勾选</Button>
      <Button onClick={() => setSelected([])} disabled={!selected.length}>清空</Button>
      <Button type="primary" disabled={!enabled || !!error || limit === null || !ids.length || ids.length > limit || ids.length !== selected.length}
        onClick={() => onInvestigate(ids)}>对所选 {ids.length} 组深入追查 · 查看发送内容</Button>
    </Space>
    <Text type="secondary">深入追查上限 {limit ?? "读取中"} 条，与系统设置一致。一键勾选跳过初判未完成、需人工验证、暂缓及已有深入追查的候选；也可手动选择。不会自动调用模型。</Text>
    <Table<any> rowKey="group_id" size="small" loading={loading && !data} dataSource={shown} scroll={{x:1100}}
      pagination={{pageSize:15,showSizeChanger:false}} rowSelection={{selectedRowKeys:selected,
        onChange: keys => { setSelected(keys.map(String)); setRepresentatives(current => ({...current,
          ...Object.fromEntries(groups.filter((group: any) => keys.includes(group.group_id) && !current[group.group_id]).map((group: any) => [group.group_id,group.representative.candidate_id]))})); }, preserveSelectedRowKeys:true,
        getCheckboxProps: group => ({disabled: !group.members.some((row: any) => row.eligible)})}}
      expandable={{expandedRowRender: group => <List size="small" dataSource={group.members} renderItem={(row: any) => <List.Item>
        <Space wrap><Text>{row.file}:{row.line}</Text><Tag color={colors[row.priority]}>{row.priority_label}</Tag>
          <Text>{row.reasons.join(" ")}</Text>{row.source_gaps?.length > 0 && <Text type="secondary">待补证：{row.source_gaps.map((gap: any) => <span key={gap.obligation_index}>#{gap.obligation_index} <ChineseNarrative value={gap.description} />；</span>)}</Text>}{row.failure_code && <Text type="danger">原因码：{row.failure_code}</Text>}
          <Button size="small" onClick={() => onEvidence({id:row.candidate_id})}>查看源码证据</Button>
          {row.operation_id && <Button size="small" onClick={() => go("/tasks/operations/" + row.operation_id)}>查看初判依据</Button>}
          <Button size="small" disabled={!row.eligible} onClick={() => {setRepresentatives(current => ({...current,[group.group_id]:row.candidate_id})); setSelected(current => current.includes(group.group_id) ? current : [...current,group.group_id]);}}>选为本组代表</Button>
        </Space></List.Item>} />}}
      columns={[
        {title:"顺序",width:65,render:(_,group) => group.rank ?? "—"},
        {title:"调查优先级",width:170,render:(_,group) => <Space direction="vertical" size={2}><Tag color={colors[group.priority]}>{group.priority_label}</Tag>{group.members.some((row: any) => row.priority === "incomplete") && <Text type="danger">含初判未完成项</Text>}</Space>},
        {title:"相似候选组",width:250,render:(_,group) => <Space direction="vertical" size={0}><a onClick={() => onEvidence({id:group.representative.candidate_id})}>{group.file}:{group.representative.line}</a><Text>{group.symbol || "符号未知，独立保留"}</Text><Text code>{group.rule_id}</Text><Space>{group.representative.cwe && <Tag color="blue">{group.representative.cwe}</Tag>}<Tag>静态等级：{({critical:"严重", high:"高危", medium:"中危", low:"低危"} as Record<string,string>)[group.representative.severity] || "未知"}</Tag></Space><Text type="secondary">{group.member_count} 条候选 · 展开查看成员</Text></Space>},
        {title:"初判与推荐理由",render:(_,group) => <Space direction="vertical" size={2}><Text strong>{assessmentLabels[group.representative.assessment] || group.priority_label}</Text><Text>{group.reasons.join(" ")}</Text>{group.representative.source_gaps?.length > 0 && <Text type="secondary">追查方向：<ChineseNarrative value={group.representative.source_gaps[0].description} /></Text>}<Text type="secondary">代表候选：{(representatives[group.group_id] || group.representative.candidate_id).slice(0,12)}；源码主张 {group.representative.source_claim_count}，未决源码核查 {group.representative.source_unresolved_count}</Text></Space>},
        {title:"依据",width:115,render:(_,group) => group.representative.operation_id && <Button size="small" onClick={() => go("/tasks/operations/" + group.representative.operation_id)}>查看初判</Button>},
      ]}/>
  </Space>;
}
