import React, { useMemo, useRef, useState } from "react";
import { Alert, Button, Card, Input, Select, Space, Table, Tag, Typography, message } from "antd";
import { api } from "../../api";
import { blindReviewOperationIds, blindReviewPairs } from "./blindReview.js";

const { Text } = Typography;

export default function AgentBlindReview({ operations }: { operations: any[] }) {
  const [experimentId, setExperimentId] = useState<string>();
  const [pairKeys, setPairKeys] = useState<string[]>([]);
  const [sessionId, setSessionId] = useState("");
  const [session, setSession] = useState<any>(null);
  const [agreementSessionIds, setAgreementSessionIds] = useState("");
  const [agreement, setAgreement] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const importInput = useRef<HTMLInputElement>(null);
  const sessionRequest = useRef(0);
  const agreementRequest = useRef(0);
  const eligible = useMemo(() => operations.filter((item) => item.kind === "agent_investigation"
    && ["completed", "completed_with_limitations"].includes(item.status)
    && item.result_sha256
    && item.spec?.experiment_id), [operations]);
  const experimentOptions = [...new Set(eligible.map((item) => item.spec.experiment_id))]
    .sort().map((value) => ({ value, label: value }));
  const pairing = useMemo(() => blindReviewPairs(operations, experimentId), [operations, experimentId]);
  const operationOptions = pairing.pairs.map((pair) => ({ value: pair.key, label: pair.label }));
  const operationIds = blindReviewOperationIds(pairKeys, pairing.pairs);
  const loadSession = async (id = sessionId) => {
    const targetId = id.trim();
    if (!targetId) return;
    const request = ++sessionRequest.current;
    setSession(null);
    setSessionId(targetId);
    const value = await api(`/agent/blind-sessions/${targetId}`);
    if (sessionRequest.current === request) setSession(value);
  };
  const createSession = async () => {
    setBusy(true);
    try {
      const created = await api("/agent/blind-sessions", { experiment_id: experimentId, operation_ids: operationIds });
      await loadSession(created.id);
      message.success("已创建匿名盲审会话；请导出文件并交给独立复核人");
    } catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const exportPacket = async () => {
    if (!session || session.id !== sessionId || session.state !== "open") return;
    const targetId = session.id;
    setBusy(true);
    try {
      const packet = await api(`/agent/blind-sessions/${targetId}/export`);
      const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a"); link.href = url;
      link.download = `ohscanner-blind-session-${sessionId}.json`; link.click();
      URL.revokeObjectURL(url);
    } catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const exportEvidenceBundle = async () => {
    if (!session || session.id !== sessionId || session.state !== "closed") return;
    setBusy(true);
    try {
      const bundle = await api(`/agent/blind-sessions/${session.id}/evidence-bundle`);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a"); link.href = url;
      link.download = `ohscanner-agent-evidence-${sessionId}.json`; link.click();
      URL.revokeObjectURL(url);
    } catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const importReviews = async (file?: File) => {
    if (!file || !session || session.id !== sessionId) return;
    const targetId = session.id;
    setBusy(true);
    try {
      const data = JSON.parse(await file.text());
      if (data.schema_version !== 1 || data.blind_session_id !== targetId || !Array.isArray(data.reviews)) {
        throw new Error("评价文件版本或会话编号不匹配");
      }
      const result = await api(`/agent/blind-sessions/${targetId}/import`, { reviews: data.reviews });
      await loadSession(targetId);
      message.success(`已导入 ${result.imported_count} 条评价，审计记录绑定对应结果哈希`);
    } catch (error) { message.error(String(error)); }
    finally {
      setBusy(false);
      if (importInput.current) importInput.current.value = "";
    }
  };
  const closeSession = async () => {
    if (!session || session.id !== sessionId) return;
    const targetId = session.id;
    const request = sessionRequest.current;
    setBusy(true);
    try {
      const value = await api(`/agent/blind-sessions/${targetId}/close`, {});
      if (sessionRequest.current === request) setSession(value);
      message.success("盲审完成，已揭示实验组别");
    }
    catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const downloadAgreement = () => {
    if (!agreement) return;
    const blob = new Blob([JSON.stringify(agreement, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a"); link.href = url;
    link.download = `ohscanner-blind-agreement-${agreement.experiment_id}.json`;
    link.click(); URL.revokeObjectURL(url);
  };
  const compareReviewers = async () => {
    const sessionIds = agreementSessionIds.split(/[\s,;，；]+/).filter(Boolean);
    const request = ++agreementRequest.current;
    setBusy(true);
    try {
      const value = await api("/agent/blind-review-agreement", { session_ids: sessionIds });
      if (agreementRequest.current === request) setAgreement(value);
      message.success("已按保存的结果哈希比较复核结果一致性");
    } catch (error) { message.error(String(error)); }
    finally { setBusy(false); }
  };
  const reviewed = session?.items?.filter((item: any) => item.reviewed).length || 0;
  return <Card className="section-gap" title="R1 / R2 离线匿名盲审">
    <Alert type="warning" showIcon message="离线复核，不把原操作详情交给复核人" description="导出的复核包不含模式、模型、仓库/提交/候选标识或原操作 ID。把 JSON 和离线表单交给独立复核人；复核期间不要共享主工作台访问权限。自然语言和证据数量仍可能泄露实验组别，因此保留复核人的猜测备注。" />
    <Space direction="vertical" className="section-gap" style={{ width: "100%" }}>
      <Space wrap>
        <Select style={{ minWidth: 220 }} placeholder="选择实验批次" value={experimentId} options={experimentOptions}
          disabled={busy} onChange={(value) => { setExperimentId(value); setPairKeys([]); }} />
        <Select mode="multiple" style={{ minWidth: 420 }} placeholder="选择完整的候选配对（R1 + R2）" value={pairKeys}
          options={operationOptions} disabled={!experimentId || busy} onChange={(values) => {
            if (values.length > 10) { message.warning("一次最多选择 10 组完整配对"); return; }
            setPairKeys(values);
          }} maxTagCount="responsive" />
        <Button type="primary" disabled={!experimentId || pairKeys.length < 1 || operationIds.length > 20 || busy} loading={busy} onClick={() => void createSession()}>
          开始匿名复核
        </Button>
      </Space>
      <Text type="secondary">选择一组就会同时加入 R1 和 R2 两条结果；最多选 10 组。创建时服务端还会核对源码绑定、实验配置和同源码 R0 静态基线。复核条目随机排序；在线会话状态接口不返回源码包或未揭盲的组别映射。</Text>
      {experimentOptions.length === 0 && <Alert type="info" showIcon
        message="当前没有已完成的实验批次可供盲审"
        description="先为本次扫描候选完成人工 R0 静态基线，再按同一源码和实验配置完成 R1/R2。此面板只读取已完成结果，不会启动扫描或模型调用。" />}
      {experimentId && pairing.eligibleOperationCount === 0 && <Alert type="info" showIcon
        message="这个实验批次还没有可用于盲审的已完成 R1/R2 结果"
        description="先完成同一条扫描候选的 R1 单轮和 R2 工具 Agent；当前页面不会自动启动模型任务。" />}
      {experimentId && pairing.eligibleOperationCount > 0 && pairing.pairs.length === 0 && <Alert type="warning" showIcon
        message="暂时没有完整且唯一的 R1/R2 配对"
        description={`已完成结果 ${pairing.eligibleOperationCount} 条；缺少一侧的配对 ${pairing.incompletePairCount} 组，重复或有歧义的配对 ${pairing.ambiguousPairCount} 组。请检查实验批次和候选绑定后刷新。`} />}
      <Space.Compact style={{ width: "100%" }}>
        <Input aria-label="盲审会话编号" value={sessionId} onChange={(event) => {
          sessionRequest.current++;
          setSession(null);
          setSessionId(event.target.value);
        }} placeholder="输入已创建的盲审会话编号" />
        <Button loading={busy} disabled={!sessionId} onClick={() => void loadSession().catch((error) => message.error(String(error)))}>查看复核进度</Button>
      </Space.Compact>
      <Space.Compact style={{ width: "100%" }}>
        <Input aria-label="独立复核会话编号" value={agreementSessionIds} onChange={(event) => {
          agreementRequest.current++;
          setAgreement(null);
          setAgreementSessionIds(event.target.value);
        }} placeholder="输入同一批结果的 2-10 个已关闭盲审会话编号，以逗号或空格分隔" />
        <Button loading={busy} disabled={agreementSessionIds.split(/[\s,;，；]+/).filter(Boolean).length < 2} onClick={() => void compareReviewers()}>比较复核结果一致性</Button>
      </Space.Compact>
      <Text type="secondary">一致性只统计同一结果哈希上各复核人标签的两两相同率，不校正偶然一致，也不能证明复核人身份独立或结论正确。</Text>
      {agreement && <>
        <Alert className="section-gap" type="info" showIcon message={`一致性报告：${agreement.matched_operation_count} 个相同结果，${agreement.blind_session_count} 个盲审会话`} description={`${agreement.interpretation} 报告 SHA-256：${agreement.report_sha256}`} />
        <Button onClick={downloadAgreement}>下载一致性报告</Button>
        {(["single_shot", "tool_agent"] as const).map((mode) => {
          const row = agreement.per_arm[mode];
          const percent = (value: number | null) => value === null ? "unknown" : `${(value * 100).toFixed(1)}%`;
          const obligationRows = Object.values<any>(row.evidence_obligation_agreement)
            .reduce((sum, value) => sum + value.comparable_items, 0);
          const claimRows = Object.values<any>(row.claim_evidence_support_agreement)
            .reduce((sum, value) => sum + value.comparable_items, 0);
          return <Alert key={mode} className="section-gap" type="info" showIcon
            message={`${mode === "single_shot" ? "R1 单轮" : "R2 工具 Agent"}：${row.reviewed_operations} 个结果；独立复核人标签数 ${row.unique_reviewer_labels_min}-${row.unique_reviewer_labels_max}`}
            description={`引文准确性两两一致 ${percent(row.agreement.citation_accuracy.pairwise_agreement)}；人工分诊两两一致 ${percent(row.agreement.post_review_disposition.pairwise_agreement)}；义务判定 ${obligationRows} 项，支持性主张 ${claimRows} 项。`} />;
        })}
      </>}
      {session && session.id === sessionId && <>
        <Alert type={session.state === "closed" ? "warning" : "info"} showIcon
          message={`会话 ${session.id} · ${session.state === "closed" ? "已揭盲" : "盲审中"} · ${session.items.length} 条 · ${reviewed} 条已复核`} />
        {session.state === "open" && <Space wrap>
          <Button type="primary" loading={busy} onClick={() => void exportPacket()}>下载匿名复核材料</Button>
          <Button href="/api/v1/agent/blind-reviewer.html" target="_blank">打开复核表单</Button>
          <input ref={importInput} type="file" accept="application/json,.json" style={{ display: "none" }}
            onChange={(event) => void importReviews(event.target.files?.[0])} />
          <Button loading={busy} onClick={() => importInput.current?.click()}>导入复核结果</Button>
          <Button danger loading={busy} disabled={!session.items.length || session.items.some((item: any) => !item.reviewed)} onClick={() => void closeSession()}>
            全部评价后揭盲
          </Button>
        </Space>}
        {session.state === "closed" && <>
          <Alert type="warning" showIcon message="揭盲证据包包含源码上下文和完整 Agent 结果"
            description="仅在受控审查目录保存或分享。包内含 R0 记录、盲审评分、已保存的作业配置、结果哈希及总包哈希。" />
          <Button className="section-gap" loading={busy} onClick={() => void exportEvidenceBundle()}>
            下载复核记录包
          </Button>
        </>}
        {session.state === "closed" && session.blind_guess_summary && <Alert className="section-gap" type="info" showIcon
          message={"盲审泄漏检查：" + session.blind_guess_summary.correct_guesses + " / " + session.blind_guess_summary.guessed_items + " 次组别猜测正确；覆盖 " + session.blind_guess_summary.guessed_items + " / " + session.blind_guess_summary.reviewed_items + "；准确率 " + (session.blind_guess_summary.accuracy_when_guessed === null ? "unknown" : Math.round(session.blind_guess_summary.accuracy_when_guessed * 100) + "%") + "；平均置信度 " + (session.blind_guess_summary.mean_confidence_when_guessed ?? "unknown") + "%"}
          description="该指标只描述复核人对实验组别的猜测，不是漏洞准确率，也不代表模型有效性。猜测正确率高可能说明盲审包泄露了组别线索。" />}
        <Table<any> className="section-gap" size="small" rowKey="blind_item_id" dataSource={session.items}
          pagination={false} columns={[
            { title: "盲审条目", dataIndex: "blind_item_id", render: (value) => <Text code>{value}</Text> },
            { title: "随机顺序", dataIndex: "order", render: (value) => value + 1 },
            { title: "状态", dataIndex: "reviewed", render: (value) => value ? <Tag color="green">已复核</Tag> : <Tag>待复核</Tag> },
            ...(session.state === "closed" ? [
              { title: "揭盲模式", dataIndex: ["unblinded", "mode"] },
              { title: "结果 SHA-256", dataIndex: ["unblinded", "result_sha256"], render: (value: string) => <Text code>{value}</Text> },
            ] : []),
          ]} />
        {session.state === "closed" && session.operator_review_by_arm && <div className="section-gap">
          <Text type="secondary">揭盲后的人工反馈，仅描述分诊和证据体验；不是漏洞真值、Precision 或 Recall。</Text>
          {(["single_shot", "tool_agent"] as const).map((mode) => {
            const stats = session.operator_review_by_arm[mode];
            const disposition = stats.post_review_disposition;
            const useful = stats.usefulness;
            const citations = stats.citation_accuracy;
            const obligationAgreement = stats.obligation_disposition_concordance;
            const claimSupport = stats.claim_evidence_support;
            return <Alert key={mode} className="section-gap" type="info" showIcon
              message={`${mode === "single_shot" ? "R1 单轮" : "R2 工具 Agent"}：${stats.review_count} 条复核；看后建议 investigate ${disposition.investigate} / likely_noise ${disposition.likely_noise} / unknown ${disposition.unknown}`}
              description={`有用/部分/无用/不安全：${useful.useful}/${useful.partially_useful}/${useful.not_useful}/${useful.unsafe}；引文全对/部分错/多数错/未检查：${citations.all_accurate}/${citations.some_incorrect}/${citations.mostly_incorrect}/${citations.not_checked}；证据义务与模型判定一致 ${obligationAgreement.exact_matches}/${obligationAgreement.reviewed_obligations}、分歧 ${obligationAgreement.differences}、未评 ${obligationAgreement.not_reviewed}（不代表漏洞真值）；逐条主张证据支持（支持/部分/不支持/未知）：${claimSupport.supported}/${claimSupport.partially_supported}/${claimSupport.unsupported}/${claimSupport.unverifiable}，未评 ${claimSupport.not_reviewed}（证据语义复核，不是漏洞真值、Precision 或 Recall）；复核中位用时：${stats.median_elapsed_seconds ?? "unknown"} 秒`} />;
          })}
        </div>}
        {session.state === "closed" && session.items.map((item: any) => {
          if (!item.review) return null;
          const actual = item.unblinded?.mode;
          const guessed = item.review.guessed_arm || "unknown";
          const guessResult = guessed === "unknown" ? "未猜出" : guessed === actual ? "猜测正确" : "猜测错误";
          return <Alert key={item.blind_item_id} className="section-gap" type="success" showIcon
            message={`${actual} · ${item.review.reviewer} · ${item.review.usefulness} · 引文 ${item.review.citation_accuracy}`}
            description={`组别猜测：${guessed}（置信度 ${item.review.guess_confidence ?? "未填"}%，${guessResult}）；review SHA-256 ${item.review_sha256}；result SHA-256 ${item.unblinded?.result_sha256}`} />;
        })}
      </>}
    </Space>
  </Card>;
}
