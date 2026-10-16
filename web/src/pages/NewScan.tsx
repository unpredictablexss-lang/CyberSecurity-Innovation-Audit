import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  ConfigProvider,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  AppstoreOutlined,
  BranchesOutlined,
  CodeOutlined,
  FileSearchOutlined,
  FolderOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ExperimentOutlined,
} from "@ant-design/icons";
import "antd/dist/reset.css";
import { api, artifact, terminal } from "../api";
import { State, Hash, go, CodeView, Header, labels } from "../components";
const { Text, Title, Paragraph } = Typography;
export default function NewScan({
  repos,
  detectors,
  refresh,
}: {
  repos: any[];
  detectors: any[];
  refresh: () => Promise<void>;
}) {
  const [form] = Form.useForm();
  const [refs, setRefs] = useState<any[]>([]);
  const [selectedRef, setSelectedRef] = useState("");
  const [selectedRepository, setSelectedRepository] = useState("");
  const [refsByRepository, setRefsByRepository] = useState<Record<string, any[]>>({});
  const refsRequest = useRef(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <>
      <Header
        title="新建源码审计"
        description="先冻结版本，再开始扫描。每个任务保留算法版本、纳入范围与执行预算。"
      />
      <Row gutter={22}>
        <Col span={16}>
          <Card>
            {error && <Alert type="error" message={error} />}
            <Form
              form={form}
              layout="vertical"
              initialValues={{
                revision: "HEAD",
                include_text: ".",
                timeout_seconds: 300,
                memory_mb: 2048,
              }}
              onFinish={async (values) => {
                setBusy(true);
                try {
                  const { include_text, ...rest } = values;
                  const job = await api("/scans", {
                    ...rest,
                    include_paths: String(include_text)
                      .split("\n")
                      .map((x) => x.trim())
                      .filter(Boolean),
                  });
                  await refresh();
                  go("/tasks/" + job.id);
                } catch (e) {
                  setError(String(e));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Form.Item
                name="repository_id"
                label="本地仓库"
                rules={[{ required: true }]}
              >
                <Select
                  placeholder="选择已登记仓库"
                  showSearch
                  optionFilterProp="label"
                  options={repos.map((r) => ({ value: r.id, label: r.name + " · " + r.path }))}
                  onOpenChange={(open) => { if (open) void refresh().catch((e) => setError(String(e))); }}
                  onChange={(id) => {
                    setSelectedRepository(id);
                    setSelectedRef("");
                    setRefs([]);
                    form.setFieldValue("revision", undefined);
                    const request = ++refsRequest.current;
                    void api("/repositories/" + id + "/revisions")
                      .then((items) => {
                        setRefsByRepository((previous) => ({ ...previous, [id]: items }));
                        if (refsRequest.current === request) setRefs(items);
                      })
                      .catch((e) => { if (refsRequest.current === request) setError(String(e)); });
                  }}
                />
              </Form.Item>
              <Form.Item label="从当前仓库 Ref 选择（可选）">
                <Select
                  showSearch
                  allowClear
                  value={selectedRef || undefined}
                  optionFilterProp="label"
                  options={(refsByRepository[selectedRepository] || refs).map((r) => ({ value: r.ref, label: r.ref }))}
                  onChange={(r) => { setSelectedRef(r || ""); form.setFieldValue("revision", r || undefined); }}
                />
              </Form.Item>
              <Form.Item
                name="revision"
                label="分支、Tag 或完整 Commit"
                rules={[{ required: true }]}
              >
                <Input />
              </Form.Item>
              <Form.Item
                name="include_text"
                label="纳入路径（每行一个；. 表示全仓源码）"
                rules={[{ required: true }]}
              >
                <Input.TextArea rows={3} />
              </Form.Item>
              <Form.Item
                name="detector_ids"
                label="自研检测器"
                rules={[{ required: true, message: "至少选择一个检测器" }]}
              >
                <Checkbox.Group className="detector-options">
                  {detectors.map((d) => (
                    <Checkbox key={d.id} value={d.id}>
                      <strong>{d.id}</strong>
                      <span>
                        {d.summary} · {d.version}
                      </span>
                    </Checkbox>
                  ))}
                </Checkbox.Group>
              </Form.Item>
              <Row gutter={20}>
                <Col span={12}>
                  <Form.Item name="timeout_seconds" label="任务硬超时（秒）">
                    <InputNumber min={1} max={3600} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="memory_mb" label="地址空间上限（MiB）">
                    <InputNumber min={256} max={8192} />
                  </Form.Item>
                </Col>
              </Row>
              <Button
                type="primary"
                htmlType="submit"
                loading={busy}
                size="large"
              >
                冻结版本并创建任务
              </Button>
            </Form>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="执行过程">
            <Timeline
              items={[
                "解析 Ref 并固定 Commit / Tree",
                "独立进程读取、解析和执行检测器",
                "记录覆盖、候选与证据义务",
                "校验来源并发布报告",
              ].map((children) => ({ children }))}
            />
            <Alert
              showIcon
              type="warning"
              message="组件级审计"
              description="最多 2,000 个源码文件、总源码 32 MiB。超限明确失败，不自动进行未验证的分片。"
            />
          </Card>
        </Col>
      </Row>
    </>
  );
}
